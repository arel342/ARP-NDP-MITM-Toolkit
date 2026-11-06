# ARP-NDP-MITM-Toolkit
# ARP + NDP MITM Toolkit — Worm Shadow Edition (v10)

Interactive network testing toolkit untuk ARP/NDP spoofing, MITM monitoring, dan router DoS testing **pada jaringan milik sendiri**.

> ⚠️ **Hanya untuk jaringan yang kamu miliki atau punya izin eksplisit untuk diuji.** Menjalankan tool ini di jaringan publik, kantor, kafe, atau jaringan orang lain tanpa izin adalah tindakan ilegal dan bisa dikenai sanksi pidana.

---

## 📋 Daftar Isi

1. [Fitur](#fitur)
2. [Prasyarat](#prasyarat)
3. [Instalasi dari Nol](#instalasi-dari-nol)
4. [Cara Mengetahui Interface & Gateway](#cara-mengetahui-interface--gateway)
5. [Cara Menjalankan](#cara-menjalankan)
6. [Penjelasan Menu](#penjelasan-menu)
7. [Contoh Skenario Penggunaan](#contoh-skenario-penggunaan)
8. [Peringatan Penting](#peringatan-penting)
9. [Troubleshooting](#troubleshooting)
10. [Cleanup Manual (Jika Script Crash)](#cleanup-manual-jika-script-crash)

---

## ✨ Fitur

| Fitur | Deskripsi |
|---|---|
| **Scan Subnet** | ARP scan + ping sweep + mDNS hostname resolve |
| **Block ALL** | Putus internet semua device (IPv4 + IPv6) |
| **Block 1 Host** | Putus internet satu device saja |
| **MITM Monitor** | Forward traffic + log DNS/SNI live (target tetap online) |
| **Aggressive Kill** | Block + matikan internet PC sendiri |
| **Passive Monitor** | Sniff traffic tanpa poison |
| **Airwave Jammer** | Broadcast flood + TCP RST + ARP poison → 100% packet loss |
| **Multi-Interface** | Bisa jalan di Wi-Fi + Ethernet sekaligus |
| **Auto Restore** | ARP/NDP/firewall di-restore otomatis saat stop |

---

## 🔧 Prasyarat

- **Python 3.9+**
- **Administrator / root privileges**
- **Windows:** Npcap (wajib)
- **Linux:** `libpcap-dev`

---

## 🚀 Instalasi dari Nol

### 🪟 Windows

#### 1. Install Python

1. Buka https://www.python.org/downloads/
2. Download **Python 3.11** atau lebih baru
3. **PENTING:** Saat installer jalan, **centang** `Add python.exe to PATH`
4. Klik **Install Now**
5. Verifikasi di PowerShell/CMD:
   ```powershell
   python --version
