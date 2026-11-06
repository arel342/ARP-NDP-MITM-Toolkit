# ARP + NDP MITM Toolkit — Worm Shadow Edition (v10)

Dokumentasi **peringatan, prasyarat, dan langkah instalasi** untuk toolkit pengujian jaringan.

> ⚠️ **PERINGATAN PENGGUNAAN**
>
> Gunakan perangkat lunak ini hanya pada jaringan yang Anda miliki atau yang secara eksplisit telah memberi izin tertulis untuk diuji. Penggunaan pada jaringan publik, kantor, kafe, ISP, atau jaringan milik orang lain tanpa izin dapat mengganggu layanan dan berpotensi melanggar hukum.
>
> Toolkit yang melibatkan ARP/NDP spoofing, MITM, packet injection, atau pengujian DoS dapat menyebabkan perangkat kehilangan koneksi, router tidak stabil, dan gangguan pada seluruh jaringan. Dokumentasi ini hanya menjelaskan persiapan dan instalasi; bukan panduan menjalankan serangan atau mengganggu koneksi perangkat.

---

## Daftar Isi

1. [Peringatan Penting](#peringatan-penting)
2. [Prasyarat](#prasyarat)
3. [Instalasi di Windows](#instalasi-di-windows)
4. [Instalasi di Linux](#instalasi-di-linux)
5. [Memeriksa Interface dan Gateway](#memeriksa-interface-dan-gateway)
6. [Menyiapkan Folder Proyek](#menyiapkan-folder-proyek)
7. [Pemeriksaan Setelah Instalasi](#pemeriksaan-setelah-instalasi)
8. [Troubleshooting Instalasi](#troubleshooting-instalasi)
9. [Referensi](#referensi)

---

## Peringatan Penting

- Jalankan pengujian hanya pada jaringan milik sendiri atau jaringan yang telah memberikan izin eksplisit.
- Jangan menjalankan pengujian disruptif pada jaringan produksi, kantor, sekolah, fasilitas umum, atau jaringan ISP.
- ARP/NDP spoofing dan MITM dapat mengganggu komunikasi perangkat lain serta mengekspos metadata lalu lintas.
- Pengujian DoS atau flooding dapat membuat router/perangkat jaringan tidak responsif dan memutus koneksi pengguna lain.
- Jangan melakukan pengujian dari sesi SSH, RDP, atau koneksi jarak jauh yang bergantung pada jaringan yang sedang diuji.
- Pastikan tersedia akses administratif langsung ke router dan cara pemulihan koneksi sebelum melakukan pengujian yang telah diotorisasi.
- Tutup aplikasi pengujian setelah selesai dan pulihkan konfigurasi jaringan yang diubah.
- Patuhi kebijakan organisasi, ketentuan penyedia layanan, dan hukum yang berlaku.

## Prasyarat

| Komponen | Kebutuhan |
|---|---|
| Python | Python 3.9 atau lebih baru; disarankan Python 3.11+ |
| Hak akses | Administrator pada Windows atau root/sudo pada Linux untuk fungsi jaringan yang memerlukannya |
| Windows | Npcap |
| Linux | `libpcap-dev` |
| Dependensi Python | Scapy atau paket yang tercantum di `requirements.txt` |
| Berkas proyek | `arp_menu.py` dan `requirements.txt` |

Pastikan berkas `arp_menu.py` dan `requirements.txt` benar-benar tersedia sebelum melanjutkan.

---

## Instalasi di Windows

### 1. Instal Python

1. Buka [https://www.python.org/downloads/](https://www.python.org/downloads/).
2. Unduh Python 3.11 atau versi lebih baru.
3. Jalankan installer.
4. Centang **Add python.exe to PATH**.
5. Pilih **Install Now**.
6. Buka PowerShell dan verifikasi:

```powershell
python --version
```

Pastikan versi Python yang tampil adalah 3.9 atau lebih baru.

### 2. Instal Npcap

1. Buka [https://npcap.com/#download](https://npcap.com/#download).
2. Unduh installer Npcap dari situs resminya.
3. Jalankan installer dan ikuti petunjuknya.
4. Jika kompatibilitas aplikasi memerlukannya, aktifkan opsi **WinPcap API-compatible Mode**.
5. Selesaikan instalasi. Restart Windows jika diminta.
6. Periksa status layanan dari PowerShell:

```powershell
sc.exe query npcap
```

Jika layanan tersedia, periksa apakah statusnya berjalan. Nama layanan atau status dapat berbeda menurut versi dan konfigurasi instalasi.

### 3. Siapkan folder proyek

Contoh lokasi folder:

```text
C:\Users\<nama>\Downloads\arp
```

Letakkan berkas proyek berikut di folder yang sama:

```text
arp/
├── arp_menu.py
├── requirements.txt
└── README.md
```

Buka PowerShell dan pindah ke folder proyek:

```powershell
cd "$HOME\Downloads\arp"
```

### 4. Instal dependensi Python

Jika proyek menyediakan `requirements.txt`, jalankan:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Jika `requirements.txt` tidak tersedia atau tidak mencantumkan Scapy, periksa dokumentasi proyek sebelum memasang dependensi secara manual. Paket Scapy dapat dipasang dengan:

```powershell
python -m pip install scapy
```

---

## Instalasi di Linux

Langkah berikut ditujukan untuk distribusi berbasis Debian/Ubuntu, termasuk Kali Linux.

### 1. Perbarui daftar paket

```bash
sudo apt update
```

### 2. Instal Python, pip, dan libpcap

```bash
sudo apt install -y python3 python3-pip python3-venv libpcap-dev
```

### 3. Siapkan folder proyek

Masuk ke folder yang berisi berkas proyek:

```bash
cd /path/ke/folder/arp
```

Pastikan berkas berikut tersedia:

```text
arp_menu.py
requirements.txt
README.md
```

### 4. Buat virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 5. Instal dependensi

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Jika dependensi Scapy tidak tercantum di `requirements.txt`, periksa kebutuhan proyek terlebih dahulu. Instalasi manual Scapy:

```bash
python -m pip install scapy
```

---

## Memeriksa Interface dan Gateway

Pemeriksaan ini hanya untuk mengidentifikasi konfigurasi jaringan lokal.

### Windows

Daftar adapter jaringan:

```powershell
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, MacAddress
```

Informasi alamat IP dan gateway:

```powershell
ipconfig
```

Rute default IPv4:

```powershell
Get-NetRoute -DestinationPrefix 0.0.0.0/0 |
    Select-Object NextHop, ifIndex
```

Gunakan nama pada kolom `Name` untuk mengenali adapter, misalnya `Ethernet` atau `Wi-Fi`.

### Linux

Daftar interface dan alamat IP:

```bash
ip addr
```

Rute default:

```bash
ip route
```

Catat nama interface dan gateway yang sesuai dengan koneksi yang memang Anda kelola.

---

## Menyiapkan Folder Proyek

Struktur minimal yang diharapkan:

```text
arp/
├── arp_menu.py
├── requirements.txt
└── README.md
```

Pastikan:

- Nama berkas sama persis dengan yang digunakan proyek.
- `requirements.txt` berisi dependensi yang diperlukan.
- Instalasi dilakukan dari folder proyek yang benar.
- Tidak ada berkas proyek yang diunduh dari sumber yang tidak tepercaya.

## Pemeriksaan Setelah Instalasi

Lakukan pemeriksaan dasar berikut sebelum penggunaan lebih lanjut.

### Windows

```powershell
python --version
python -m pip --version
python -m pip show scapy
Get-NetAdapter
```

### Linux

```bash
python3 --version
python3 -m pip --version
python3 -m pip show scapy
ip link
```

Perintah di atas memeriksa versi Python, instalasi paket, dan ketersediaan interface jaringan. Pemeriksaan ini tidak membuktikan bahwa seluruh fitur proyek kompatibel dengan perangkat atau sistem Anda.

---

## Troubleshooting Instalasi

### `python is not recognized` pada Windows

- Pastikan Python sudah terinstal.
- Pastikan opsi **Add python.exe to PATH** dipilih.
- Tutup dan buka kembali PowerShell.
- Coba perintah `py --version`.

### `pip` tidak ditemukan

Gunakan pemanggilan pip melalui Python:

```powershell
python -m pip --version
```

Pada Linux:

```bash
python3 -m pip --version
```

### Instalasi paket gagal

- Pastikan koneksi internet tersedia.
- Perbarui pip.
- Periksa apakah versi Python kompatibel dengan dependensi.
- Baca pesan error lengkap sebelum mengulang instalasi.

### Npcap tidak terdeteksi pada Windows

- Pastikan Npcap diunduh dari situs resminya.
- Periksa instalasi melalui **Apps & features**.
- Jalankan `sc.exe query npcap`.
- Ikuti petunjuk pemulihan atau instalasi ulang dari dokumentasi Npcap.

### Interface tidak terlihat

- Pastikan adapter aktif.
- Periksa nama adapter melalui `Get-NetAdapter` pada Windows atau `ip link` pada Linux.
- Pastikan driver perangkat jaringan terpasang dengan benar.

---

## Referensi

- [Python Downloads](https://www.python.org/downloads/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Npcap](https://npcap.com/)
- [RFC 826 — Address Resolution Protocol (ARP)](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 4861 — Neighbor Discovery for IP version 6 (IPv6)](https://www.rfc-editor.org/rfc/rfc4861)
- [RFC 4862 — IPv6 Stateless Address Autoconfiguration](https://www.rfc-editor.org/rfc/rfc4862)

---



cek gadeway
Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
Select-Object NextHop, InterfaceAlias

contoh 
NextHop     InterfaceAlias
-------     --------------
192.168.1.1 Wi-Fi
192.168.1.1 Ethernet



jalankan py
 python arp_menu.py --iface "Wi-Fi" --gateway YOU-GADEWAY --pcap capture.pcap


## Lisensi dan Disclaimer

Dokumentasi ini disediakan untuk edukasi dan persiapan pengujian keamanan jaringan yang sah. Pastikan Anda memiliki otorisasi sebelum melakukan pengujian. Pengguna bertanggung jawab untuk mematuhi hukum, kebijakan jaringan, dan ketentuan layanan yang berlaku.
