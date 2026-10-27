# Infrastructure Vulnerability Assessment & SLA Tracking Simulation

## 1. Tujuan
Membangun simulasi lab *Vulnerability Management* mandiri untuk mempelajari proses pemindaian aset, inventarisasi celah keamanan (CVE), klasifikasi severity berbasis CVSS, serta pemantauan SLA remediasi dan analisis *False Positive*.

## 2. Topologi Lab
- **Scanner / OS:** Ubuntu Linux (x86_64)
- **Target Scan:** Localhost (127.0.0.1) / Layanan aktif (CUPS, dll.)
- **Tools Utama:** Nmap (Nmap Scripting Engine / vulners), Python 3 (Custom Vulnerability & SLA Tracker)

## 3. Langkah Menjalankan
1. Jalankan pemindaian kerentanan Nmap:
   ```bash
   sudo nmap -sV --script vulners -T4 -oN sample_output/hasil.txt localhost

## 4. Screenshot Hasil Simulasi
![Bukti Tracker Vulnerability](screenshots/tracker_result.png)

## 5. Analisis False Positive

Pemindaian `nmap -sV --script vulners` terhadap localhost menghasilkan 2 temuan CVE pada layanan CUPS (port 631). Keduanya diverifikasi secara manual:

| CVE | Skor CVSS | Status | Alasan / Analisis |
|---|---|---|---|
| CVE-2022-26691 | 7.2 | False Positive | Banner Nmap hanya menampilkan "CUPS 2.4" tanpa nomor patch, sehingga vulners mencocokkan semua CVE untuk seri 2.4. Versi terpasang 2.4.16 lebih baru dari versi perbaikan 2.4.2. |
| CVE-2024-47850 | 7.5 | False Positive | CVE ini terkait komponen `cups-browsed` (versi terpasang 2.1.1-0ubuntu3), bukan `cupsd` di port TCP 631. |

Bukti verifikasi diperoleh melalui pemeriksaan versi paket (`dpkg`, `apt policy`) serta analisis cakupan konfigurasi rentan di NVD.

## 6. Keterbatasan
- Pemindaian hanya mencakup 1 host (localhost) dan port lokal sebagai skala pembelajaran awal.
- Pencocokan CVE berbasis versi banner, yang terbukti rentan menghasilkan *False Positive*.
- SLA bersifat simulasi (Critical 7 hari, High 30, Medium 90, Low 180). Tidak menggunakan scanner komersial seperti Nessus atau Qualys.
- Fitur SLA breach tidak didemokan dengan data palsu; seluruh temuan di localhost terbukti False Positive.

