# Infrastructure Vulnerability Assessment & SLA Tracking Simulation

## 1. Tujuan
Simulasi mandiri proses Vulnerability Management: pemindaian aset, inventarisasi celah (CVE), klasifikasi severity berbasis CVSS, pemantauan SLA remediasi, serta analisis false positive dan verifikasi komponen.

## 2. Topologi Lab
- Scanner dan target: Ubuntu Linux, localhost (127.0.0.1)
- Layanan yang dianalisis: CUPS (cupsd) dan cups-browsed
- Tools: Nmap (NSE script vulners), Python 3 (vuln_tracker.py)

## 3. Langkah Menjalankan
1. Pindai localhost, simpan format teks dan XML:
   ```bash
   sudo nmap -sV --script vulners -T4 -oN sample_output/hasil.txt -oX sample_output/hasil.xml localhost
   ```
2. Hasilkan tracker CSV:
   ```bash
   python3 vuln_tracker.py sample_output/hasil.txt -o sample_output/tracker.csv
   ```
3. Simulasi tanggal untuk menguji perhitungan SLA dan breach:
   ```bash
   python3 vuln_tracker.py sample_output/hasil.txt -o sample_output/tracker.csv --as-of 2026-12-15
   ```
4. Perbarui kolom `status` dan `notes` di tracker.csv setelah verifikasi manual. Nilainya dipertahankan saat script dijalankan ulang.

SLA simulasi: Critical 7 hari, High 30, Medium 90, Low 180, dihitung dari tanggal pertama temuan terlihat (first_seen).

## 4. Hasil
Pemindaian localhost menemukan 1 port terbuka (631/tcp, CUPS 2.4) dan 2 temuan CVE, keduanya High menurut skor vulners.

![Hasil tracker](screenshots/tracker_result.png)

## 5. Analisis Verifikasi

| CVE | Skor | Status | Analisis | Bukti |
|---|---|---|---|---|
| CVE-2022-26691 | 7.2 | False Positive | Banner Nmap hanya menampilkan "CUPS 2.4" tanpa nomor patch, sehingga vulners mencocokkan CVE untuk seluruh seri 2.4. Versi terpasang 2.4.16, lebih baru dari versi perbaikan 2.4.2 (changelog CUPS). | evidence/apt_policy_cups.txt |
| CVE-2024-47850 | 7.5 | Not Exploitable | CVE menyangkut komponen cups-browsed (terpasang 2.1.1-0ubuntu3, layanan aktif), bukan cupsd yang dideteksi Nmap di TCP 631. Vektor serangannya adalah paket IPP via UDP 631, namun tidak ada socket UDP di port 631 dan cups-browsed tidak memiliki socket UDP; TCP 631 dimiliki cupsd hanya di loopback. | evidence/apt_policy_cups-browsed.txt, evidence/cups-browsed_status.txt, evidence/cups-browsed_enabled.txt, evidence/udp_listeners.txt, evidence/tcp631_owner.txt |

Catatan: alamat IP LAN dan IPv6 link-local di evidence/udp_listeners.txt disensor; baris lainnya tidak diubah dari output asli.

Rekomendasi remediasi (tidak dijalankan di lab ini): jika cups-browsed tidak dibutuhkan, nonaktifkan dengan `sudo systemctl disable --now cups-browsed` dan pindai ulang untuk memastikan statusnya.

## 6. Keterbatasan
- Skala kecil: 1 host dan 1 port terbuka.
- Pencocokan CVE berbasis versi banner, rawan false positive.
- Skor CVSS dari vulners dapat berbeda dari sumber lain (contoh: CVE-2022-26691 tercatat 6.7 di OSV).
- Status Not Exploitable berlaku pada konfigurasi saat ini; komponen rentan tetap terpasang dan aktif, sehingga perlu ditinjau ulang jika konfigurasi berubah.
- SLA bersifat simulasi dan tidak memakai scanner komersial (Nessus, Qualys).
- Fitur SLA breach belum terdemonstrasi karena tidak ada temuan berstatus Open.
