# Cinder — Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Scanner kerentanan web otomatis untuk reconnaissance, pengujian deep scan, triage, dan pelaporan.**

**by lifyDev**

```text
 ██████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║     ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║     ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╗██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

Cinder v0.5 adalah web vulnerability scanner berbasis Python untuk membantu pengujian keamanan yang sah dengan crawling, deteksi kerentanan, bukti request/response, serta laporan terminal, JSON, dan HTML.

## Fitur

### Reconnaissance

- Crawling situs dengan batas kedalaman, jumlah halaman, dan host yang sama.
- Pemeliharaan `robots.txt` dan jeda antar-request yang dapat dikonfigurasi.
- Fingerprinting teknologi dan rekonstruksi parameter serta endpoint dari halaman yang ditemukan.
- Rekognisi endpoint API, skema OpenAPI, aset JavaScript, dan tanda rahasia.
- Deteksi DOM XSS dan jalur browser-based scanning bila Playwright tersedia.

### Injection

- **SQL Injection:** error-based, boolean-based, time-based, dan union-based.
- **Cross-Site Scripting:** payload XSS sadar konteks untuk parameter HTML, atribut, dan JavaScript.
- **Command Injection:** pengujian payload command melalui parameter yang dapat dieksploitasi.
- **Server-Side Template Injection:** deteksi ekspresi dan perilaku khusus template engine.
- **Insecure Deserialization:** pemeriksaan pola deserialisasi berbahaya pada input yang ditemukan.

### Auth & Session

- **JWT:** deteksi algoritma `none`, serangan RS→HS, dan weak secret.
- **IDOR:** pemeriksaan referensi objek serta endpoint milik pengguna lain.
- **Auth logic:** pemeriksaan alur otentikasi, kontrol akun, dan endpoint sensitif.
- **Upload bypass:** pengujian validasi tipe, ekstensi, dan nama berkas upload.
- Dukungan Bearer token, cookie sesi, dan header HTTP kustom.

### Access Control & Request Security

- **SSRF:** deteksi interaksi atau indikasi akses ke layanan internal dan URL eksternal.
- **Path traversal:** pengujian traversal terhadap parameter berkas dan jalur.
- **Open redirect:** pengujian parameter tujuan dan redirect eksternal.
- **CORS:** deteksi origin yang tidak aman dan kebijakan CORS terlalu permisif.
- **CSRF:** pemeriksaan token, cookie, dan kontrol metode pada aksi sensitif.

### Logic & Race

- Deteksi kelemahan alur bisnis dan kontrol logika aplikasi.
- Pengujian race condition melalui permintaan bersamaan pada endpoint yang relevan.
- Sinkronisasi serta korelasi temuan untuk mengurangi noise hasil scanning.

### Protocol Security

- **HTTP request smuggling:** deteksi pola CL/TE dan indikator inkonsistensi framing.
- **Web cache poisoning:** pengujian header dan perilaku cache yang berpotensi berbahaya.
- **GraphQL:** pemeriksaan introspection, endpoint, query, dan kelemahan konfigurasi.

### Tambahan

- Pemeriksaan security headers yang hilang atau salah konfigurasi.
- Analisis cookie keamanan, atribut, dan pengaturan sesi.
- Pencarian sensitive files seperti berkas lingkungan, konfigurasi, backup, dan metadata.
- Deteksi WAF serta karakteristik respons dari lapisan perlindungan.
- Pemindaian DOM-based XSS pada halaman dan artefak JavaScript.
- Fuzzer parameter untuk menemukan pola respons dan perilaku yang tidak biasa.
- Korelasi exploit chain dari temuan yang saling berkaitan.
- Triage temuan untuk menggabungkan, memfilter, dan mengutamakan hasil.

### Evidence & Report

- Bukti lengkap berupa request dan response yang relevan.
- Ringkasan terminal dengan tabel temuan dan fingerprint target.
- Laporan JSON untuk integrasi pipeline/CI dan laporan HTML yang mandiri.
- 5 bucket severity: `critical`, `high`, `medium`, `low`, dan `info`.
- Exit code `1` bila ditemukan temuan berseverity `high` atau `critical`.

## Instalasi

Cinder membutuhkan Python 3.10 atau lebih baru.

```bash
git clone https://github.com/pikrong/Cinder.git
cd Cinder

python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Opsional untuk HTTP/2 dan pemindaian DOM berbasis browser:

```bash
pip install "httpx[http2]"
pip install playwright
python -m playwright install chromium
```

## Penggunaan

Pemindaian dasar:

```bash
python cinder.py -u https://target.example.com
```

Pemindaian mendalam:

```bash
python cinder.py -u https://target.example.com --deep --verbose
```

Ekspor JSON dan HTML:

```bash
python cinder.py -u https://target.example.com --json -o scan.json
python cinder.py -u https://target.example.com --html -o report.html
```

Sesi terautentikasi:

```bash
python cinder.py -u https://target.example.com \
  --auth-token "eyJ..." \
  --cookie "session=abc123" \
  --header "X-Tenant-ID: demo"
```

Fuzzing dan eksploit chain:

```bash
python cinder.py -u https://target.example.com --fuzz --chain --deep
```

Tanpa banner:

```bash
python cinder.py -u https://target.example.com --no-banner
```

## Tabel Opsi CLI

| Opsi | Deskripsi |
|---|---|
| `-u`, `--url` | URL target yang akan dipindai (wajib). |
| `-o`, `--output` | Jalur berkas untuk menyimpan laporan. |
| `--json` | Output atau ekspor laporan dalam format JSON. |
| `--html` | Output atau ekspor laporan dalam format HTML. |
| `--config` | Memuat berkas konfigurasi YAML; default `config.yaml`. |
| `--depth` | Membatasi kedalaman crawler. |
| `--max-pages` | Membatasi jumlah halaman yang dikumpulkan. |
| `--timeout` | Mengatur timeout request dalam detik. |
| `--deep` | Menjalankan seluruh modul lanjutan dan pemindaian mendalam. |
| `--fuzz` | Mengaktifkan fuzzer parameter. |
| `--chain` | Mengaktifkan korelasi dan sintesis exploit chain. |
| `--auth-token` | Menambahkan Bearer token untuk sesi terautentikasi. |
| `--cookie` | Menambahkan cookie sesi, misalnya `name=value; ...`. |
| `--header` | Menambahkan header kustom `Key: Value`; opsi boleh diulang. |
| `--verbose` | Menampilkan log detail setiap request dan aktivitas pemindaian. |
| `--ignore-robots` | Mengabaikan arahan `robots.txt`. |
| `--no-banner` | Menyembunyikan banner startup Cinder. |

## Disclaimer Etika

Gunakan Cinder **hanya** untuk:

- Sistem atau aset yang sepenuhnya Anda miliki.
- Sistem yang diberi izin tertulis eksplisit dari pemiliknya.
- Lingkungan lab, sandbox, atau kompetisi CTF yang secara khusus mengizinkan pengujian.

Pengujian sistem tanpa izin dapat melanggar hukum, termasuk **UU ITE di Indonesia** dan **Computer Fraud and Abuse Act (CFAA) di Amerika Serikat**, serta peraturan setempat lainnya.

Pengguna sepenuhnya bertanggung jawab atas tindakannya dan dampak dari penggunaan alat ini. Penulis serta kontributor Cinder tidak bertanggung jawab atas penyalahgunaan, kerusakan, gangguan layanan, kehilangan data, atau konsekuensi hukum yang timbul dari penggunaan alat ini.

**Gunakan secara bertanggung jawab dan secara legal.**

## Lisensi

Cinder dilisensikan di bawah lisensi [MIT](LICENSE).

**MIT © lifyDev**
