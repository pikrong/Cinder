# Cinder — Web Vulnerability Scanner

Cinder adalah scanner kerentanan web open-source berbasis Python. Ia merayapi
situs target secara sopan, menjalankan serangkaian pemeriksaan keamanan, lalu
menyajikan laporan dalam format terminal (rich) atau JSON.

## Fitur

- **Crawler sopan** — mengikuti tautan dengan batas kedalaman, jumlah halaman,
  dan domain; menghormati `robots.txt` dan jeda antar-request.
- **Pemeriksaan bawaan**
  - Header keamanan yang hilang/lemah (CSP, HSTS, X-Frame-Options, dll.)
  - Reflected XSS (probe parameter)
  - Error-based SQL Injection (probe parameter)
  - Open Redirect (probe parameter)
  - Directory listing terbuka
  - File sensitif terekspos (`.env`, `.git/config`, backup, dll.)
- **Konfigurasi YAML** untuk menyalakan/mematikan pemeriksaan, payload, dan
  batas pemindaian (`config.yaml`).
- **Output** ke terminal, file teks, atau JSON (`--json`).
- **CLI ergonomis** dengan [Typer](https://typer.tiangolo.com/) dan
  [Rich](https://github.com/Textualize/rich).

## Instalasi

Butuh Python 3.10+.

```bash
git clone https://github.com/your-org/cinder.git
cd cinder
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Opsional, jalankan langsung sebagai modul:

```bash
python cinder.py --help
```

## Penggunaan

Pemindaian dasar:

```bash
python cinder.py -u https://example.com
```

Simpan hasil ke file:

```bash
python cinder.py -u https://example.com -o scan.txt
```

Output JSON (cocok untuk pipeline/CI):

```bash
python cinder.py -u https://example.com --json -o scan.json
```

### Opsi CLI

| Flag | Deskripsi |
|------|-----------|
| `-u, --url` | URL target yang akan dipindai (wajib). |
| `-o, --output` | Path file untuk menyimpan laporan. |
| `--json` | Keluarkan laporan dalam format JSON. |
| `--config` | Path ke file konfigurasi (default: `config.yaml`). |
| `--depth` | Batas kedalaman crawl (menimpa config). |
| `--max-pages` | Batas jumlah halaman (menimpa config). |
| `--timeout` | Timeout per-request dalam detik. |

Contoh dengan override:

```bash
python cinder.py -u https://example.com --depth 3 --max-pages 200 --json -o out.json
```

## Disclaimer Etika

Cinder ditujukan **hanya** untuk pengujian keamanan yang sah dan diizinkan,
seperti:

- sistem yang Anda miliki sendiri,
- target dengan izin tertulis eksplisit dari pemiliknya, atau
- lingkungan lab/CTF yang memang dirancang untuk diuji.

Memindai sistem tanpa izin dapat melanggar hukum (mis. UU ITE di Indonesia,
CFAA di AS, atau regulasi setempat lainnya). Pengguna bertanggung jawab penuh
atas tindakannya. Penulis dan kontributor Cinder tidak bertanggung jawab atas
penyalahgunaan atau kerusakan akibat penggunaan alat ini.

**Gunakan secara bertanggung jawab dan etis.**

## Lisensi

Dirilis di bawah lisensi [MIT](LICENSE).
