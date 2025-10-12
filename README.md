# Tugas Keamanan Informasi — Implementasi DES (Python & C++)

Cavel Ferrari
5025211198

Repositori ini berisi dua implementasi pendidikan DES (Data Encryption Standard):
- `python/` — implementasi DES murni di Python (ECB, PKCS#7 padding) dengan CLI
- `cpp/` — implementasi DES di C++ (ECB, PKCS#7 padding) dengan Makefile

---
## Struktur
- python/
  - des.py
  - cli.py
  - test_vectors.txt
  - README.md
- cpp/
  - des.cpp
  - cli.cpp
  - Makefile
  - README.md
- README.md (this file)

## Cara singkat pakai (Python)
```bash
# Enkripsi
python3 python/cli.py encrypt --key 133457799BBCDFF1 --in plain.bin --out cipher.bin

# Dekripsi
python3 python/cli.py decrypt --key 133457799BBCDFF1 --in cipher.bin --out plain_dec.bin
```

## Cara singkat pakai (C++)
Build & pakai:
```bash
cd cpp
make
./des_cli encrypt 133457799BBCDFF1 plain.bin cipher.bin
./des_cli decrypt 133457799BBCDFF1 cipher.bin plain_dec.bin
```

