# 🔒 FastOpenSSL

**FastOpenSSL** is a modified version of OpenSSL 1.1.0 that applies **AES-GCM encryption/decryption pre-computation** for enhanced performance.
It utilizes a **circular buffer** to generate key streams in parallel and applies XOR-based encryption efficiently.

---

## 📁 Project Structure

```bash
./openssl # FastOpenSSL source code (based on OpenSSL 1.1.0)
./example # Sample code demonstrating FastOpenSSL (original vs. FastOpenSSL)
```

## ⚙️ Run the Sample code
```bash
./config -Wl,-rpath,$HOME/openssl_build/lib -g -O0 --prefix=$HOME/openssl_build
cd example
./mk.sh
```

## To Do
- [ ] Issue #1: Auth Tag Validation   
- [ ] Remove comments in code  
- [ ] Code Refactoring  
