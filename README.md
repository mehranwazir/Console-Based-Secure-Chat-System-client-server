# SecureChat – Assignment #2

**CS-3002 Information Security, Fall 2025**

A console-based, PKI-enabled secure chat system implemented entirely at the **application layer (no TLS)**.
SecureChat demonstrates:

* X.509 certificates (PKI)
* Diffie–Hellman key exchange
* AES-128 encryption (CBC + PKCS#7)
* RSA SHA-256 digital signatures
* Sequence numbers & timestamps
* Replay attack protection
* Non-repudiation with signed transcripts

---

## 📁 Project Structure

```
securechat-skeleton/
├── app/
│   ├── client.py
│   ├── server.py
│   ├── crypto/
│   │   ├── aes.py
│   │   ├── dh.py
│   │   ├── pki.py
│   │   └── sign.py
│   ├── common/
│   │   ├── protocol.py
│   │   └── utils.py
│   └── storage/
│       ├── db.py
│       └── transcript.py
├── scripts/
│   ├── gen_ca.py
│   ├── gen_cert.py
├── transcripts/          
├── certs/
├── .env.example
├── requirements.txt
└── README.md
```

---

# ⚙️ 1 — Setup Instructions

## 1.1 Create virtual environment

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux / macOS

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

# 🗄️ 2 — Configure MySQL

Create database + user:

```sql
CREATE DATABASE securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
```

Copy `.env.example` → `.env`:

```
DB_HOST=127.0.0.1
DB_USER=scuser
DB_PASS=scpass
DB_NAME=securechat
```

Initialize database schema:

```bash
python -m app.storage.db --init
```

Output:

```
[+] MySQL 'users' table created
```

---

# 🔐 3 — Generate Certificates (PKI)

All certificate generation commands are included.

## 3.1 Create Root CA

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA" --out certs/ca
```

Creates:

* `certs/ca.crt.pem`
* `certs/ca.key.pem`  

## 3.2 Issue server & client certificates

```bash
python scripts/gen_cert.py --ca certs/ca.crt.pem --cakey certs/ca.key.pem --cn server.local --out certs/server
python scripts/gen_cert.py --ca certs/ca.crt.pem --cakey certs/ca.key.pem --cn client.local --out certs/client
```

Creates:

* `server.crt.pem`, `server.key.pem`
* `client.crt.pem`, `client.key.pem`

---

# 🔎 3.3 — Commands to **View/Inspect Certificates**

These are essential for PKI demonstration.
Run them after generating certs.

---

## 📌 View Root CA certificate

```bash
openssl x509 -in certs/ca.crt.pem -noout -text
```

## 📌 View Server certificate

```bash
openssl x509 -in certs/server.crt.pem -noout -text
```

## 📌 View Client certificate

```bash
openssl x509 -in certs/client.crt.pem -noout -text
```

---

## 📌 Print Certificate Fingerprints

SHA-256 fingerprint:

```bash
openssl x509 -in certs/server.crt.pem -fingerprint -sha256 -noout
```

MD5 fingerprint:

```bash
openssl x509 -in certs/server.crt.pem -fingerprint -md5 -noout
```

---

## 📌 Verify Certificate Signature Using CA

```bash
openssl verify -CAfile certs/ca.crt.pem certs/server.crt.pem
openssl verify -CAfile certs/ca.crt.pem certs/client.crt.pem
```

Expected output:

```
certs/server.crt.pem: OK
certs/client.crt.pem: OK
```

---

## 📌 View Public Key inside any cert

```bash
openssl x509 -in certs/server.crt.pem -pubkey -noout
```

---

## 📌 Print certificate validity period (important for PKI)

```bash
openssl x509 -in certs/server.crt.pem -noout -dates
```

---

# 🔄 4 — Running SecureChat

### Start Server

```bash
python -m app.server
```

### Start Client (New Terminal)

```bash
python -m app.client
```

Expected flow:

* Certificate exchange
* Certificate validation
* Temporary DH → AES_TEMP_KEY
* Encrypted register/login
* New DH → SESSION_KEY
* Secure chat mode
* `/quit` generates transcript + receipt

---

# 💬 5 — Secure Messaging Format

```json
{
  "type": "msg",
  "seqno": <int>,
  "ts": <unix_ms>,
  "ct": "<AES-CBC ciphertext (base64)>",
  "sig": "<RSA signature over SHA256(seqno||ts||ct)>"
}
```

Provides:

* Confidentiality → AES-128
* Integrity → SHA-256 digest
* Authenticity → RSA-2048 signature
* Freshness → seqno + timestamp
* Replay protection

---

# 🧾 6 — Transcripts & Non-Repudiation

Every chat session generates two files:

### 1. Transcript

```
transcripts/server_YYYYMMDD_HHMMSS.log
```

### 2. Signed Receipt

```
transcripts/server_receipt_YYYYMMDD_HHMMSS.json
```

Receipt structure:

```json
{
  "type": "receipt",
  "peer": "server",
  "first seq": 1,
  "last seq": 5,
  "transcript sha256": "...",
  "sig": "RSA_SIGNATURE"
}
```

---

# 🧪 7 — Verify Transcript Offline

Run:

```bash
python verify_transcript.py 
```

Successful verification prints:

```
[PASS] Non-repudiation verification SUCCESS ✔
```

---


# 📝 8 — Author

**Name:** Mehran
**Roll Number:** 22i-0810
**Course:** CS-3002 Information Security – FAST NUCES

---


