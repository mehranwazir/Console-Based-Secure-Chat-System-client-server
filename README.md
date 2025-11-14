SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

A fully implemented, cryptographically secure, console-based chat system using:

X.509 certificates (PKI)

Diffie–Hellman key exchange

AES-128 encryption (CBC + PKCS#7)

RSA SHA-256 signatures

Sequence numbers & timestamps

Non-repudiation via transcript signing

All cryptographic operations are performed at the application layer (no TLS).

📁 Project Structure
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

⚙️ 1. Setup Instructions
1.1 Clone & create virtual environment
git clone <your-fork-url>
cd securechat-skeleton
python -m venv .venv
.\.venv\Scripts\activate        # Windows
pip install -r requirements.txt

1.2 Configure MySQL

Create database and user (via MySQL Workbench or CLI):

CREATE DATABASE securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;

1.3 Configure .env

Create .env in root directory:

DB_HOST=127.0.0.1
DB_USER=scuser
DB_PASS=scpass
DB_NAME=securechat

1.4 Initialize database schema
python -m app.storage.db --init


You should see:

[+] MySQL 'users' table created

🔐 2. Generate Certificates (PKI)
2.1 Create Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"


Produces:

certs/ca.key.pem

certs/ca.crt.pem

2.2 Issue certificates
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client


Produces:

server.key.pem

server.crt.pem

client.key.pem

client.crt.pem

🚫 Do NOT commit any .key.pem files.

🔄 3. Running the System
3.1 Start Server
python -m app.server


You should see:

[*] Listening on 0.0.0.0:9000

3.2 Start Client
python -m app.client


Client performs:

Certificate exchange

Certificate validation

Temporary DH → AES_TEMP_KEY

Encrypted registration/login

New DH session → SESSION_KEY

Enter chat mode

💬 4. Chat Usage
Sending a message

Type in client or server:

> hello


Messages are encrypted, signed, timestamped, and logged in transcript.

Quit chat
/quit


Generates a SessionReceipt in transcripts/.

🔒 5. Security Features
5.1 PKI & Certificate Validation

Client & Server send certificates

Validate:

CA signature

validity period

Common Name (CN)

Rejects self-signed or mismatched CN (BAD_CERT)

5.2 Encrypted Registration/Login

Temporary DH exchange creates AES_TEMP_KEY

Credentials encrypted with AES-128-CBC

Server stores:

salt (16 bytes)

pwd_hash = SHA256(salt || password)

5.3 Session DH & AES-128

New DH exchange after login:

SESSION_KEY = Trunc16(SHA256(shared_secret))


Used for all chat messages.

5.4 Secure Messaging

Each message contains:

{
  "type": "msg",
  "seqno": n,
  "ts": unix_ms,
  "ct": base64(AES(ciphertext)),
  "sig": base64(RSA_SIGN(SHA256(seqno || ts || ct)))
}


Provides:

Confidentiality (AES)

Integrity (SHA256)

Authenticity (RSA)

Replay protection (seqno, ts)

5.5 Non-Repudiation

Each side maintains a transcript:

seqno | timestamp | ciphertext | signature | peer_cert_fp


At /quit, a SessionReceipt is created:

{
  "type": "receipt",
  "peer": "client",
  "first seq": 1,
  "last seq": 5,
  "transcript sha256": "....",
  "sig": "RSA_SIGNATURE"
}


Receipt signature is verified offline.

🧪 6. Testing & Evidence Required (All Passed)
✔ Wireshark: encrypted packets only
✔ BAD_CERT test
✔ Tampering test → SIG_FAIL
✔ Replay attack → REPLAY detected
✔ Transcript SHA256 + Receipt signature verification
✔ Login & register encrypted
✔ DH secret → matching AES keys

Screenshots included in TestReport.

🗂 7. MySQL Schema Dump Example

mysql_schema.sql:

CREATE TABLE users (
  email VARCHAR(255),
  username VARCHAR(255) UNIQUE,
  salt BINARY(16),
  pwd_hash CHAR(64)
);

🚫 8. Items Not Committed to GitHub

All private keys (*.key.pem)

.env

/certs/ folder

/transcripts/ folder

MySQL password

PCAP files (add only in final ZIP)

📝 9. Author

Name: Mehran
Roll Number: 22i-0810
Course: FAST-NUCES | CS-3002 Information Security

