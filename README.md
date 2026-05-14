# 🗳️ SecureVote IOBM — Campus E-Voting System

> A cryptographically secure, blockchain-backed electronic voting system built for the **IEEE IOBM Student Branch Elections 2026**.  
> Built with Flask · SQLite · RSA Digital Signatures · Blockchain Ledger · OTP 2FA

---

## 📌 Project Overview

SecureVote IOBM is a full-stack web-based e-voting platform designed for small-scale institutional elections. It ensures **voter anonymity**, **tamper-proof vote storage**, and **verifiable election results** using industry-standard cryptographic techniques.

This was developed as a **semester project** for a Cybersecurity / Software Engineering course at the Institute of Business Management (IoBM), Karachi.

---

## ✨ Features

### 🔐 Security
- **bcrypt** password hashing with salt
- **OTP Two-Factor Authentication** via email (6-digit, 10-minute expiry)
- **Account lockout** after 5 failed login attempts (10-minute cooldown)
- **Password strength enforcement** (uppercase, number, special character)
- **HMAC-chained audit log** — every action is tamper-evident
- **RSA digital signature** on final election results (2048-bit key pair)
- **Input sanitization** and IOBM email whitelist enforcement

### ⛓️ Blockchain
- Every vote is stored as a **blockchain block** with SHA-256 hashing
- Each block contains: index, candidate, position, vote token, timestamp, previous hash
- Admin dashboard verifies **full chain integrity** in real time

### 🗳️ Voting
- Students vote for **4 positions**: President, Vice President, General Secretary, Treasurer
- **One vote per position** per student — enforced at database level
- **10-minute timed voting window** — session auto-closes after expiry
- Votes are **anonymized** — voter identity is never stored with vote records
- Anonymous vote tokens generated per vote

### 📊 Admin Panel
- Manage **eligible voter whitelist** (add / remove by IOBM email)
- Add and remove **candidates** per position
- View **live results** with progress bars
- **Sign and finalize** election results with RSA private key
- Full **audit log** viewer with IP addresses and timestamps
- Blockchain integrity status displayed on dashboard

### 🔍 Public Verification
- Anyone can verify the **RSA signature** of final results using the public key
- Public key displayed on the verification page
- Results cannot be modified after signing without detection

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask |
| Database | SQLite via Flask-SQLAlchemy |
| Authentication | bcrypt, OTP via SMTP (Gmail) |
| Cryptography | `cryptography` library — RSA, Fernet |
| Blockchain | Custom SHA-256 chained ledger |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Email | smtplib + Gmail SMTP |

---

## 📁 Project Structure

```
SecureVote-IOBM/
│
├── app.py                  # Flask routes and application logic
├── auth.py                 # Registration, login, OTP, session management
├── models.py               # SQLAlchemy database models
├── crypto.py               # RSA, blockchain, HMAC, OTP generation
├── config.py               # App configuration (email, secrets, limits)
│
├── static/
│   ├── style.css           # Global stylesheet
│   └── main.js             # Session countdown timer
│
├── templates/
│   ├── base.html           # Base layout with navbar
│   ├── login.html          # Student login page
│   ├── register.html       # Registration with password strength meter
│   ├── otp_verify.html     # OTP verification (registration & login)
│   ├── vote.html           # Voting page with live timer
│   ├── vote_closed.html    # Voting session ended page
│   ├── student_results.html# Election results for students
│   ├── verify_results.html # Public RSA signature verification
│   ├── admin.html          # Admin dashboard
│   └── admin_voters.html   # Eligible voter management
│
├── data.db                 # SQLite database (auto-created on first run)
├── secret.key              # Fernet key (auto-generated)
├── rsa_private.pem         # RSA private key (auto-generated)
├── rsa_public.pem          # RSA public key (auto-generated)
│
├── requirements.txt        # Python dependencies
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/your-username/SecureVote-IOBM.git
cd SecureVote-IOBM
```

### 2. Create a virtual environment
```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Mac/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure email (for OTP)
Open `config.py` and update:
```python
MAIL_USERNAME = 'your-email@gmail.com'
MAIL_PASSWORD = 'your-app-password'   # Gmail App Password, not your real password
```
> To get a Gmail App Password: Google Account → Security → 2-Step Verification → App Passwords

### 5. Run the application
```bash
python app.py
```

Then open your browser and go to: **http://localhost:5000**

---

## 🔑 Default Admin Credentials

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `admin123` |
| URL | `/admin` |

> ⚠️ Change these in `config.py` before deploying.

---

## 🚀 How to Use

### As Admin:
1. Go to `/admin` and log in
2. Add eligible voters by IOBM email under **Manage Voters**
3. Add candidates for each of the 4 positions
4. Monitor live results on the dashboard
5. After voting ends, click **Sign & Finalize Results** to RSA-sign them

### As a Student:
1. Go to `/register` — your IOBM email must be on the approved list
2. Verify your email with the OTP sent to your inbox
3. Log in — a second OTP is sent for 2FA
4. Vote for candidates in all 4 positions within the 10-minute window
5. View results at `/results` after the election is finalized

---

## 🔐 Cybersecurity Features Summary

| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt with random salt |
| Two-Factor Auth | Time-limited OTP via email |
| Brute Force Protection | Account lockout after 5 attempts |
| Voter Anonymity | Vote tokens — identity never linked to vote |
| Tamper Detection | HMAC-chained audit log |
| Vote Integrity | SHA-256 blockchain ledger |
| Result Authentication | RSA-2048 digital signature |
| Email Whitelist | Only approved emails can register |
| Session Security | Timed voting window, auto-logout |

---

## 👨‍💻 Author

**Waniya** — IoBM, Karachi  
Semester Project — Cybersecurity / Software Engineering  
IEEE IOBM Student Branch Elections 2026

---

## 📄 License

This project is for academic purposes only.  
Not licensed for commercial use.

---

> *"Security is not a product, but a process."* — Bruce Schneier
