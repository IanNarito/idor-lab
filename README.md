# IDOR Security Academy Lab

A deliberately vulnerable web application designed for teaching and practicing Insecure Direct Object Reference (IDOR) vulnerabilities. This lab provides a hands-on environment to explore four progressive IDOR patterns commonly encountered in web application penetration testing.

## ⚠️ Security Disclaimer
**WARNING:** This application is intentionally vulnerable and contains severe security flaws. **Do not deploy this application on a public-facing server or in a production environment.** It is designed to be run strictly on a local, isolated machine (via Docker) for educational purposes only.

---

## 🎯 Lab Scenarios

This lab walks students through four distinct IDOR variations:

1. **Lab 1: Basic Sequential ID** - Exposes direct database keys (integers) in URL parameters.
2. **Lab 2: Encoded ID** - Demonstrates obfuscation using simple encoding schemes (Base64).
3. **Lab 3: Hashed ID** - Replaces sequential IDs with deterministic cryptographic hashes (MD5).
4. **Lab 4: Unpredictable UUID** - Highlights the difference between identifier unguessability and actual backend authorization checks using a two-account methodology.

---

## ⚙️ Prerequisites

To run this lab, you will need:
* [Docker](https://docs.docker.com/get-docker/) and Docker Compose
* Git

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone [https://github.com/IanNarito/idor-lab.git](https://github.com/IanNarito/idor-lab.git)
cd idor-lab
docker compose up --build -d
