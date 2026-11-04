# MailShield – Secure Email Authentication Gateway

MailShield is a Flask-based web application designed to demonstrate email authentication concepts and help users analyze email authentication results.

It provides tools for analyzing email headers and testing SPF, DKIM, and DMARC authentication logic through an interactive dashboard.

## Features

- **Email Header Analyzer:** Extracts important email header fields and displays SPF, DKIM, and DMARC results reported in Authentication-Results headers.
- **SPF Checker:** Evaluates sender IP addresses against supported SPF mechanisms.
- **DKIM Key Management:** Generates RSA 2048-bit DKIM key pairs and displays the public DNS TXT record.
- **DKIM Testing:** Locally signs a test email and verifies its DKIM signature.
- **DMARC Checker:** Evaluates SPF/DKIM domain alignment against a supplied DMARC policy.
- **Security Headers:** Configures basic HTTP security response headers.
- **Automated Testing:** Includes pytest test cases for core functionality and Flask routes.

## Technologies Used

- Python 3.12
- Flask
- HTML5
- CSS3
- JavaScript
- dnspython
- cryptography
- dkimpy
- pytest

## Project Structure

```text
MailShield/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── src/
│   ├── __init__.py
│   ├── header_parser.py
│   ├── spf_checker.py
│   ├── dkim_handler.py
│   └── dmarc_checker.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── keys/
│   ├── dkim_private.pem
│   └── dkim_public.pem
│
└── tests/
    ├── test_mailshield.py
    ├── test_dkim.py
    ├── test_spf.py
    └── test_dmarc.py
```

*Note: Generated DKIM key files are local and excluded from Git.*

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd MailShield
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

Open the following address in your browser:

```text
http://127.0.0.1:5000/
```

## Running Tests

Run the automated test suite using:

```bash
python -m pytest -v
```

The project currently includes **17 automated tests** covering authentication logic, application routes, error handling, and security headers.

## Security Considerations

- DKIM private keys are excluded from version control.
- Flask debug mode is disabled.
- Request size is limited to 64 KB.
- Basic HTTP security headers are configured.
- Never upload private keys or secret environment variables to a public repository.
- Configure a strong `FLASK_SECRET_KEY` environment variable before deployment.

## Current Limitations

This project is an educational demonstration and is not a complete production email authentication server.

- **SPF:** Supports `ip4`, `ip6`, and `all` mechanisms. It does not implement the complete SPF specification.
- **DKIM:** Performs local signing and verification using a locally generated public key. It does not publish DNS records or send emails.
- **DMARC:** Implements exact domain alignment. It does not support relaxed organizational-domain alignment or enforce quarantine/reject policies.
- **Header Analyzer:** Parses authentication results already present in pasted email headers. It does not independently authenticate the original email.

## Future Enhancements

- Complete SPF specification support.
- Relaxed DMARC alignment.
- Integration with real DNS records.
- Email server integration.
- Authentication reporting and analytics.
- Enhanced security and deployment configuration.

## Project Purpose

MailShield was developed as an academic project to explore email authentication protocols, understand email security mechanisms, and demonstrate their implementation through a web-based application.