# MailShield – Secure Email Authentication Gateway

MailShield is a web-based email authentication gateway developed using Python and Flask. It helps users understand and test email authentication mechanisms such as SPF, DKIM, and DMARC through a simple dashboard.

**Live Demo:** https://mailshield-3rxl.onrender.com

**GitHub Repository:** https://github.com/dev-bhoomi17/MailShield

## Features

- **Email Header Analyzer:** Extracts important email header information and displays SPF, DKIM, and DMARC results reported in the supplied headers.
- **SPF Checker:** Evaluates sender IP addresses against supported SPF record mechanisms.
- **DKIM Key Management:** Generates RSA 2048-bit DKIM key pairs and displays the DNS TXT record.
- **DKIM Signing and Verification:** Signs sample emails and verifies their signatures locally.
- **DMARC Checker:** Evaluates SPF/DKIM domain alignment and reports the configured DMARC policy.
- **Security Headers:** Adds HTTP security headers to Flask responses.
- **Automated Testing:** Includes unit and application route tests using pytest.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web framework |
| HTML, CSS, JavaScript | Frontend |
| dnspython | DNS record lookup |
| cryptography | RSA key generation |
| dkimpy | DKIM signing and verification |
| pytest | Automated testing |
| Gunicorn | Production WSGI server |
| Render | Cloud deployment |
| Git and GitHub | Version control |

## Project Structure

```text
MailShield/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── src/
│   ├── __init__.py
│   ├── header_parser.py
│   ├── spf_checker.py
│   ├── dkim_handler.py
│   └── dmarc_checker.py
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
├── keys/
│   └── Generated locally (not committed)
└── tests/
    ├── test_mailshield.py
    ├── test_dkim.py
    ├── test_spf.py
    └── test_dmarc.py
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/dev-bhoomi17/MailShield.git
cd MailShield
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

**Windows:**

```powershell
venv\Scripts\activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure the Flask secret key

For local development, set a secret key before running the application.

```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-unique-secret"
```

### 6. Run the application

```bash
python app.py
```

Open the following URL in your browser:

http://127.0.0.1:5000

## Running Tests

Run the complete automated test suite:

```bash
python -m pytest -v
```

**Latest local test result:** 17 tests passed.

## Security Considerations

- Private DKIM keys are excluded from Git using `.gitignore`.
- Flask secret configuration is provided through an environment variable.
- The application limits request size to 64 KB.
- HTTP security headers are configured.
- Generated DKIM keys should be handled securely.

## Current Limitations

- **SPF:** The evaluator supports `ip4`, `ip6`, and `all`; it is not a complete implementation of the SPF specification.
- **DKIM:** Signing and verification use locally generated keys. DNS publication and actual email delivery are not implemented.
- **DMARC:** The evaluator supports exact domain alignment and reports policy; it does not enforce quarantine or rejection.
- **Header Analyzer:** It parses authentication results already present in the supplied headers. It does not independently authenticate the original email.

## Future Enhancements

- Full SPF specification support.
- Relaxed DMARC alignment.
- Integration with real email servers.
- Secure persistent DKIM key management.
- Detailed authentication reports and analytics.

## Project Purpose

MailShield demonstrates the working principles of email authentication and common mechanisms used to help protect email domains against spoofing and unauthorized use.

Developed as an academic project using Python, Flask, and web technologies.