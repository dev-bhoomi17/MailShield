
import re

from src.dkim_handler import generate_dkim_keys, get_dns_public_key
import os
from src.dkim_handler import sign_email, verify_email
from src.spf_checker import check_spf
from src.dmarc_checker import check_dmarc

from flask import Flask, render_template, request
from src.header_parser import parse_email_headers

app = Flask(__name__)

app.config.update(
    MAX_CONTENT_LENGTH=64 * 1024,
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "mailshield-dev-key")
)

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response

def extract_authentication_status(results):
    """Extract SPF, DKIM and DMARC results from Authentication-Results."""

    summary = {
        "SPF": "NOT FOUND",
        "DKIM": "NOT FOUND",
        "DMARC": "NOT FOUND"
    }

    for result in results:
        for protocol in summary:
            pattern = (
                rf"\b{protocol.lower()}\s*=\s*"
                rf"(pass|fail|softfail|neutral|none|"
                rf"temperror|permerror|policy)"
            )

            matches = re.findall(pattern, result, re.IGNORECASE)

            if matches:
                summary[protocol] = matches[0].upper()

    return summary


@app.route("/", methods=["GET", "POST"])
def index():

    parsed_data = None
    auth_summary = None
    error = None

    if request.method == "POST":

        raw_headers = request.form.get("raw_headers", "")

        parsed_data = parse_email_headers(raw_headers)

        if parsed_data["success"]:

            auth_summary = extract_authentication_status(
                parsed_data["authentication_results"]
            )

            parsed_data["received_spf"] = (
                parsed_data["received_spf"]
            )

        else:
            error = parsed_data["error"]
            parsed_data = None

    return render_template(
        "index.html",
        parsed_data=parsed_data,
        auth_summary=auth_summary,
        error=error
    )


@app.route("/generate-dkim-keys", methods=["POST"])
def generate_keys():

    try:
        result = generate_dkim_keys()
        dns_record = get_dns_public_key()

        return render_template(
            "index.html",
            parsed_data=None,
            auth_summary=None,
            error=None,
            dkim_message=result["message"],
            dkim_record=dns_record,
            private_key_path=os.path.abspath(
                result["private_key"]
            )
        )

    except Exception as error:
        return render_template(
            "index.html",
            parsed_data=None,
            auth_summary=None,
            error=None,
            dkim_message=f"Key generation failed: {error}",
            dkim_record=None,
            private_key_path=None
        )


@app.route("/test-dkim", methods=["POST"])
def test_dkim():

    raw_email = request.form.get("raw_email", "").strip()

    signed_email, error = sign_email(raw_email)

    if error:
        return render_template(
            "index.html",
            parsed_data=None,
            auth_summary=None,
            error=None,
            dkim_test_error=error
        )

    verification = verify_email(signed_email)

    return render_template(
        "index.html",
        parsed_data=None,
        auth_summary=None,
        error=None,
        signed_email=signed_email,
        verification=verification
    )


@app.route("/check-spf", methods=["POST"])
def check_spf_route():

    domain = request.form.get("domain", "").strip()
    sender_ip = request.form.get("sender_ip", "").strip()
    spf_record = request.form.get("spf_record", "").strip()

    if not domain or not sender_ip or not spf_record:
        return render_template(
            "index.html",
            parsed_data=None,
            auth_summary=None,
            error=None,
            spf_result={
                "status": "ERROR",
                "message": "Please fill in all SPF fields."
            }
        )

    result = check_spf(
        domain,
        sender_ip,
        record=spf_record
    )

    return render_template(
        "index.html",
        parsed_data=None,
        auth_summary=None,
        error=None,
        spf_result=result
    )


@app.route("/check-dmarc", methods=["POST"])
def check_dmarc_route():

    from_domain = request.form.get("from_domain", "").strip()
    spf_result = request.form.get("spf_result", "").strip()
    dkim_result = request.form.get("dkim_result", "").strip()
    spf_domain = request.form.get("spf_domain", "").strip()
    dkim_domain = request.form.get("dkim_domain", "").strip()
    dmarc_record = request.form.get("dmarc_record", "").strip()

    if not all([
        from_domain, spf_result, dkim_result,
        spf_domain, dkim_domain, dmarc_record
    ]):
        result = {
            "status": "ERROR",
            "policy": "unknown",
            "message": "Please fill in all DMARC fields."
        }
    else:
        result = check_dmarc(
            from_domain=from_domain,
            spf_result=spf_result,
            dkim_result=dkim_result,
            spf_domain=spf_domain,
            dkim_domain=dkim_domain,
            record=dmarc_record
        )

    return render_template(
        "index.html",
        parsed_data=None,
        auth_summary=None,
        error=None,
        dmarc_result=result
    )


if __name__ == "__main__":
    app.run(
    host="127.0.0.1",
    port=5000,
    debug=False
)
