
import pytest
from unittest.mock import patch

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


# ---------------- HOMEPAGE TESTS ----------------

def test_homepage_loads(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"MailShield" in response.data


def test_header_analyzer_empty_input(client):
    response = client.post(
        "/",
        data={"raw_headers": ""}
    )

    assert response.status_code == 200


# ---------------- SPF TESTS ----------------

def test_spf_route(client):
    response = client.post(
        "/check-spf",
        data={
            "domain": "example.test",
            "sender_ip": "192.0.2.10",
            "spf_record": "v=spf1 ip4:192.0.2.10 -all"
        }
    )

    assert response.status_code == 200
    assert b"PASS" in response.data


def test_empty_spf_form(client):
    response = client.post(
        "/check-spf",
        data={}
    )

    assert response.status_code == 200
    assert b"Please fill in all SPF fields." in response.data


# ---------------- DMARC TESTS ----------------

def test_dmarc_route(client):
    response = client.post(
        "/check-dmarc",
        data={
            "from_domain": "example.test",
            "spf_result": "PASS",
            "spf_domain": "example.test",
            "dkim_result": "FAIL",
            "dkim_domain": "untrusted.test",
            "dmarc_record": "v=DMARC1; p=reject"
        }
    )

    assert response.status_code == 200
    assert b"DMARC authentication passed" in response.data


def test_empty_dmarc_form(client):
    response = client.post(
        "/check-dmarc",
        data={}
    )

    assert response.status_code == 200
    assert b"Please fill in all DMARC fields." in response.data


# ---------------- DKIM KEY GENERATION TESTS ----------------

@patch("app.generate_dkim_keys")
@patch("app.get_dns_public_key")
def test_dkim_key_generation_route(
    mock_dns_record,
    mock_generate_keys,
    client
):
    mock_generate_keys.return_value = {
        "message": "DKIM keys generated successfully.",
        "private_key": "keys/dkim_private.pem"
    }

    mock_dns_record.return_value = (
        "v=DKIM1; k=rsa; p=TESTPUBLICKEY"
    )

    response = client.post("/generate-dkim-keys")

    assert response.status_code == 200
    assert b"DKIM keys generated successfully." in response.data
    assert b"TESTPUBLICKEY" in response.data


@patch("app.generate_dkim_keys")
def test_dkim_key_generation_error(
    mock_generate_keys,
    client
):
    mock_generate_keys.side_effect = Exception("Test error")

    response = client.post("/generate-dkim-keys")

    assert response.status_code == 200
    assert b"Key generation failed" in response.data


# ---------------- DKIM SIGNING TESTS ----------------

@patch("app.verify_email")
@patch("app.sign_email")
def test_dkim_signing_route(
    mock_sign_email,
    mock_verify_email,
    client
):
    mock_sign_email.return_value = (
        "DKIM-Signature: test-signature\n"
        "From: alice@example.test\n\n"
        "Test email",
        None
    )

    mock_verify_email.return_value = {
        "status": "PASS",
        "message": "DKIM verification successful."
    }

    response = client.post(
        "/test-dkim",
        data={
            "raw_email": (
                "From: alice@example.test\n"
                "To: bob@example.test\n\n"
                "Test email"
            )
        }
    )

    assert response.status_code == 200
    assert b"PASS" in response.data

    mock_sign_email.assert_called_once()
    mock_verify_email.assert_called_once()


@patch("app.sign_email")
def test_dkim_signing_error(
    mock_sign_email,
    client
):
    mock_sign_email.return_value = (None, "Invalid email input")

    response = client.post(
        "/test-dkim",
        data={"raw_email": ""}
    )

    assert response.status_code == 200
    assert b"Invalid email input" in response.data
def test_security_headers(client):
    response = client.get("/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in response.headers["Permissions-Policy"]