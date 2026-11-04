
from src.dkim_handler import (
    generate_dkim_keys,
    sign_email,
    verify_email
)


def test_dkim_signing_and_verification():

    # Step 1: Generate DKIM keys
    result = generate_dkim_keys()
    print("\nKey generation:", result["message"])

    # Step 2: Prepare a test email
    raw_email = (
        "From: sender@example.test\r\n"
        "To: receiver@example.test\r\n"
        "Subject: MailShield DKIM Test\r\n"
        "\r\n"
        "This is a test email signed by MailShield.\r\n"
    )

    # Step 3: Sign the email
    signed_email, error = sign_email(raw_email)

    assert error is None, error
    assert signed_email is not None

    print("Email signing: SUCCESS")

    # Step 4: Verify the DKIM signature
    result = verify_email(signed_email)

    print("Verification:", result["status"])
    print(result["message"])

    assert result["status"] == "PASS"


if __name__ == "__main__":
    test_dkim_signing_and_verification()
