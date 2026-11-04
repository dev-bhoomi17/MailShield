
from email import policy
from email.parser import Parser


def parse_email_headers(raw_headers):
    """
    Parse raw email headers and extract authentication information.
    """

    if not raw_headers or not raw_headers.strip():
        return {
            "success": False,
            "error": "Please provide email headers."
        }

    try:
        headers = Parser(policy=policy.default).parsestr(
            raw_headers,
            headersonly=True
        )

        authentication_results = headers.get_all(
            "Authentication-Results", []
        )

        received_spf = headers.get_all("Received-SPF", [])

        from_address = headers.get("From", "Not found")
        return_path = headers.get("Return-Path", "Not found")
        message_id = headers.get("Message-ID", "Not found")

        return {
            "success": True,
            "from": str(from_address),
            "return_path": str(return_path),
            "message_id": str(message_id),
            "authentication_results": [
                str(value) for value in authentication_results
            ],
            "received_spf": [
                str(value) for value in received_spf
            ]
        }

    except Exception as error:
        return {
            "success": False,
            "error": f"Unable to parse headers: {error}"
        }
