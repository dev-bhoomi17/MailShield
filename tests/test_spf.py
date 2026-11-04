
from src.spf_checker import check_spf


def test_authorized_ip_passes_spf():

    record = "v=spf1 ip4:192.0.2.10 -all"

    result = check_spf(
        "example.test",
        "192.0.2.10",
        record=record
    )

    print("\nAuthorized IP:", result["status"])

    assert result["status"] == "PASS"


def test_unauthorized_ip_fails_spf():

    record = "v=spf1 ip4:192.0.2.10 -all"

    result = check_spf(
        "example.test",
        "192.0.2.20",
        record=record
    )

    print("\nUnauthorized IP:", result["status"])

    assert result["status"] == "FAIL"
