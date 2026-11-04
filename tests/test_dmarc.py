
from src.dmarc_checker import check_dmarc


def test_dmarc_pass_with_aligned_spf():

    result = check_dmarc(
        from_domain="example.test",
        spf_result="PASS",
        dkim_result="FAIL",
        spf_domain="example.test",
        dkim_domain="untrusted.test",
        record="v=DMARC1; p=none"
    )

    print("\nAligned SPF:", result["status"])

    assert result["status"] == "PASS"


def test_dmarc_fail_when_both_unaligned():

    result = check_dmarc(
        from_domain="example.test",
        spf_result="FAIL",
        dkim_result="FAIL",
        spf_domain="untrusted.test",
        dkim_domain="untrusted.test",
        record="v=DMARC1; p=reject"
    )

    print("\nUnaligned authentication:", result["status"])

    assert result["status"] == "FAIL"


def test_dmarc_pass_with_aligned_dkim():

    result = check_dmarc(
        from_domain="example.test",
        spf_result="FAIL",
        dkim_result="PASS",
        spf_domain="untrusted.test",
        dkim_domain="example.test",
        record="v=DMARC1; p=quarantine"
    )

    print("\nAligned DKIM:", result["status"])

    assert result["status"] == "PASS"
