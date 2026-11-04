
import dns.resolver


def get_dmarc_record(domain):
    """Retrieve the DMARC TXT record for a domain."""

    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for answer in answers:
            record = answer.to_text().strip('"')

            if record.startswith("v=DMARC1"):
                return record, None

        return None, "No DMARC record found."

    except dns.resolver.NXDOMAIN:
        return None, "Domain does not exist."

    except dns.resolver.NoAnswer:
        return None, "No DMARC TXT record found."

    except dns.resolver.Timeout:
        return None, "DNS lookup timed out."

    except Exception as error:
        return None, f"DNS lookup failed: {error}"


def parse_dmarc_policy(record):
    """Extract DMARC policy information from a record."""

    policy = {}

    for item in record.split(";"):
        item = item.strip()

        if "=" in item:
            key, value = item.split("=", 1)
            policy[key.strip()] = value.strip()

    return policy


def check_dmarc(from_domain, spf_result, dkim_result,
                spf_domain=None, dkim_domain=None,
                record=None):
    """
    Evaluate DMARC using SPF/DKIM authentication and alignment.

    This implementation uses exact domain alignment.
    """

    if record is None:
        record, error = get_dmarc_record(from_domain)

        if error:
            return {
                "status": "NONE",
                "policy": "none",
                "message": error
            }

    policy_data = parse_dmarc_policy(record)

    if policy_data.get("v") != "DMARC1" or "p" not in policy_data:
        return {
            "status": "ERROR",
            "policy": "unknown",
            "message": "Invalid DMARC record."
        }

    policy = policy_data["p"].lower()

    if policy not in ("none", "quarantine", "reject"):
        return {
            "status": "ERROR",
            "policy": policy,
            "message": "Unsupported DMARC policy."
        }

    # SPF passes only when its authenticated domain aligns.
    spf_aligned = (
        spf_result == "PASS"
        and spf_domain is not None
        and spf_domain.lower() == from_domain.lower()
    )

    # DKIM passes only when its signing domain aligns.
    dkim_aligned = (
        dkim_result == "PASS"
        and dkim_domain is not None
        and dkim_domain.lower() == from_domain.lower()
    )

    dmarc_pass = spf_aligned or dkim_aligned

    if dmarc_pass:
        return {
            "status": "PASS",
            "policy": policy,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "message": "DMARC authentication passed."
        }

    return {
        "status": "FAIL",
        "policy": policy,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "message": f"DMARC failed. Policy is {policy}."
    }
