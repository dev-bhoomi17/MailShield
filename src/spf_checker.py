
import dns.resolver


def get_spf_record(domain):
    """
    Retrieve the SPF TXT record for a domain.
    """

    try:
        answers = dns.resolver.resolve(domain, "TXT")

        spf_records = []

        for answer in answers:
            record = answer.to_text().strip('"')

            if record.startswith("v=spf1"):
                spf_records.append(record)

        if len(spf_records) == 0:
            return None, "No SPF record found."

        if len(spf_records) > 1:
            return None, "Multiple SPF records found. Configuration is invalid."

        return spf_records[0], None

    except dns.resolver.NXDOMAIN:
        return None, "Domain does not exist."

    except dns.resolver.NoAnswer:
        return None, "No TXT records found."

    except dns.resolver.Timeout:
        return None, "DNS lookup timed out."

    except Exception as error:
        return None, f"DNS lookup failed: {error}"


def check_spf(domain, sender_ip, record=None):
    """
    Check whether the sender IP is authorized by the domain's SPF record.

    This initial implementation supports:
    - ip4
    - ip6
    - all
    """

    import ipaddress

    if record is None:
        record, error = get_spf_record(domain)
    else:
        error = None
        

    if error:
        return {
            "status": "NONE",
            "record": None,
            "message": error
        }

    try:
        sender = ipaddress.ip_address(sender_ip)
    except ValueError:
        return {
            "status": "ERROR",
            "record": record,
            "message": "Invalid sender IP address."
        }

    terms = record.split()[1:]

    for term in terms:

        if term in ("-all", "~all", "?all", "+all"):
            if term == "-all":
                status = "FAIL"
            elif term == "~all":
                status = "SOFTFAIL"
            elif term == "?all":
                status = "NEUTRAL"
            else:
                status = "PASS"

            return {
                "status": status,
                "record": record,
                "message": f"SPF result: {status}"
            }

        qualifier = "+"

        if term.startswith(("-", "~", "?")):
            qualifier = term[0]
            term = term[1:]

        try:
            if term.startswith("ip4:") and sender.version == 4:
                network = ipaddress.ip_network(
                    term[4:], strict=False
                )

                if sender in network:
                    status = {
                        "+": "PASS",
                        "-": "FAIL",
                        "~": "SOFTFAIL",
                        "?": "NEUTRAL"
                    }[qualifier]

                    return {
                        "status": status,
                        "record": record,
                        "message": f"SPF result: {status}"
                    }

            elif term.startswith("ip6:") and sender.version == 6:
                network = ipaddress.ip_network(
                    term[4:], strict=False
                )

                if sender in network:
                    status = {
                        "+": "PASS",
                        "-": "FAIL",
                        "~": "SOFTFAIL",
                        "?": "NEUTRAL"
                    }[qualifier]

                    return {
                        "status": status,
                        "record": record,
                        "message": f"SPF result: {status}"
                    }

        except ValueError:
            continue

    return {
        "status": "NEUTRAL",
        "record": record,
        "message": "No supported SPF mechanism matched the sender IP."
    }
