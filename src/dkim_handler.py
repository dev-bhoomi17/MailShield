
import os
import dkim
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


KEY_DIRECTORY = "keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIRECTORY, "dkim_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIRECTORY, "dkim_public.pem")

DEFAULT_DOMAIN = "example.test"
DEFAULT_SELECTOR = "mailshield"


def generate_dkim_keys():
    """Generate an RSA key pair for DKIM signing."""

    os.makedirs(KEY_DIRECTORY, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(PRIVATE_KEY_PATH, "wb") as file:
        file.write(private_pem)

    with open(PUBLIC_KEY_PATH, "wb") as file:
        file.write(public_pem)

    return {
        "message": "DKIM keys generated successfully.",
        "private_key": PRIVATE_KEY_PATH,
        "public_key": PUBLIC_KEY_PATH
    }


def get_dns_public_key():
    """Generate the public key value for a DKIM DNS TXT record."""

    if not os.path.exists(PUBLIC_KEY_PATH):
        return None

    with open(PUBLIC_KEY_PATH, "rb") as file:
        public_key = serialization.load_pem_public_key(file.read())

    # DKIM requires the DER-encoded RSA public key, not SPKI.
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )

    encoded_key = base64.b64encode(public_der).decode("ascii")

    return f"v=DKIM1; k=rsa; p={encoded_key}"



def sign_email(raw_email, domain=DEFAULT_DOMAIN,
               selector=DEFAULT_SELECTOR):
    """Sign an email using the generated DKIM private key."""

    if not os.path.exists(PRIVATE_KEY_PATH):
        return None, "Generate DKIM keys first."

    with open(PRIVATE_KEY_PATH, "rb") as file:
        private_key = file.read()

    try:
        signature = dkim.sign(
            raw_email.encode("utf-8"),
            selector.encode(),
            domain.encode(),
            private_key,
            include_headers=[
                b"from",
                b"to",
                b"subject"
            ]
        )

        signed_email = signature + raw_email.encode("utf-8")

        return signed_email.decode("utf-8"), None

    except Exception as error:
        return None, f"DKIM signing failed: {error}"



def verify_email(signed_email, domain=DEFAULT_DOMAIN,
                 selector=DEFAULT_SELECTOR):
    """Verify a DKIM signature using our locally generated public key."""

    record = get_dns_public_key()

    if not record:
        return {
            "status": "ERROR",
            "message": "DKIM public key not found."
        }

    expected_name = (
        f"{selector}._domainkey.{domain}."
    ).lower()

    def local_dns_lookup(name, timeout=5):
        if isinstance(name, bytes):
            name = name.decode("ascii")

        if name.lower() == expected_name:
            return record.encode("ascii")

        return None

    try:
        result = dkim.verify(
            signed_email.encode("utf-8"),
            dnsfunc=local_dns_lookup
        )

        return {
            "status": "PASS" if result else "FAIL",
            "message": (
                "DKIM signature is valid."
                if result
                else "DKIM signature verification failed."
            )
        }

    except Exception as error:
        return {
            "status": "ERROR",
            "message": f"DKIM verification error: {error}"
        }
