import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_public_key
from cryptography.hazmat.backends import default_backend
import requests
from cryptography import x509
from pretix.base.payment import PaymentException

def build_data_to_sign(payload: dict) -> str:
    """
    Build canonical string for signing/verifying according to Aircash spec.
    - Keys sorted alphabetically (case-insensitive).
    - Floats trimmed (123.450 → 123.45).
    - Empty/None values => "key=".
    """
    items = []
    for key in sorted(payload.keys(), key=lambda x: x.lower()):
        if key == "Signature":
            continue 

        val = payload[key]
        if val is None or val == "":
            items.append(f"{key}=")
        else:
            if isinstance(val, float):
                val = str(val).rstrip("0").rstrip(".")
            items.append(f"{key}={val}")
    return "&".join(items)

def generate_signature(data_to_sign, certificate_path, certificate_pass):
    with open(certificate_path, 'rb') as pfx_file:
        pfx_data = pfx_file.read()

    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        pfx_data,
        certificate_pass.encode(),
        backend=default_backend() 
    )

    original_data = data_to_sign.encode('utf-8')

    signature = private_key.sign(
        original_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode('utf-8')

from decimal import Decimal

def build_data_to_verify(payload: dict) -> str:
    keys = ["AircashTransactionId", "Amount", "CurrencyId", "Parameters", "Status"]
    parts = []

    for key in keys:
        if key.lower() in ("signature", "events"):
            continue

        # Look up value in multiple casings
        val = (
            payload.get(key)
            or payload.get(key.lower())
            or payload.get(key[0].lower() + key[1:])
        )

        if key == "Parameters":
            if not val:
                parts.append(f"{key}=")
            else:
                param_parts = []
                for item in val:
                    for subkey in ["Key", "Value"]:
                        # handle lowercase too
                        sval = item.get(subkey) or item.get(subkey.lower())
                        if sval is not None:
                            param_parts.append(f"{subkey}={sval}")
                parts.append(f"{key}=" + "&".join(param_parts))
            continue

        if val is None or val == "":
            parts.append(f"{key}=")
        else:
            if isinstance(val, float):
                val = str(val).rstrip("0").rstrip(".")
            parts.append(f"{key}={val}")

    return "&".join(parts)




def verify_signature(payload: dict, signature: str, public_key_path: str) -> bool:
    """
    Verify Aircash response/webhook signature using Aircash certificate PEM.
    - payload: dict response with 'Signature' already removed
    - signature: Base64-encoded signature string from Aircash
    - public_key_path: path to Aircash's certificate PEM
    """
    canonical = build_data_to_verify(payload)

    logger.info("Canonical string for verification: %s", canonical)


    with open(public_key_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
        pub_key = cert.public_key()

    try:
        pub_key.verify(
            base64.b64decode(signature),
            canonical.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print("Aircash signature verification failed:", e)
        return False


import logging

logger = logging.getLogger(__name__)

def query_aircash_status(payment, settings):
    base_url = settings.api_base.rstrip("/")
    if base_url.endswith("/v2"):
        base_url = base_url[:-3] + "/v3"
    elif base_url.endswith("/v2/"):
        base_url = base_url[:-4] + "/v3"

    url = base_url + "/status"

    payload = {
        "PartnerId": settings.partner_id,
        "PartnerTransactionId": f"{payment.order.code}-{payment.local_id}",
    }
    data_to_sign = build_data_to_sign(payload)
    payload["Signature"] = generate_signature(
        data_to_sign,
        certificate_path=settings.certificate_path,
        certificate_pass=settings.certificate_pass,
    )

    resp = requests.post(url, json=payload, timeout=30)

    if resp.status_code != 200:
        raise PaymentException("Aircash status API error: " + resp.text)

    data = resp.json()

    signature = data.pop("signature", None)
    if not signature:
        raise PaymentException("Aircash response missing Signature")


    valid = verify_signature(data, signature, settings.public_key_path)

    if not valid:
        raise PaymentException("Invalid signature on Aircash response")

    return data
