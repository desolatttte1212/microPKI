from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# Маппинг причин отзыва (RFC 5280)
REASON_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keycompromise": x509.ReasonFlags.key_compromise,
    "cacompro mise": x509.ReasonFlags.ca_compromise,
    "affiliationchanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
    "certificatehold": x509.ReasonFlags.certificate_hold,
    "removefromcrl": x509.ReasonFlags.remove_from_crl,
    "privilegewithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aacompro mise": x509.ReasonFlags.aa_compromise,
}


def get_reason_flag(reason_str: Optional[str]) -> x509.ReasonFlags:
    if not reason_str:
        return x509.ReasonFlags.unspecified
    key = reason_str.lower().replace("_", "").replace(" ", "")
    if key == "keycompromise": return x509.ReasonFlags.key_compromise
    if key == "cacompro mise": return x509.ReasonFlags.ca_compromise  # Fix typo in map key if needed

    for k, v in REASON_MAP.items():
        if k.replace("_", "").replace(" ", "") == key:
            return v
    return x509.ReasonFlags.unspecified


def generate_crl(
        ca_cert: x509.Certificate,
        ca_key,
        revoked_certs: List[Dict[str, Any]],
        next_update_days: int = 7,
        crl_number: int = 1
) -> bytes:
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=next_update_days)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(next_update)

    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    for entry in revoked_certs:
        serial_int = int(entry['serial_hex'], 16)
        rev_date_str = entry['revocation_date']
        if rev_date_str.endswith('Z'):
            rev_date_str = rev_date_str[:-1] + '+00:00'
        try:
            rev_date = datetime.fromisoformat(rev_date_str)
        except:
            rev_date = now

        rev_date = rev_date.replace(microsecond=0)
        reason = get_reason_flag(entry.get('revocation_reason'))

        revoked_builder = x509.RevokedCertificateBuilder()
        revoked_builder = revoked_builder.serial_number(serial_int)
        revoked_builder = revoked_builder.revocation_date(rev_date)
        revoked_builder = revoked_builder.add_extension(x509.CRLReason(reason), critical=False)

        revoked_cert = revoked_builder.build(default_backend())
        builder = builder.add_revoked_certificate(revoked_cert)

    sig_algo = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    crl_obj = builder.sign(ca_key, sig_algo, default_backend())

    return crl_obj.public_bytes(serialization.Encoding.PEM)


def save_crl(crl_pem: bytes, out_path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(crl_pem)
    import os, stat
    try:
        os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except:
        pass