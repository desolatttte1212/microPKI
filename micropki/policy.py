from __future__ import annotations
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

# Политики по умолчанию (могут быть переопределены через config)
DEFAULT_POLICIES = {
    "key_size": {
        "rsa": {
            "root_ca": {"min": 4096},
            "intermediate_ca": {"min": 2048},
            "end_entity": {"min": 2048}
        },
        "ecc": {
            "root_ca": {"min_curve": "secp384r1"},
            "intermediate_ca": {"min_curve": "secp384r1"},
            "end_entity": {"min_curve": "secp256r1"}
        }
    },
    "validity": {
        "root_ca": {"max_days": 3650},
        "intermediate_ca": {"max_days": 1825},
        "end_entity": {"max_days": 365}
    },
    "san": {
        "server": {"allowed_types": ["dns", "ip"], "allow_wildcard": False},
        "client": {"allowed_types": ["email", "dns"], "require_email": True},
        "code_signing": {"allowed_types": ["dns", "uri"], "forbidden_types": ["email", "ip"]}
    },
    "algorithms": {
        "rsa": {"min_hash": "sha256", "forbidden": ["sha1"]},
        "ecc": {"p256_hash": "sha256", "p384_hash": "sha384"}
    },
    "path_length": {
        "intermediate_ca": {"max": 0}
    }
}


class PolicyError(Exception):
    """Исключение при нарушении политики."""
    pass


def check_key_size(key, cert_type: str, key_type: str, policies: dict = None) -> None:
    """Проверяет размер ключа согласно политикам."""
    policies = policies or DEFAULT_POLICIES
    key_policies = policies["key_size"].get(key_type, {})

    if key_type == "rsa":
        if not isinstance(key, rsa.RSAPrivateKey):
            raise PolicyError(f"Expected RSA key, got {type(key)}")
        min_size = key_policies.get(cert_type, {}).get("min", 2048)
        if key.key_size < min_size:
            raise PolicyError(f"RSA key size {key.key_size} < {min_size} bits for {cert_type}")

    elif key_type == "ecc":
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise PolicyError(f"Expected ECC key, got {type(key)}")
        min_curve_name = key_policies.get(cert_type, {}).get("min_curve", "secp256r1")
        actual_curve = key.curve.name
        curve_order = {"secp256r1": 256, "secp384r1": 384, "secp521r1": 521}
        if curve_order.get(actual_curve, 0) < curve_order.get(min_curve_name, 256):
            raise PolicyError(f"ECC curve {actual_curve} < {min_curve_name} for {cert_type}")


def check_validity_period(validity_days: int, cert_type: str, policies: dict = None) -> None:
    """Проверяет период действия сертификата."""
    policies = policies or DEFAULT_POLICIES
    max_days = policies["validity"].get(cert_type, {}).get("max_days", 365)
    if validity_days > max_days:
        raise PolicyError(f"Validity {validity_days} days > max {max_days} days for {cert_type}")


def check_san_policy(san_list: list, template: str, policies: dict = None) -> None:
    """Проверяет SAN согласно шаблону."""
    policies = policies or DEFAULT_POLICIES
    san_policy = policies["san"].get(template, {})
    allowed = san_policy.get("allowed_types", [])
    forbidden = san_policy.get("forbidden_types", [])
    allow_wildcard = san_policy.get("allow_wildcard", False)

    for san in san_list:
        san_type = None
        san_value = None

        if isinstance(san, x509.DNSName):
            san_type = "dns"
            san_value = san.value
        elif isinstance(san, x509.IPAddress):
            san_type = "ip"
            san_value = str(san.value)
        elif isinstance(san, x509.RFC822Name):
            san_type = "email"
            san_value = san.value
        elif isinstance(san, x509.UniformResourceIdentifier):
            san_type = "uri"
            san_value = san.value

        if san_type:
            if san_type in forbidden:
                raise PolicyError(f"SAN type '{san_type}' forbidden for template '{template}'")
            if allowed and san_type not in allowed:
                raise PolicyError(f"SAN type '{san_type}' not allowed for template '{template}'")
            if san_type == "dns" and san_value and san_value.startswith("*."):
                if not allow_wildcard:
                    raise PolicyError(f"Wildcard SAN '{san_value}' not allowed by policy")


def check_signature_algorithm(cert_or_csr, key_type: str, policies: dict = None) -> None:
    """Проверяет алгоритм подписи."""
    policies = policies or DEFAULT_POLICIES
    algo = cert_or_csr.signature_algorithm_oid._name if hasattr(cert_or_csr.signature_algorithm_oid, '_name') else str(
        cert_or_csr.signature_algorithm_oid)

    if key_type == "rsa":
        rsa_policies = policies["algorithms"]["rsa"]
        if any(forbidden in algo.lower() for forbidden in rsa_policies.get("forbidden", [])):
            raise PolicyError(f"Signature algorithm '{algo}' forbidden for RSA")
        if rsa_policies["min_hash"] not in algo.lower():
            # Разрешаем более сильные хеши
            if "sha256" not in algo.lower() and "sha384" not in algo.lower() and "sha512" not in algo.lower():
                raise PolicyError(f"Signature algorithm '{algo}' weaker than {rsa_policies['min_hash']}")


def check_path_length(pathlen: Optional[int], cert_type: str, policies: dict = None) -> None:
    """Проверяет ограничение длины пути."""
    if cert_type != "intermediate_ca":
        return
    policies = policies or DEFAULT_POLICIES
    max_pathlen = policies["path_length"].get(cert_type, {}).get("max", 0)
    if pathlen is not None and pathlen > max_pathlen:
        raise PolicyError(f"pathLenConstraint {pathlen} > max {max_pathlen} for intermediate CA")