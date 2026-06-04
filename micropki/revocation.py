from cryptography.x509 import ReasonFlags


def parse_reason(reason_str: str) -> ReasonFlags:
    """Парсит строку причины отзыва в ReasonFlags"""
    reason_map = {
        "unspecified": ReasonFlags.unspecified,
        "keycompromise": ReasonFlags.key_compromise,
        "cacompro mise": ReasonFlags.ca_compromise,
        "affiliationchanged": ReasonFlags.affiliation_changed,
        "superseded": ReasonFlags.superseded,
        "cessationofoperation": ReasonFlags.cessation_of_operation,
        "certificatehold": ReasonFlags.certificate_hold,
        "removefromcrl": ReasonFlags.remove_from_crl,
        "privilegewithdrawn": ReasonFlags.privilege_withdrawn,
        "aacompro mise": ReasonFlags.aa_compromise,
    }

    # Нормализуем строку
    normalized = reason_str.lower().replace("_", "").replace(" ", "")

    # Ищем в мапе
    for key, value in reason_map.items():
        if key.replace("_", "").replace(" ", "") == normalized:
            return value

    return ReasonFlags.unspecified