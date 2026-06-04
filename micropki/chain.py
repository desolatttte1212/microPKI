from __future__ import annotations
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone
from typing import List


class ChainError(Exception):
    pass


def verify_cert_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    """Проверяет подпись сертификата ключом эмитента."""
    public_key = issuer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            raise ChainError(f"Unsupported key type: {type(public_key)}")
    except Exception as e:
        raise ChainError(f"Signature verification failed: {e}")


def build_chain(
        leaf: x509.Certificate,
        untrusted: List[x509.Certificate],
        trusted: List[x509.Certificate],
) -> List[x509.Certificate]:
    """Строит цепочку сертификатов от листового до доверенного корневого."""
    chain: List[x509.Certificate] = [leaf]
    current = leaf
    used_indices = set()
    max_depth = len(untrusted) + len(trusted) + 1

    for _ in range(max_depth):
        # Если сертификат самоподписанный - это корень
        if current.issuer == current.subject:
            for t in trusted:
                if t.subject == current.subject:
                    try:
                        verify_cert_signature(current, t)
                        chain.append(t)
                        return chain
                    except ChainError:
                        continue
            raise ChainError(f"Self-signed cert not in trusted store: {current.subject.rfc4514_string()}")

        issuer_name = current.issuer
        found = False

        # Сначала ищем в доверенных корнях
        for t in trusted:
            if t.subject == issuer_name:
                try:
                    verify_cert_signature(current, t)
                    chain.append(t)
                    return chain
                except ChainError:
                    continue

        # Потом ищем в недоверенных промежуточных
        for idx, c in enumerate(untrusted):
            if idx in used_indices:
                continue
            if c.subject == issuer_name:
                try:
                    verify_cert_signature(current, c)
                    chain.append(c)
                    used_indices.add(idx)
                    current = c
                    found = True
                    break
                except ChainError:
                    continue

        if not found:
            raise ChainError(
                f"Cannot find issuer '{issuer_name.rfc4514_string()}' for cert '{current.subject.rfc4514_string()}'"
            )

    raise ChainError("Chain building failed: maximum depth exceeded or no trusted root found")


def validate_chain(chain: List[x509.Certificate], validation_time: datetime = None) -> bool:
    """Валидирует построенную цепочку: подписи, сроки, Basic Constraints, Key Usage."""
    if validation_time is None:
        validation_time = datetime.now(timezone.utc)

    for i, cert in enumerate(chain):
        # Безопасное получение времени (совместимо с разными версиями cryptography)
        not_before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=timezone.utc)

        if validation_time < not_before:
            raise ChainError(f"Certificate not yet valid: {cert.subject.rfc4514_string()}")
        if validation_time > not_after:
            raise ChainError(f"Certificate expired: {cert.subject.rfc4514_string()}")

        # Проверка подписи (кроме корневого)
        if i < len(chain) - 1:
            issuer = chain[i + 1]
            verify_cert_signature(cert, issuer)

            # Проверка Basic Constraints у эмитента
            try:
                bc_ext = issuer.extensions.get_extension_for_class(x509.BasicConstraints)
                if not bc_ext.value.ca:
                    raise ChainError(f"Issuer is not a CA: {issuer.subject.rfc4514_string()}")
            except x509.ExtensionNotFound:
                pass

            # Проверка Key Usage у эмитента (должен иметь keyCertSign)
            try:
                ku_ext = issuer.extensions.get_extension_for_class(x509.KeyUsage)
                if ku_ext.critical and not ku_ext.value.key_cert_sign:
                    raise ChainError(f"Issuer lacks keyCertSign: {issuer.subject.rfc4514_string()}")
            except x509.ExtensionNotFound:
                pass

    return True