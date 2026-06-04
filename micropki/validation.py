import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID


class ValidationError(Exception):
    def __init__(self, message, cert_idx=None):
        self.message = message
        self.cert_idx = cert_idx
        super().__init__(message)


def verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate):
    """Проверяет подпись сертификата cert ключом из issuer_cert"""
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
            raise ValidationError(f"Unsupported key type in issuer: {type(public_key)}")
    except Exception as e:
        raise ValidationError(f"Signature verification failed: {e}")


def check_validity_period(cert: x509.Certificate, validation_time: datetime.datetime = None):
    """Проверяет, действителен ли сертификат в указанное время"""
    if validation_time is None:
        validation_time = datetime.datetime.now(datetime.timezone.utc)

    if validation_time.tzinfo is None:
        validation_time = validation_time.replace(tzinfo=datetime.timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if validation_time < not_before:
        raise ValidationError(f"Certificate is not yet valid (Not Before: {not_before})")
    if validation_time > not_after:
        raise ValidationError(f"Certificate has expired (Not After: {not_after})")


def check_basic_constraints(cert: x509.Certificate, is_ca: bool):
    """Проверяет расширение Basic Constraints"""
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        bc = bc_ext.value
        if bc.ca != is_ca:
            raise ValidationError(f"Basic Constraints mismatch: expected CA={is_ca}, got CA={bc.ca}")
        return bc.path_length
    except x509.ExtensionNotFound:
        if is_ca:
            raise ValidationError("CA certificate missing Basic Constraints extension")
        return None


def _certs_match_by_subject(cert1: x509.Certificate, cert2: x509.Certificate) -> bool:
    """Сравнивает два сертификата по их Subject (байтовое сравнение)"""
    return cert1.subject.public_bytes() == cert2.subject.public_bytes()


def build_chain(leaf_cert: x509.Certificate, untrusted_certs: list, trusted_roots: list):
    """
    Строит цепочку от leaf до trusted root.
    Возвращает список сертификатов [leaf, intermediate..., root].
    """
    chain = [leaf_cert]
    current_cert = leaf_cert

    # Создаем словарь для поиска: ключ = bytes(subject), значение = сертификат
    pool = {}
    for c in untrusted_certs + trusted_roots:
        subj_bytes = c.subject.public_bytes()
        pool[subj_bytes] = c

    # Отладочная информация
    print(f"DEBUG: Building chain for leaf: {leaf_cert.subject.rfc4514_string()}")
    print(f"DEBUG: Leaf issuer: {leaf_cert.issuer.rfc4514_string()}")
    print(f"DEBUG: Available certs in pool:")
    for c in untrusted_certs + trusted_roots:
        print(f"   - Subject: {c.subject.rfc4514_string()}, Is Self-Signed: {c.subject == c.issuer}")

    max_depth = len(untrusted_certs) + len(trusted_roots) + 1

    for iteration in range(max_depth):
        issuer_name_bytes = current_cert.issuer.public_bytes()
        issuer_cert = pool.get(issuer_name_bytes)

        if not issuer_cert:
            # Детальная отладка при неудаче
            print(f"DEBUG: Could not find issuer for: {current_cert.subject.rfc4514_string()}")
            print(f"DEBUG: Looking for issuer bytes: {issuer_name_bytes.hex()[:64]}...")
            print(f"DEBUG: Available subject bytes in pool:")
            for subj_bytes in pool.keys():
                print(f"   - {subj_bytes.hex()[:64]}...")
            raise ValidationError(f"Could not find issuer for: {current_cert.subject.rfc4514_string()}")

        print(f"DEBUG: Found issuer: {issuer_cert.subject.rfc4514_string()}")

        # Проверяем, является ли найденный сертификат корневым (самоподписанным)
        if issuer_cert.subject == issuer_cert.issuer:
            print(f"DEBUG: Found self-signed cert, checking if trusted...")
            # Проверяем, есть ли этот сертификат в списке доверенных (по содержимому, не по ссылке)
            is_trusted = any(_certs_match_by_subject(issuer_cert, trusted) for trusted in trusted_roots)

            if is_trusted:
                print(f"DEBUG: Self-signed cert is trusted. Chain complete.")
                chain.append(issuer_cert)
                break
            else:
                raise ValidationError("Found self-signed certificate but it is not in the trusted store")

        # Добавляем в цепочку и продолжаем поиск
        chain.append(issuer_cert)
        current_cert = issuer_cert

    # Финальная проверка: достигли ли мы самоподписанного корня
    if chain[-1].subject != chain[-1].issuer:
        raise ValidationError("Chain building failed: did not reach a self-signed root")

    return chain


def validate_path(chain: list, validation_time: datetime.datetime = None):
    """Выполняет полную валидацию построенной цепочки."""
    for i in range(len(chain)):
        cert = chain[i]
        is_last = (i == len(chain) - 1)

        check_validity_period(cert, validation_time)

        if not is_last:
            issuer_cert = chain[i + 1]
            verify_signature(cert, issuer_cert)
            check_basic_constraints(issuer_cert, is_ca=True)

            try:
                ku_ext = issuer_cert.extensions.get_extension_for_class(x509.KeyUsage)
                if ku_ext.critical and not ku_ext.value.key_cert_sign:
                    raise ValidationError(f"Issuer {issuer_cert.subject.rfc4514_string()} does not have keyCertSign")
            except x509.ExtensionNotFound:
                pass

    return True