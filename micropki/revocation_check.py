import requests
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization, hashes
from .revocation import parse_reason


def get_ocsp_url(cert: x509.Certificate) -> str:
    """Извлекает URL OCSP респондера из расширения AIA"""
    try:
        aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia_ext.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def check_status_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, ocsp_url: str = None) -> dict:
    """
    Проверяет статус через внешний вызов к OCSP-респондеру.
    Возвращает {'status': 'good'|'revoked'|'unknown', ...} или None, если OCSP недоступен.
    """
    if not ocsp_url:
        ocsp_url = get_ocsp_url(cert)

    if not ocsp_url:
        return None

    try:
        from cryptography.x509 import ocsp

        # Строим запрос (совместимо с cryptography 40+)
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
        req = builder.build()

        # Отправка запроса
        headers = {'Content-Type': 'application/ocsp-request'}
        resp = requests.post(ocsp_url, data=req.public_bytes(serialization.Encoding.DER), headers=headers, timeout=5)

        if resp.status_code != 200:
            return None

        # Парсинг ответа
        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)

        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return None

        # Получаем статус из ответов
        for single_resp in ocsp_resp.responses:
            status_map = {
                ocsp.OCSPCertStatus.GOOD: 'good',
                ocsp.OCSPCertStatus.REVOKED: 'revoked',
                ocsp.OCSPCertStatus.UNKNOWN: 'unknown'
            }

            result = {
                'status': status_map.get(single_resp.certificate_status, 'unknown'),
                'source': 'ocsp'
            }

            if single_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                result['reason'] = single_resp.revocation_reason
                result['time'] = single_resp.revocation_time

            return result

        return {'status': 'unknown', 'source': 'ocsp'}

    except Exception as e:
        print(f"OCSP check failed: {e}")
        return None


def check_status_crl(cert: x509.Certificate, issuer_cert: x509.Certificate, crl_data: bytes = None) -> dict:
    """Проверяет статус через CRL."""
    if not crl_data:
        return None

    try:
        # Пробуем загрузить как PEM, потом DER
        try:
            crl_obj = x509.load_pem_x509_crl(crl_data)
        except:
            crl_obj = x509.load_der_x509_crl(crl_data)

        # Проверка подписи CRL ключом эмитента
        issuer_public_key = issuer_cert.public_key()
        crl_obj.verify_signature(issuer_public_key)

        # Поиск серийного номера
        for revoked_entry in crl_obj:
            if revoked_entry.serial_number == cert.serial_number:
                return {
                    'status': 'revoked',
                    'reason': revoked_entry.reason,
                    'time': revoked_entry.revocation_time,
                    'source': 'crl'
                }

        return {'status': 'good', 'source': 'crl'}

    except Exception as e:
        print(f"CRL check failed: {e}")
        return None


def check_revocation_status(cert: x509.Certificate, issuer_cert: x509.Certificate, ocsp_url: str = None,
                            crl_data: bytes = None) -> dict:
    """
    Основная функция проверки отзыва с логикой Fallback (OCSP first, then CRL).
    """
    # 1. Попробовать OCSP
    ocsp_result = check_status_ocsp(cert, issuer_cert, ocsp_url)
    if ocsp_result and ocsp_result['status'] in ['good', 'revoked']:
        return ocsp_result

    # 2. Fallback to CRL
    crl_result = check_status_crl(cert, issuer_cert, crl_data)
    if crl_result:
        return crl_result

    return {'status': 'unknown', 'source': 'none'}