from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class TemplateError(Exception):
    pass


def parse_san_entry(entry_str):
    """Парсит строку вида dns:example.com или ip:1.2.3.4"""
    if entry_str.startswith("dns:"):
        return x509.DNSName(entry_str[4:])
    elif entry_str.startswith("ip:"):
        import ipaddress
        return x509.IPAddress(ipaddress.ip_address(entry_str[3:]))
    elif entry_str.startswith("email:"):
        return x509.RFC822Name(entry_str[6:])
    elif entry_str.startswith("uri:"):
        return x509.UniformResourceIdentifier(entry_str[4:])
    else:
        raise ValueError(f"Unsupported SAN type: {entry_str}")


def get_template_extensions(template_name: str, san_list, key_type: str):
    extensions = []

    # Basic Constraints: CA=FALSE для всех end-entity
    extensions.append(x509.Extension(
        ExtensionOID.BASIC_CONSTRAINTS, critical=True, value=x509.BasicConstraints(ca=False, path_length=None)
    ))

    # Key Usage
    if template_name == 'server':
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        )
        extensions.append(x509.Extension(ExtensionOID.KEY_USAGE, critical=True, value=ku))
        extensions.append(x509.Extension(
            ExtensionOID.EXTENDED_KEY_USAGE, critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        ))

    elif template_name == 'client':
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        )
        extensions.append(x509.Extension(ExtensionOID.KEY_USAGE, critical=True, value=ku))
        extensions.append(x509.Extension(
            ExtensionOID.EXTENDED_KEY_USAGE, critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        ))

    elif template_name == 'code_signing':
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        )
        extensions.append(x509.Extension(ExtensionOID.KEY_USAGE, critical=True, value=ku))
        extensions.append(x509.Extension(
            ExtensionOID.EXTENDED_KEY_USAGE, critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        ))
    else:
        raise TemplateError(f"Unknown template: {template_name}")

    # Обработка SAN
    if template_name == 'server':
        # Проверяем, является ли san_list объектом SAN (из CSR) или списком строк
        if isinstance(san_list, x509.SubjectAlternativeName):
            # Если это объект из CSR, проверяем, есть ли там DNS или IP
            has_dns_ip = any(isinstance(name, (x509.DNSName, x509.IPAddress)) for name in san_list)
            if not has_dns_ip:
                raise TemplateError("Server certificate must have at least one DNS or IP SAN.")
            extensions.append(x509.Extension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=False, value=san_list))
        else:
            # Если это список строк (из CLI), парсим как раньше
            parsed_sans = []
            for san in san_list:
                if isinstance(san, str):
                    parsed_sans.append(parse_san_entry(san))
                else:
                    parsed_sans.append(san)

            if not parsed_sans:
                raise TemplateError("Server certificate must have at least one DNS or IP SAN.")

            # Проверка на наличие DNS/IP
            has_dns_ip = any(isinstance(name, (x509.DNSName, x509.IPAddress)) for name in parsed_sans)
            if not has_dns_ip:
                raise TemplateError("Server certificate must have at least one DNS or IP SAN.")

            extensions.append(x509.Extension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                critical=False,
                value=x509.SubjectAlternativeName(parsed_sans)
            ))

    return extensions