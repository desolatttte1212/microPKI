from typing import List, Tuple, Optional
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
import ipaddress


class TemplateError(Exception):
    pass


def parse_san_entry(entry: str) -> x509.GeneralName:
    if ':' not in entry:
        raise TemplateError(f"Invalid SAN format '{entry}'. Expected 'type:value'.")

    san_type, value = entry.split(':', 1)
    san_type = san_type.lower().strip()
    value = value.strip()

    if san_type == 'dns':
        return x509.DNSName(value)
    elif san_type == 'ip':
        try:
            return x509.IPAddress(ipaddress.ip_address(value))
        except ValueError:
            raise TemplateError(f"Invalid IP address in SAN: {value}")
    elif san_type == 'email':
        return x509.RFC822Name(value)
    elif san_type == 'uri':
        return x509.UniformResourceIdentifier(value)
    else:
        raise TemplateError(f"Unsupported SAN type: {san_type}")


def get_template_extensions(template_name: str, san_list: List[x509.GeneralName], key_type: str) -> List[
    x509.Extension]:
    extensions = []

    extensions.append(x509.Extension(
        ExtensionOID.BASIC_CONSTRAINTS,
        critical=True,
        value=x509.BasicConstraints(ca=False, path_length=None)
    ))

    san_ext = x509.Extension(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        critical=False,
        value=x509.SubjectAlternativeName(san_list)
    )
    extensions.append(san_ext)

    if template_name == 'server':
        ku_value = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=(key_type == 'rsa'),
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(x509.Extension(ExtensionOID.KEY_USAGE, critical=True, value=ku_value))

        extensions.append(x509.Extension(
            ExtensionOID.EXTENDED_KEY_USAGE,
            critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        ))

        if not any(isinstance(name, (x509.DNSName, x509.IPAddress)) for name in san_list):
            raise TemplateError("Server certificate must have at least one DNS or IP SAN.")

    elif template_name == 'client':
        ku_value = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(x509.Extension(ExtensionOID.KEY_USAGE, critical=True, value=ku_value))

        extensions.append(x509.Extension(
            ExtensionOID.EXTENDED_KEY_USAGE,
            critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        ))

    elif template_name == 'code_signing':
        ku_value = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(x509.Extension(ExtensionOID.KEY_USAGE, critical=True, value=ku_value))

        extensions.append(x509.Extension(
            ExtensionOID.EXTENDED_KEY_USAGE,
            critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        ))

        if any(isinstance(name, x509.IPAddress) for name in san_list):
            raise TemplateError("Code Signing certificate should not contain IP SANs.")

    else:
        raise TemplateError(f"Unknown template: {template_name}")

    return extensions