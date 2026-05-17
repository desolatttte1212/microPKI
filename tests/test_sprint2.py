import sys
import pytest
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from micropki.templates import parse_san_entry, get_template_extensions, TemplateError
from micropki.ca import generate_key_pair, parse_subject_name

class TestSanParsing:
    def test_parse_dns(self):
        entry = parse_san_entry("dns:example.com")
        assert isinstance(entry, x509.DNSName)
        assert entry.value == "example.com"

    def test_parse_ip_v4(self):
        entry = parse_san_entry("ip:192.168.1.1")
        assert isinstance(entry, x509.IPAddress)
        assert str(entry.value) == "192.168.1.1"

    def test_parse_ip_v6(self):
        entry = parse_san_entry("ip:::1")
        assert isinstance(entry, x509.IPAddress)
        assert str(entry.value) == "::1"

    def test_parse_email(self):
        entry = parse_san_entry("email:user@example.com")
        assert isinstance(entry, x509.RFC822Name)
        assert entry.value == "user@example.com"

    def test_parse_uri(self):
        entry = parse_san_entry("uri:http://example.com/app")
        assert isinstance(entry, x509.UniformResourceIdentifier)
        assert entry.value == "http://example.com/app"

    def test_parse_invalid_format(self):
        with pytest.raises(TemplateError, match="Invalid SAN format"):
            parse_san_entry("example.com")  # Нет типа

    def test_parse_invalid_type(self):
        with pytest.raises(TemplateError, match="Unsupported SAN type"):
            parse_san_entry("fax:12345")

    def test_parse_invalid_ip(self):
        with pytest.raises(TemplateError, match="Invalid IP address"):
            parse_san_entry("ip:999.999.999.999")

class TestTemplates:
    def _get_rsa_key(self):
        return generate_key_pair("rsa", 2048)

    def _get_ec_key(self):
        return generate_key_pair("ecc", 256)

    def test_server_template_basic(self):
        san_list = [parse_san_entry("dns:example.com")]
        exts = get_template_extensions("server", san_list, "rsa")

        ext_types = [e.oid._name for e in exts]
        assert "basicConstraints" in ext_types
        assert "keyUsage" in ext_types
        assert "subjectAltName" in ext_types
        assert "extendedKeyUsage" in ext_types

        eku_ext = next(e for e in exts if e.oid._name == "extendedKeyUsage")
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value

        ku_ext = next(e for e in exts if e.oid._name == "keyUsage")
        assert ku_ext.value.key_encipherment is True
        assert ku_ext.value.digital_signature is True

    def test_server_template_requires_san(self):
        with pytest.raises(TemplateError, match="must have at least one DNS or IP SAN"):
            get_template_extensions("server", [], "rsa")

    def test_client_template(self):
        san_list = [parse_san_entry("email:user@example.com")]
        exts = get_template_extensions("client", san_list, "ecc")

        eku_ext = next(e for e in exts if e.oid._name == "extendedKeyUsage")
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value

        ku_ext = next(e for e in exts if e.oid._name == "keyUsage")
        assert ku_ext.value.digital_signature is True

    def test_code_signing_template(self):
        san_list = [parse_san_entry("dns:developer.example.com")]
        exts = get_template_extensions("code_signing", san_list, "rsa")

        eku_ext = next(e for e in exts if e.oid._name == "extendedKeyUsage")
        assert ExtendedKeyUsageOID.CODE_SIGNING in eku_ext.value

    def test_code_signing_rejects_ip(self):
        san_list = [parse_san_entry("ip:1.2.3.4")]
        with pytest.raises(TemplateError, match="should not contain IP SANs"):
            get_template_extensions("code_signing", san_list, "rsa")

    def test_unknown_template(self):
        with pytest.raises(TemplateError, match="Unknown template"):
            get_template_extensions("smart_fridge", [], "rsa")

class TestIntegration:
    def test_full_server_flow_mock(self):
        key = generate_key_pair("rsa", 2048)

        sans = [
            parse_san_entry("dns:mysite.com"),
            parse_san_entry("dns:www.mysite.com"),
            parse_san_entry("ip:10.0.0.1")
        ]

        extensions = get_template_extensions("server", sans, "rsa")

        assert len(extensions) >= 4

        san_ext = next(e for e in extensions if e.oid._name == "subjectAltName")
        values = [name.value for name in san_ext.value]
        assert "mysite.com" in values
        assert "www.mysite.com" in values
        assert any(str(v) == "10.0.0.1" for v in values if hasattr(v, '__str__'))  # IP check

    def test_subject_parsing_complex(self):
        subject_str = "/CN=Test CA,O=My Org,OU=IT Dept,C=US,L=NY,ST=New York"
        name = parse_subject_name(subject_str)
        assert len(name) == 6
        attrs = {attr.oid._name: attr.value for attr in name}
        assert attrs['commonName'] == "Test CA"
        assert attrs['countryName'] == "US"