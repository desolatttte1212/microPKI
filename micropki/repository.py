from __future__ import annotations
from flask import Flask, Response, jsonify, request
from pathlib import Path
import logging
import sqlite3
import time
from typing import Optional, Dict, Any, List
from .ratelimit import RateLimiter

app = Flask(__name__)

_global_db_path = "./pki/micropki.db"
_global_cert_dir = "./pki/certs"
_global_logger = None
_rate_limiter: Optional[RateLimiter] = None


def _log_message(msg):
    if _global_logger:
        _global_logger.info(f"[HTTP] {msg}")
    else:
        print(f"[HTTP] {msg}")


def _check_rate_limit(client_ip: str) -> tuple[bool, float]:
    """Проверяет rate limit, возвращает (allowed, retry_after_seconds)."""
    global _rate_limiter
    if not _rate_limiter or _rate_limiter.rate <= 0:
        return True, 0.0
    return _rate_limiter.allow(client_ip)


def _rate_limit_response(retry_after: float) -> Response:
    """Создает ответ 429 Too Many Requests."""
    resp = Response("Too Many Requests", status=429, mimetype='text/plain')
    resp.headers['Retry-After'] = str(int(retry_after) + 1)
    return resp


def get_certificate_by_serial(serial_number: int, db_path: str) -> Optional[Dict[str, Any]]:
    """Получает сертификат по серийному номеру (int) из БД."""
    from .database import get_db_path

    db_file = get_db_path(db_path)
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    serial_hex = f"{serial_number:X}"

    cursor.execute(
        "SELECT * FROM certificates WHERE serial_hex = ?",
        (serial_hex.lower(),)
    )
    row = cursor.fetchone()
    conn.close()

    return dict(row) if row else None


@app.route('/certificate/<serial>', methods=['GET'])
def get_cert(serial):
    client_ip = request.remote_addr or "127.0.0.1"
    allowed, retry_after = _check_rate_limit(client_ip)
    if not allowed:
        _log_message(f"429 Rate limited: {client_ip}")
        return _rate_limit_response(retry_after)

    try:
        int(serial, 16)
    except ValueError:
        _log_message(f"400 Bad Request: Invalid serial '{serial}'")
        return Response("Invalid serial format", status=400, mimetype='text/plain')

    from .database import get_certificate_by_serial as db_get_cert
    rec = db_get_cert(_global_db_path, serial)
    if rec:
        _log_message(f"200 OK: Served cert {serial}")
        return Response(rec['cert_pem'], mimetype='application/x-pem-file')
    _log_message(f"404 Not Found: Cert {serial}")
    return Response("Certificate not found", status=404, mimetype='text/plain')


@app.route('/ca/<level>', methods=['GET'])
def get_ca(level):
    client_ip = request.remote_addr or "127.0.0.1"
    allowed, retry_after = _check_rate_limit(client_ip)
    if not allowed:
        return _rate_limit_response(retry_after)

    if level not in ['root', 'intermediate']:
        return Response("Invalid CA level", status=400, mimetype='text/plain')
    filename = "ca.cert.pem" if level == 'root' else "intermediate.cert.pem"
    file_path = Path(_global_cert_dir) / filename
    if file_path.exists():
        _log_message(f"200 OK: Served CA {level}")
        return Response(file_path.read_text(), mimetype='application/x-pem-file')
    _log_message(f"404 Not Found: CA {level}")
    return Response("CA certificate not found", status=404, mimetype='text/plain')


@app.route('/crl', methods=['GET'])
def get_crl():
    client_ip = request.remote_addr or "127.0.0.1"
    allowed, retry_after = _check_rate_limit(client_ip)
    if not allowed:
        return _rate_limit_response(retry_after)

    ca_type = request.args.get('ca', 'intermediate').lower()
    if ca_type not in ['root', 'intermediate']:
        return Response("Invalid CA type", status=400, mimetype='text/plain')
    filename = f"{ca_type}.crl.pem"
    file_path = Path(_global_cert_dir).parent / "crl" / filename
    if not file_path.exists():
        file_path = Path(_global_cert_dir) / filename
    if file_path.exists():
        content = file_path.read_bytes()
        _log_message(f"200 OK: Served CRL ({ca_type})")
        resp = Response(content, mimetype='application/pkix-crl')
        resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return resp
    _log_message(f"404 Not Found: CRL ({ca_type})")
    return Response("CRL not found.", status=404, mimetype='text/plain')


@app.route('/request-cert', methods=['POST'])
def request_cert_api():
    client_ip = request.remote_addr or "127.0.0.1"
    allowed, retry_after = _check_rate_limit(client_ip)
    if not allowed:
        return _rate_limit_response(retry_after)

    csr_pem = request.get_data()
    template = request.args.get('template', 'server')

    if not csr_pem:
        return Response("Missing CSR body", status=400)
    if not template:
        return Response("Missing template parameter", status=400)

    import tempfile, os
    tmp_csr_fd, tmp_csr_path = tempfile.mkstemp(suffix='.csr')
    try:
        with os.fdopen(tmp_csr_fd, 'wb') as tmp:
            tmp.write(csr_pem)

        base_dir = Path(__file__).resolve().parent.parent
        pki_dir = base_dir / "pki"
        secrets_dir = base_dir / "secrets"

        ca_cert_path = pki_dir / "certs" / "intermediate.cert.pem"
        ca_key_path = pki_dir / "private" / "intermediate.key.pem"

        pass_file_candidates = [
            secrets_dir / "int.pass",
            pki_dir / "secrets" / "int.pass",
            secrets_dir / "intermediate.pass",
            pki_dir / "secrets" / "intermediate.pass"
        ]

        ca_pass_file = None
        for candidate in pass_file_candidates:
            if candidate.exists():
                ca_pass_file = str(candidate)
                break

        if not ca_pass_file:
            raise FileNotFoundError("Could not find Intermediate CA passphrase file.")
        if not ca_cert_path.exists():
            raise FileNotFoundError(f"Intermediate CA cert not found at: {ca_cert_path}")
        if not ca_key_path.exists():
            raise FileNotFoundError(f"Intermediate CA key not found at: {ca_key_path}")

        api_out_dir = pki_dir / "api_issued"
        api_out_dir.mkdir(parents=True, exist_ok=True)

        class FakeArgs:
            def __init__(self):
                self.ca_cert = str(ca_cert_path)
                self.ca_key = str(ca_key_path)
                self.ca_pass_file = ca_pass_file
                self.template = template
                self.csr = tmp_csr_path
                self.san = []
                self.out_dir = str(api_out_dir)
                self.validity_days = 365
                self.db_path = str(pki_dir / "micropki.db")
                self.subject = None
                # Для аудита
                self.audit_logger = _global_logger

        fake_args = FakeArgs()
        logger = _global_logger or logging.getLogger(__name__)

        from .ca import issue_end_entity_cert
        cert_pem = issue_end_entity_cert(fake_args, logger)

        return Response(cert_pem, status=201, mimetype='application/x-pem-file')

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        _log_message(f"Error issuing cert via API: {e}\n{error_trace}")
        return Response(f"Internal Server Error: {str(e)}", status=500)
    finally:
        try:
            if os.path.exists(tmp_csr_path):
                os.unlink(tmp_csr_path)
        except:
            pass


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "service": "MicroPKI Repository API (Sprint 7)",
        "endpoints": ["/certificate/<serial>", "/ca/root", "/ca/intermediate", "/crl", "/request-cert"],
        "security": {
            "rate_limiting": "enabled" if _rate_limiter and _rate_limiter.rate > 0 else "disabled",
            "audit_logging": "enabled"
        }
    })


def run_server(host="127.0.0.1", port=8080, db_path="./pki/micropki.db",
               cert_dir="./pki/certs", logger_obj=None, rate_limit: float = 0.0, rate_burst: int = 10):
    global _global_db_path, _global_cert_dir, _global_logger, _rate_limiter
    _global_db_path = db_path
    _global_cert_dir = cert_dir
    _global_logger = logger_obj

    if rate_limit > 0:
        _rate_limiter = RateLimiter(rate=rate_limit, burst=rate_burst)
        if logger_obj:
            logger_obj.info(f"Rate limiting enabled: {rate_limit} req/s, burst {rate_burst}")
        print(f"[RATE LIMIT] Enabled: {rate_limit} req/s, burst {rate_burst}", flush=True)

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    print(f"[START] MicroPKI Repository Server starting...", flush=True)
    print(f"   Binding to: http://{host}:{port}", flush=True)
    print(f"   DB Path:    {_global_db_path}", flush=True)
    print(f"   Cert Dir:   {_global_cert_dir}", flush=True)
    if _rate_limiter and _rate_limiter.rate > 0:
        print(f"   Rate Limit: {rate_limit} req/s, burst {rate_burst}", flush=True)

    app.run(host=host, port=port, debug=False, threaded=True)