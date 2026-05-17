from flask import Flask, Response, jsonify, request
from pathlib import Path
import logging

from .database import get_certificate_by_serial

app = Flask(__name__)

_global_db_path = "./pki/micropki.db"
_global_cert_dir = "./pki/certs"
_global_logger = None


def _log_message(msg):
    if _global_logger:
        _global_logger.info(f"[HTTP] {msg}")
    else:
        print(f"[HTTP] {msg}")


@app.route('/certificate/<serial>', methods=['GET'])
def get_cert(serial):
    try:
        int(serial, 16)
    except ValueError:
        _log_message(f"400 Bad Request: Invalid serial '{serial}'")
        return Response("Invalid serial format (must be hexadecimal)", status=400, mimetype='text/plain')

    rec = get_certificate_by_serial(_global_db_path, serial)

    if rec:
        _log_message(f"200 OK: Served certificate {serial}")
        return Response(rec['cert_pem'], mimetype='application/x-pem-file')
    else:
        _log_message(f"404 Not Found: Certificate {serial}")
        return Response("Certificate not found in database", status=404, mimetype='text/plain')


@app.route('/ca/<level>', methods=['GET'])
def get_ca(level):
    if level not in ['root', 'intermediate']:
        return Response("Invalid CA level. Use 'root' or 'intermediate'", status=400, mimetype='text/plain')

    filename = "ca.cert.pem" if level == 'root' else "intermediate.cert.pem"
    file_path = Path(_global_cert_dir) / filename

    if file_path.exists():
        _log_message(f"200 OK: Served CA certificate '{level}'")
        return Response(file_path.read_text(), mimetype='application/x-pem-file')

    _log_message(f"404 Not Found: CA file '{filename}' missing")
    return Response("CA certificate file not found on disk", status=404, mimetype='text/plain')


@app.route('/crl', methods=['GET'])
def get_crl():
    _log_message("501 Not Implemented: CRL requested")
    return Response(
        "CRL generation is not yet implemented (Scheduled for Sprint 4)",
        status=501,
        mimetype='text/plain'
    )


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "service": "MicroPKI Repository API",
        "version": "0.3.0 (Sprint 3)",
        "endpoints": {
            "GET /": "This help message",
            "GET /certificate/<serial_hex>": "Retrieve certificate PEM by serial number",
            "GET /ca/root": "Retrieve Root CA certificate",
            "GET /ca/intermediate": "Retrieve Intermediate CA certificate",
            "GET /crl": "Get Certificate Revocation List (Not Implemented)"
        }
    })


def run_server(host="127.0.0.1", port=8080, db_path="./pki/micropki.db", cert_dir="./pki/certs", logger_obj=None):
    global _global_db_path, _global_cert_dir, _global_logger

    _global_db_path = db_path
    _global_cert_dir = cert_dir
    _global_logger = logger_obj

    werkzeug_log = logging.getLogger('werkzeug')
    werkzeug_log.setLevel(logging.ERROR)

    print(f" MicroPKI Repository Server starting...")
    print(f"   Binding to: http://{host}:{port}")
    print(f"   Database:   {_global_db_path}")
    print(f"   Cert Dir:   {_global_cert_dir}")
    print("-" * 40)

    app.run(host=host, port=port, debug=False, threaded=True)
