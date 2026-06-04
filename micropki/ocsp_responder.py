import logging
from flask import Flask, Response, request
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from . import ocsp as ocsp_module

app = Flask(__name__)

_config = {
    "db_path": "./pki/micropki.db",
    "ca_cert": None,
    "responder_cert": None,
    "responder_key": None,
    "cache_ttl": 3600,
    "logger": None
}


def load_ca_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_responder(path_cert, path_key):
    with open(path_cert, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(path_key, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return cert, key


@app.route('/', methods=['POST'])
def ocsp_endpoint():
    """Основной эндпоинт для OCSP-запросов (POST /)"""
    if request.content_type != 'application/ocsp-request':
        return Response("Invalid Content-Type", status=400, mimetype='text/plain')

    request_der = request.get_data()

    response_der = ocsp_module.process_ocsp_request(
        request_der=request_der,
        responder_cert=_config["responder_cert"],
        responder_key=_config["responder_key"],
        issuer_cert=_config["ca_cert"],
        db_path=_config["db_path"],
        logger=_config["logger"] or logging.getLogger(__name__)
    )

    return Response(response_der, mimetype='application/ocsp-response')


def run_ocsp_server(host, port, db_path, ca_cert_path, resp_cert_path, resp_key_path, cache_ttl, logger=None):
    _config["db_path"] = db_path
    _config["ca_cert"] = load_ca_cert(ca_cert_path)
    _config["responder_cert"], _config["responder_key"] = load_responder(resp_cert_path, resp_key_path)
    _config["cache_ttl"] = cache_ttl
    _config["logger"] = logger

    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    print(f"[START] OCSP Responder starting on {host}:{port}", flush=True)
    app.run(host=host, port=port, debug=False, threaded=True)