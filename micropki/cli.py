import argparse
import sys
from pathlib import Path

from .logger import setup_logger
from .crypto_utils import read_passphrase_from_file
from .database import init_db, list_certificates, get_certificate_by_serial
from tabulate import tabulate


VALID_REASONS = [
    "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL",
    "privilegeWithdrawn", "aACompromise"
]


def parse_args():
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI (Sprint 6)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # === CA Команды ===
    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_subparsers = ca_parser.add_subparsers(dest="subcommand", required=True)

    # init
    init_p = ca_subparsers.add_parser("init", help="Init Root CA")
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, default=None)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--log-file", default=None)
    init_p.add_argument("--db-path", default="./pki/micropki.db")

    # issue-intermediate
    int_p = ca_subparsers.add_parser("issue-intermediate", help="Issue Intermediate CA")
    int_p.add_argument("--root-cert", required=True)
    int_p.add_argument("--root-key", required=True)
    int_p.add_argument("--root-pass-file", required=True)
    int_p.add_argument("--subject", required=True)
    int_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    int_p.add_argument("--key-size", type=int, default=None)
    int_p.add_argument("--passphrase-file", required=True)
    int_p.add_argument("--out-dir", default="./pki")
    int_p.add_argument("--validity-days", type=int, default=1825)
    int_p.add_argument("--pathlen", type=int, default=0)
    int_p.add_argument("--log-file", default=None)
    int_p.add_argument("--db-path", default="./pki/micropki.db")

    # issue-cert
    cert_p = ca_subparsers.add_parser("issue-cert", help="Issue Leaf Cert")
    cert_p.add_argument("--ca-cert", required=True)
    cert_p.add_argument("--ca-key", required=True)
    cert_p.add_argument("--ca-pass-file", required=True)
    cert_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    cert_p.add_argument("--subject", required=False)
    cert_p.add_argument("--san", action="append", default=[])
    cert_p.add_argument("--out-dir", default="./pki/certs")
    cert_p.add_argument("--validity-days", type=int, default=365)
    cert_p.add_argument("--csr", default=None)
    cert_p.add_argument("--log-file", default=None)
    cert_p.add_argument("--db-path", default="./pki/micropki.db")

    # list-certs
    list_p = ca_subparsers.add_parser("list-certs", help="List certificates from DB")
    list_p.add_argument("--db-path", default="./pki/micropki.db")
    list_p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    list_p.add_argument("--format", choices=["table", "json", "csv"], default="table")

    # show-cert
    show_p = ca_subparsers.add_parser("show-cert", help="Show cert PEM by serial")
    show_p.add_argument("serial", help="Serial number (hex)")
    show_p.add_argument("--db-path", default="./pki/micropki.db")

    # revoke (Sprint 4)
    revoke_p = ca_subparsers.add_parser("revoke", help="Revoke a certificate by serial")
    revoke_p.add_argument("serial", help="Serial number (hex)")
    revoke_p.add_argument("--reason", choices=VALID_REASONS, default="unspecified")
    revoke_p.add_argument("--force", action="store_true", help="Skip confirmation")
    revoke_p.add_argument("--db-path", default="./pki/micropki.db")
    revoke_p.add_argument("--log-file", default=None)

    # gen-crl (Sprint 4)
    crl_p = ca_subparsers.add_parser("gen-crl", help="Generate CRL file")
    crl_p.add_argument("--ca", required=True, choices=["root", "intermediate"])
    crl_p.add_argument("--next-update", type=int, default=7)
    crl_p.add_argument("--out-file", help="Output file path")
    crl_p.add_argument("--db-path", default="./pki/micropki.db")
    crl_p.add_argument("--out-dir", default="./pki")
    crl_p.add_argument("--root-pass-file")
    crl_p.add_argument("--ca-pass-file")
    crl_p.add_argument("--log-file", default=None)

    # issue-ocsp-cert (Sprint 5)
    ocsp_cert_p = ca_subparsers.add_parser("issue-ocsp-cert", help="Issue OCSP Responder Certificate")
    ocsp_cert_p.add_argument("--ca-cert", required=True)
    ocsp_cert_p.add_argument("--ca-key", required=True)
    ocsp_cert_p.add_argument("--ca-pass-file", required=True)
    ocsp_cert_p.add_argument("--subject", required=True)
    ocsp_cert_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ocsp_cert_p.add_argument("--key-size", type=int, default=2048)
    ocsp_cert_p.add_argument("--san", action="append", default=[], help="SAN (dns:..., uri:...)")
    ocsp_cert_p.add_argument("--out-dir", default="./pki/certs")
    ocsp_cert_p.add_argument("--validity-days", type=int, default=365)
    ocsp_cert_p.add_argument("--db-path", default="./pki/micropki.db")
    ocsp_cert_p.add_argument("--log-file", default=None)

    # === DB Команды ===
    db_parser = subparsers.add_parser("db", help="Database operations")
    db_subparsers = db_parser.add_subparsers(dest="subcommand", required=True)
    db_init_p = db_subparsers.add_parser("init", help="Initialize DB schema")
    db_init_p.add_argument("--db-path", default="./pki/micropki.db")

    # === REPO Команды ===
    repo_parser = subparsers.add_parser("repo", help="Repository operations")
    repo_subparsers = repo_parser.add_subparsers(dest="subcommand", required=True)
    repo_serve_p = repo_subparsers.add_parser("serve", help="Start HTTP server")
    repo_serve_p.add_argument("--host", default="127.0.0.1")
    repo_serve_p.add_argument("--port", type=int, default=8080)
    repo_serve_p.add_argument("--db-path", default="./pki/micropki.db")
    repo_serve_p.add_argument("--cert-dir", default="./pki/certs")
    repo_serve_p.add_argument("--log-file", default=None)
    # В секции repo_serve_p добавь:
    repo_serve_p.add_argument("--rate-limit", type=float, default=0.0,
                              help="Rate limit (requests per second, 0=disabled)")
    repo_serve_p.add_argument("--rate-burst", type=int, default=10, help="Rate limit burst allowance")
    # === OCSP Команды (Sprint 5) ===
    ocsp_parser = subparsers.add_parser("ocsp", help="OCSP Responder operations")
    ocsp_subparsers = ocsp_parser.add_subparsers(dest="subcommand", required=True)
    ocsp_serve_p = ocsp_subparsers.add_parser("serve", help="Start OCSP Responder")
    ocsp_serve_p.add_argument("--host", default="127.0.0.1")
    ocsp_serve_p.add_argument("--port", type=int, default=8081)
    ocsp_serve_p.add_argument("--db-path", default="./pki/micropki.db")
    ocsp_serve_p.add_argument("--responder-cert", required=True)
    ocsp_serve_p.add_argument("--responder-key", required=True)
    ocsp_serve_p.add_argument("--ca-cert", required=True)
    ocsp_serve_p.add_argument("--cache-ttl", type=int, default=60)
    ocsp_serve_p.add_argument("--log-file", default=None)

    # === CLIENT Команды (Sprint 6) ===
    client_parser = subparsers.add_parser("client", help="Client-side tools")
    client_subparsers = client_parser.add_subparsers(dest="subcommand", required=True)

    # gen-csr
    gen_csr_p = client_subparsers.add_parser("gen-csr", help="Generate private key and CSR")
    gen_csr_p.add_argument("--subject", required=True)
    gen_csr_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    gen_csr_p.add_argument("--key-size", type=int, default=2048)
    gen_csr_p.add_argument("--san", action="append", default=[])
    gen_csr_p.add_argument("--out-key", default="./key.pem")
    gen_csr_p.add_argument("--out-csr", default="./request.csr.pem")
    gen_csr_p.add_argument("--log-file", default=None)

    # request-cert
    req_cert_p = client_subparsers.add_parser("request-cert", help="Submit CSR and get certificate")
    req_cert_p.add_argument("--csr", required=True)
    req_cert_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    req_cert_p.add_argument("--ca-url", required=True)
    req_cert_p.add_argument("--out-cert", default="./cert.pem")
    req_cert_p.add_argument("--log-file", default=None)

    # validate
    val_p = client_subparsers.add_parser("validate", help="Validate certificate chain")
    val_p.add_argument("--cert", required=True)
    val_p.add_argument("--untrusted", help="Intermediate cert(s)")
    val_p.add_argument("--trusted", default="./pki/certs/ca.cert.pem")
    val_p.add_argument("--crl", help="CRL file or URL")
    val_p.add_argument("--ocsp-url", help="Override OCSP URL")
    val_p.add_argument("--mode", choices=["chain", "full"], default="full")
    val_p.add_argument("--log-file", default=None)

    # check-status
    check_p = client_subparsers.add_parser("check-status", help="Check revocation status")
    check_p.add_argument("--cert", required=True)
    check_p.add_argument("--ca-cert", required=True)
    check_p.add_argument("--crl", help="CRL file")
    check_p.add_argument("--ocsp-url", help="Override OCSP URL")
    check_p.add_argument("--log-file", default=None)

    # === AUDIT Команды ===
    audit_parser = subparsers.add_parser("audit", help="Audit log operations")
    audit_subparsers = audit_parser.add_subparsers(dest="subcommand", required=True)

    # audit query
    query_p = audit_subparsers.add_parser("query", help="Query audit logs")
    query_p.add_argument("--from", dest="from_time", help="Start timestamp (ISO 8601)")
    query_p.add_argument("--to", dest="to_time", help="End timestamp")
    query_p.add_argument("--level", choices=["INFO", "WARNING", "ERROR", "AUDIT"])
    query_p.add_argument("--operation", help="Filter by operation type")
    query_p.add_argument("--serial", help="Filter by certificate serial")
    query_p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    query_p.add_argument("--verify", action="store_true", help="Verify hash chain integrity")
    query_p.add_argument("--log-file", default="./pki/audit/audit.log")

    # audit verify
    verify_p = audit_subparsers.add_parser("verify", help="Verify audit log integrity")
    verify_p.add_argument("--log-file", default="./pki/audit/audit.log")
    verify_p.add_argument("--chain-file", default="./pki/audit/chain.dat")

    # audit ct-verify
    ct_p = audit_subparsers.add_parser("ct-verify", help="Check CT log inclusion")
    ct_p.add_argument("--serial", required=True, help="Certificate serial (hex)")
    ct_p.add_argument("--ct-log", default="./pki/audit/ct.log")

    # === CA compromise ===
    compromise_p = ca_subparsers.add_parser("compromise", help="Simulate key compromise")
    compromise_p.add_argument("--cert", required=True, help="Path to certificate PEM")
    compromise_p.add_argument("--reason", choices=VALID_REASONS, default="keyCompromise")
    compromise_p.add_argument("--force", action="store_true", help="Skip confirmation")
    compromise_p.add_argument("--db-path", default="./pki/micropki.db")
    compromise_p.add_argument("--audit-log", default="./pki/audit/audit.log")
    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logger(args.log_file if hasattr(args, 'log_file') else None)
    logger.info(f"Command: {args.command} {args.subcommand}")

    try:
        if args.command == "db":
            if args.subcommand == "init":
                from .database import init_db
                init_db(args.db_path)
                logger.info(f"Database initialized at {args.db_path}")
                print(f"[OK] Database initialized: {args.db_path}")

        elif args.command == "ca":
            if args.subcommand == "init":
                from .ca import initialize_ca
                initialize_ca(args, logger)
            elif args.subcommand == "issue-intermediate":
                from .ca import create_intermediate_ca
                create_intermediate_ca(args, logger)
            elif args.subcommand == "issue-cert":
                from .ca import issue_end_entity_cert
                if not args.csr and not args.subject:
                    logger.error("Either --csr or --subject must be provided")
                    sys.exit(1)
                if args.template == 'server' and not args.san and not args.csr:
                    logger.error("Server certificate requires at least one SAN (--san) or CSR with SANs.")
                    sys.exit(1)
                issue_end_entity_cert(args, logger)
            elif args.subcommand == "list-certs":
                from .database import list_certificates
                certs = list_certificates(args.db_path, status_filter=args.status)
                if not certs:
                    print("No certificates found.")
                    return
                if args.format == "json":
                    import json
                    print(json.dumps(certs, indent=2))
                elif args.format == "csv":
                    if certs:
                        keys = certs[0].keys()
                        print(",".join(keys))
                        for c in certs: print(",".join(str(c[k]) for k in keys))
                else:
                    headers = ["Serial", "Subject", "Status", "Not After"]
                    rows = [[c['serial_hex'], c['subject'], c['status'], c['not_after']] for c in certs]
                    print(tabulate(rows, headers=headers, tablefmt="grid"))
            elif args.subcommand == "show-cert":
                from .database import get_certificate_by_serial
                rec = get_certificate_by_serial(args.db_path, args.serial)
                if rec:
                    print(rec['cert_pem'])
                else:
                    logger.error(f"Certificate {args.serial} not found in database.")
                    sys.exit(1)
            elif args.subcommand == "revoke":
                from .ca import revoke_certificate
                revoke_certificate(args, logger)
            elif args.subcommand == "gen-crl":
                from .ca import generate_crl_cli
                generate_crl_cli(args, logger)
            elif args.subcommand == "issue-ocsp-cert":
                from .ca import issue_ocsp_cert
                issue_ocsp_cert(args, logger)
            # === Sprint 7: CA compromise ===
            elif args.subcommand == "compromise":
                from .compromise import mark_compromised
                from .audit import AuditLogger
                from cryptography import x509

                with open(args.cert, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                serial_hex = f"{cert.serial_number:X}"

                if not args.force:
                    confirm = input(f"Really mark certificate {serial_hex} as compromised? [y/N]: ")
                    if confirm.lower() != 'y':
                        print("Aborted")
                        sys.exit(0)

                audit_log = getattr(args, 'audit_log', "./pki/audit/audit.log")
                auditor = AuditLogger(audit_log)
                mark_compromised(args.db_path, serial_hex, args.reason, auditor)
                print(f"✓ Certificate {serial_hex} marked as compromised ({args.reason})")

        elif args.command == "repo":
            if args.subcommand == "serve":
                from .repository import run_server
                logger.info(f"Starting repository server on {args.host}:{args.port}")
                # Sprint 7: Rate limiting flags
                rate_limit = getattr(args, 'rate_limit', 0.0)
                rate_burst = getattr(args, 'rate_burst', 10)
                run_server(
                    host=args.host, port=args.port,
                    db_path=args.db_path, cert_dir=args.cert_dir,
                    logger_obj=logger, rate_limit=rate_limit, rate_burst=rate_burst
                )

        elif args.command == "ocsp":
            if args.subcommand == "serve":
                from .ocsp_responder import run_ocsp_server
                run_ocsp_server(
                    host=args.host, port=args.port,
                    db_path=args.db_path,
                    ca_cert_path=args.ca_cert,
                    resp_cert_path=args.responder_cert,
                    resp_key_path=args.responder_key,
                    cache_ttl=args.cache_ttl,
                    logger=logger
                )

        elif args.command == "client":
            if args.subcommand == "gen-csr":
                from .client_tools import gen_csr
                gen_csr(args, logger)
            elif args.subcommand == "request-cert":
                from .client_tools import request_cert
                request_cert(args, logger)
            elif args.subcommand == "validate":
                from .chain import build_chain, validate_chain, ChainError
                from cryptography import x509

                with open(args.cert, 'rb') as f:
                    leaf_cert = x509.load_pem_x509_certificate(f.read())

                trusted_roots = []
                with open(args.trusted, 'rb') as f:
                    pem_data = f.read()
                    for pem in pem_data.split(b'-----END CERTIFICATE-----'):
                        if b'-----BEGIN CERTIFICATE-----' in pem:
                            pem += b'-----END CERTIFICATE-----'
                            trusted_roots.append(x509.load_pem_x509_certificate(pem))

                untrusted = []
                if args.untrusted:
                    with open(args.untrusted, 'rb') as f:
                        pem_data = f.read()
                        for pem in pem_data.split(b'-----END CERTIFICATE-----'):
                            if b'-----BEGIN CERTIFICATE-----' in pem:
                                pem += b'-----END CERTIFICATE-----'
                                untrusted.append(x509.load_pem_x509_certificate(pem))

                try:
                    chain = build_chain(leaf_cert, untrusted, trusted_roots)
                    logger.info("Chain built successfully.")

                    validate_chain(chain)
                    logger.info("Path validation PASSED (Signatures & Validity).")

                    if args.mode == 'full':
                        from .revocation_check import check_revocation_status
                        issuer_cert = chain[1] if len(chain) > 1 else trusted_roots[0]

                        crl_data = None
                        if args.crl:
                            if args.crl.startswith('http'):
                                import requests
                                crl_data = requests.get(args.crl).content
                            else:
                                with open(args.crl, 'rb') as f:
                                    crl_data = f.read()

                        rev_status = check_revocation_status(leaf_cert, issuer_cert, ocsp_url=args.ocsp_url,
                                                             crl_data=crl_data)
                        logger.info(f"Revocation Status: {rev_status['status']} (Source: {rev_status['source']})")

                        if rev_status['status'] == 'revoked':
                            logger.error("Validation FAILED: Certificate is REVOKED")
                            sys.exit(1)

                    logger.info("Validation SUCCESSFUL")

                except ChainError as e:
                    logger.error(f"Validation FAILED: {e}")
                    sys.exit(1)
                except Exception as e:
                    logger.error(f"Validation Error: {e}")
                    sys.exit(1)

            elif args.subcommand == "check-status":
                from .revocation_check import check_revocation_status
                from cryptography import x509

                with open(args.cert, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                with open(args.ca_cert, 'rb') as f:
                    issuer = x509.load_pem_x509_certificate(f.read())

                crl_data = None
                if args.crl:
                    if args.crl.startswith('http'):
                        import requests
                        crl_data = requests.get(args.crl).content
                    else:
                        with open(args.crl, 'rb') as f:
                            crl_data = f.read()

                result = check_revocation_status(cert, issuer, ocsp_url=args.ocsp_url, crl_data=crl_data)
                logger.info(f"Status: {result['status']}")
                if result['status'] == 'revoked':
                    logger.info(f"Reason: {result.get('reason')}")
                    logger.info(f"Time: {result.get('time')}")

        # === Sprint 7: Audit commands ===
        elif args.command == "audit":
            from .audit import AuditLogger
            from .transparency import CTLog

            if args.subcommand == "query":
                import json, csv

                log_file = Path(getattr(args, 'log_file', "./pki/audit/audit.log"))
                if not log_file.exists():
                    print(f"Audit log not found: {log_file}")
                    sys.exit(1)

                entries = []
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entry = json.loads(line)
                            # Фильтрация
                            if hasattr(args, 'from_time') and args.from_time and entry['timestamp'] < args.from_time:
                                continue
                            if hasattr(args, 'to_time') and args.to_time and entry['timestamp'] > args.to_time:
                                continue
                            if hasattr(args, 'level') and args.level and entry['level'] != args.level:
                                continue
                            if hasattr(args, 'operation') and args.operation and entry['operation'] != args.operation:
                                continue
                            if hasattr(args, 'serial') and args.serial and args.serial.upper() not in entry.get(
                                    'metadata', {}).get('serial', '').upper():
                                continue
                            entries.append(entry)

                # Проверка целостности если запрошено
                if hasattr(args, 'verify') and args.verify:
                    auditor = AuditLogger(str(log_file))
                    valid, idx, err = auditor.verify_chain()
                    if not valid:
                        print(f"AUDIT INTEGRITY FAILED at entry {idx}: {err}")
                        sys.exit(1)
                    print("✓ Audit log integrity verified")

                # Вывод
                if args.format == "json":
                    print(json.dumps(entries, indent=2))
                elif args.format == "csv":
                    if entries:
                        writer = csv.DictWriter(sys.stdout, fieldnames=entries[0].keys())
                        writer.writeheader()
                        writer.writerows(entries)
                else:
                    rows = [[e['timestamp'], e['level'], e['operation'], e['status'], e['message']] for e in entries]
                    print(tabulate(rows, headers=["Timestamp", "Level", "Operation", "Status", "Message"],
                                   tablefmt="grid"))

            elif args.subcommand == "verify":
                log_file = getattr(args, 'log_file', "./pki/audit/audit.log")
                chain_file = getattr(args, 'chain_file', "./pki/audit/chain.dat")
                auditor = AuditLogger(log_file, chain_file)
                valid, idx, err = auditor.verify_chain()
                if valid:
                    print("✓ Audit log integrity verified - no tampering detected")
                    sys.exit(0)
                else:
                    print(f"✗ AUDIT LOG TAMPERING DETECTED at entry {idx}: {err}")
                    sys.exit(1)

            elif args.subcommand == "ct-verify":
                serial = getattr(args, 'serial', '')
                ct_log = getattr(args, 'ct_log', "./pki/audit/ct.log")
                ct = CTLog(ct_log)
                if ct.contains(serial):
                    print(f"✓ Certificate {serial} found in CT log")
                    sys.exit(0)
                else:
                    print(f"✗ Certificate {serial} NOT found in CT log")
                    sys.exit(1)

    except Exception as e:
        logger.error(f"Critical error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()