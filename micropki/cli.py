import argparse
import sys
from pathlib import Path

from .logger import setup_logger
from .crypto_utils import read_passphrase_from_file
from .database import init_db, list_certificates, get_certificate_by_serial
from tabulate import tabulate


def parse_args():
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI (Sprint 3)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_subparsers = ca_parser.add_subparsers(dest="subcommand", required=True)

    init_p = ca_subparsers.add_parser("init", help="Init Root CA")
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, default=None)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--log-file", default=None)
    init_p.add_argument("--db-path", default="./pki/micropki.db", help="Path to DB to store Root CA")

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
    int_p.add_argument("--db-path", default="./pki/micropki.db", help="Path to DB")

    cert_p = ca_subparsers.add_parser("issue-cert", help="Issue Leaf Cert")
    cert_p.add_argument("--ca-cert", required=True)
    cert_p.add_argument("--ca-key", required=True)
    cert_p.add_argument("--ca-pass-file", required=True)
    cert_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    cert_p.add_argument("--subject", required=True)
    cert_p.add_argument("--san", action="append", default=[])
    cert_p.add_argument("--out-dir", default="./pki/certs")
    cert_p.add_argument("--validity-days", type=int, default=365)
    cert_p.add_argument("--csr", default=None)
    cert_p.add_argument("--log-file", default=None)
    cert_p.add_argument("--db-path", default="./pki/micropki.db", help="Path to DB")

    list_p = ca_subparsers.add_parser("list-certs", help="List certificates from DB")
    list_p.add_argument("--db-path", default="./pki/micropki.db")
    list_p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    list_p.add_argument("--format", choices=["table", "json", "csv"], default="table")

    show_p = ca_subparsers.add_parser("show-cert", help="Show cert PEM by serial")
    show_p.add_argument("serial", help="Serial number (hex)")
    show_p.add_argument("--db-path", default="./pki/micropki.db")

    db_parser = subparsers.add_parser("db", help="Database operations")
    db_subparsers = db_parser.add_subparsers(dest="subcommand", required=True)

    db_init_p = db_subparsers.add_parser("init", help="Initialize DB schema")
    db_init_p.add_argument("--db-path", default="./pki/micropki.db")

    repo_parser = subparsers.add_parser("repo", help="Repository operations")
    repo_subparsers = repo_parser.add_subparsers(dest="subcommand", required=True)

    repo_serve_p = repo_subparsers.add_parser("serve", help="Start HTTP server")
    repo_serve_p.add_argument("--host", default="127.0.0.1")
    repo_serve_p.add_argument("--port", type=int, default=8080)
    repo_serve_p.add_argument("--db-path", default="./pki/micropki.db")
    repo_serve_p.add_argument("--cert-dir", default="./pki/certs")
    repo_serve_p.add_argument("--log-file", default=None)

    return parser.parse_args()


def main():
    args = parse_args()

    log_file = getattr(args, 'log_file', None)
    logger = setup_logger(log_file)
    logger.info(f"Command: {args.command} {args.subcommand}")

    try:
        if args.command == "db":
            if args.subcommand == "init":
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
                if args.template == 'server' and not args.san:
                    logger.error("Server certificate requires at least one SAN (--san).")
                    sys.exit(1)
                issue_end_entity_cert(args, logger)

            elif args.subcommand == "list-certs":
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
                        for c in certs:
                            print(",".join(str(c[k]) for k in keys))
                else:
                    headers = ["Serial", "Subject", "Status", "Not After"]
                    rows = [[c['serial_hex'], c['subject'], c['status'], c['not_after']] for c in certs]
                    print(tabulate(rows, headers=headers, tablefmt="grid"))

            elif args.subcommand == "show-cert":
                rec = get_certificate_by_serial(args.db_path, args.serial)
                if rec:
                    print(rec['cert_pem'])
                else:
                    logger.error(f"Certificate {args.serial} not found in database.")
                    sys.exit(1)

        elif args.command == "repo":
            if args.subcommand == "serve":
                from .repository import run_server
                logger.info(f"Starting repository server on {args.host}:{args.port}")

                run_server(
                    host=args.host,
                    port=args.port,
                    db_path=args.db_path,
                    cert_dir=args.cert_dir,
                    logger_obj=logger
                )

        else:
            logger.error(f"Unknown command: {args.command}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Critical error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()