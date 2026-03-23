import argparse
import sys
from pathlib import Path

from .logger import setup_logger
from .crypto_utils import read_passphrase_from_file


def parse_args():
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI: Minimalist Public Key Infrastructure Tool (Sprint 2)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ca_parser = subparsers.add_parser("ca", help="Certificate Authority operations")
    ca_subparsers = ca_parser.add_subparsers(dest="subcommand", required=True)

    init_parser = ca_subparsers.add_parser("init", help="Initialize a self-signed Root CA")

    init_parser.add_argument("--subject", type=str, required=True, help="Distinguished Name")
    init_parser.add_argument("--key-type", type=str, choices=["rsa", "ecc"], default="rsa")
    init_parser.add_argument("--key-size", type=int, default=None)
    init_parser.add_argument("--passphrase-file", type=str, required=True)
    init_parser.add_argument("--out-dir", type=str, default="./pki")
    init_parser.add_argument("--validity-days", type=int, default=3650)
    init_parser.add_argument("--log-file", type=str, default=None)

    int_parser = ca_subparsers.add_parser("issue-intermediate", help="Create and sign an Intermediate CA")

    int_parser.add_argument("--root-cert", type=str, required=True, help="Path to Root CA certificate (PEM)")
    int_parser.add_argument("--root-key", type=str, required=True, help="Path to Root CA encrypted private key")
    int_parser.add_argument("--root-pass-file", type=str, required=True, help="Passphrase file for Root CA key")
    int_parser.add_argument("--subject", type=str, required=True, help="Subject DN for Intermediate CA")
    int_parser.add_argument("--key-type", type=str, choices=["rsa", "ecc"], default="rsa")
    int_parser.add_argument("--key-size", type=int, default=None)
    int_parser.add_argument("--passphrase-file", type=str, required=True, help="Passphrase for Intermediate CA key")
    int_parser.add_argument("--out-dir", type=str, default="./pki")
    int_parser.add_argument("--validity-days", type=int, default=1825)
    int_parser.add_argument("--pathlen", type=int, default=0, help="Path length constraint")
    int_parser.add_argument("--log-file", type=str, default=None)

    cert_parser = ca_subparsers.add_parser("issue-cert", help="Issue an end-entity certificate")

    cert_parser.add_argument("--ca-cert", type=str, required=True, help="Path to Intermediate CA certificate")
    cert_parser.add_argument("--ca-key", type=str, required=True, help="Path to Intermediate CA encrypted key")
    cert_parser.add_argument("--ca-pass-file", type=str, required=True, help="Passphrase for Intermediate CA key")
    cert_parser.add_argument("--template", type=str, required=True, choices=["server", "client", "code_signing"])
    cert_parser.add_argument("--subject", type=str, required=True, help="Subject DN for the certificate")
    cert_parser.add_argument("--san", action="append", default=[],
                             help="SAN entry (e.g., dns:example.com). Repeatable.")
    cert_parser.add_argument("--out-dir", type=str, default="./pki/certs")
    cert_parser.add_argument("--validity-days", type=int, default=365)
    cert_parser.add_argument("--csr", type=str, default=None, help="Optional: Path to external CSR")
    cert_parser.add_argument("--log-file", type=str, default=None)

    return parser.parse_args()


def validate_root_args(args, logger):
    if not args.subject or len(args.subject.strip()) == 0:
        logger.error("Subject cannot be empty.")
        sys.exit(1)

    expected_size = 4096 if args.key_type == "rsa" else 384
    if args.key_size is None:
        args.key_size = expected_size
    elif args.key_size != expected_size:
        logger.error(f"Invalid key size {args.key_size} for {args.key_type.upper()}. Expected {expected_size}.")
        sys.exit(1)

    try:
        read_passphrase_from_file(args.passphrase_file)
    except Exception as e:
        logger.error(f"Failed to access passphrase file: {e}")
        sys.exit(1)

    out_path = Path(args.out_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Output directory '{args.out_dir}' is not writable: {e}")
        sys.exit(1)

    if args.validity_days <= 0:
        logger.error("Validity days must be a positive integer.")
        sys.exit(1)


def main():
    args = parse_args()
    logger = setup_logger(args.log_file)
    logger.info(f"Starting MicroPKI command: {args.command} {args.subcommand}")

    try:
        if args.subcommand == "init":
            validate_root_args(args, logger)
            from .ca import initialize_ca
            initialize_ca(args, logger)

        elif args.subcommand == "issue-intermediate":
            validate_root_args(args, logger)

            if not Path(args.root_cert).exists():
                logger.error(f"Root CA certificate not found: {args.root_cert}")
                sys.exit(1)
            if not Path(args.root_key).exists():
                logger.error(f"Root CA key not found: {args.root_key}")
                sys.exit(1)
            try:
                read_passphrase_from_file(args.root_pass_file)
            except Exception as e:
                logger.error(f"Failed to access Root CA passphrase file: {e}")
                sys.exit(1)

            from .ca import create_intermediate_ca
            create_intermediate_ca(args, logger)

        elif args.subcommand == "issue-cert":
            if not Path(args.ca_cert).exists():
                logger.error(f"CA certificate not found: {args.ca_cert}")
                sys.exit(1)
            if not Path(args.ca_key).exists():
                logger.error(f"CA key not found: {args.ca_key}")
                sys.exit(1)
            try:
                read_passphrase_from_file(args.ca_pass_file)
            except Exception as e:
                logger.error(f"Failed to access CA passphrase file: {e}")
                sys.exit(1)

            if args.template == 'server' and not args.san:
                logger.error("Server certificate requires at least one SAN (--san dns:... or --san ip:...).")
                sys.exit(1)

            if args.csr and not Path(args.csr).exists():
                logger.error(f"CSR file not found: {args.csr}")
                sys.exit(1)

            from .ca import issue_end_entity_cert
            issue_end_entity_cert(args, logger)

        else:
            logger.error(f"Unknown subcommand: {args.subcommand}")
            sys.exit(1)

        logger.info("Command completed successfully.")

    except Exception as e:
        logger.error(f"Critical error during execution: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()