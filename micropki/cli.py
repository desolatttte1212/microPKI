import argparse
import sys
from pathlib import Path

from .logger import setup_logger
from .crypto_utils import read_passphrase_from_file


def parse_args():
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI: Minimalist Public Key Infrastructure Tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ca_parser = subparsers.add_parser("ca", help="Certificate Authority operations")
    ca_subparsers = ca_parser.add_subparsers(dest="subcommand", required=True)

    init_parser = ca_subparsers.add_parser("init", help="Initialize a self-signed Root CA")

    init_parser.add_argument(
        "--subject", type=str, required=True,
        help="Distinguished Name (e.g., '/CN=My Root CA' or 'CN=My Root CA,O=Demo')"
    )
    init_parser.add_argument(
        "--key-type", type=str, choices=["rsa", "ecc"], default="rsa",
        help="Key type: rsa or ecc (default: rsa)"
    )
    init_parser.add_argument(
        "--key-size", type=int, default=None,
        help="Key size: 4096 for RSA, 384 for ECC. Defaults to type standard if omitted."
    )
    init_parser.add_argument(
        "--passphrase-file", type=str, required=True,
        help="Path to file containing the encryption passphrase"
    )
    init_parser.add_argument(
        "--out-dir", type=str, default="./pki",
        help="Output directory (default: ./pki)"
    )
    init_parser.add_argument(
        "--validity-days", type=int, default=3650,
        help="Validity period in days (default: 3650)"
    )
    init_parser.add_argument(
        "--log-file", type=str, default=None,
        help="Path to log file. If omitted, logs to stderr."
    )

    return parser.parse_args()


def validate_args(args, logger):
    if not args.subject or len(args.subject.strip()) == 0:
        logger.error("Subject cannot be empty.")
        sys.exit(1)

    expected_size = 4096 if args.key_type == "rsa" else 384

    if args.key_size is None:
        args.key_size = expected_size
        logger.info(f"Key size not specified, defaulting to {expected_size} for {args.key_type.upper()}")
    elif args.key_size != expected_size:
        logger.error(f"Invalid key size {args.key_size} for {args.key_type.upper()}. Expected {expected_size}.")
        sys.exit(1)

    try:
        read_passphrase_from_file(args.passphrase_file)
        logger.info("Passphrase file validated successfully.")
    except Exception as e:
        logger.error(f"Failed to access passphrase file: {e}")
        sys.exit(1)

    out_path = Path(args.out_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
        test_file = out_path / ".write_test"
        test_file.touch()
        test_file.unlink()
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

    if args.subcommand == "init":
        validate_args(args, logger)
        logger.info("Arguments validated successfully.")

        from .ca import initialize_ca

        try:
            initialize_ca(args, logger)
        except Exception as e:
            logger.error(f"Failed to initialize CA: {e}", exc_info=True)
            sys.exit(1)

        logger.info("Command completed successfully.")
    else:
        logger.error(f"Unknown subcommand: {args.subcommand}")
        sys.exit(1)


if __name__ == "__main__":
    main()