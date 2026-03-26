import time
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def generate_unique_serial() -> int:
    timestamp = int(time.time()) & 0xFFFFFFFF

    random_bytes = os.urandom(4)
    random_part = int.from_bytes(random_bytes, byteorder='big') & 0xFFFFFFFF

    serial = (timestamp << 32) | random_part
    return serial


def serial_to_hex(serial: int) -> str:
    return format(serial, 'X')