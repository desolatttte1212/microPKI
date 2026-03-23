import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        logger.handlers.clear()
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, mode='a', encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def sanitize_message(msg: str) -> str:
    return msg