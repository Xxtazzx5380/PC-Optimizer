from __future__ import annotations

import logging
from pathlib import Path


def configure(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("pc_optimizer")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(
            log_dir / "pc_optimizer.log",
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        )
        logger.addHandler(handler)

    return logger
