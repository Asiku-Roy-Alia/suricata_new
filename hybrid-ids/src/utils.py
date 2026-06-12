"""Shared utilities used across the project.

Provides configuration loading, seed management, logging setup, and path
resolution. All scripts should import from here rather than reinventing these
primitives locally.
"""

from __future__ import annotations

import logging
import os
import random
import sys
from pathlib import Path
from typing import Any, Dict

import numpy as np
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"


def load_config(path: Path | str | None = None) -> Dict[str, Any]:
    """Load the YAML configuration and resolve paths to absolute form."""
    cfg_path = Path(path) if path else CONFIG_PATH
    with cfg_path.open("r") as fh:
        cfg = yaml.safe_load(fh)

    # Resolve all paths relative to project root.
    for key, rel in cfg["paths"].items():
        cfg["paths"][key] = str((PROJECT_ROOT / rel).resolve())
        Path(cfg["paths"][key]).mkdir(parents=True, exist_ok=True)

    return cfg


def set_seed(seed: int) -> None:
    """Fix every random source we depend on."""
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)


def setup_logging(cfg: Dict[str, Any], name: str) -> logging.Logger:
    """Configure root logger to write to both stdout and a per-script log file."""
    logs_dir = Path(cfg["paths"]["logs_dir"])
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / f"{name}.log"

    fmt = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.setLevel(logging.INFO)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    logger.addHandler(stream)

    file_handler = logging.FileHandler(log_file, mode="w")
    file_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def project_path(cfg: Dict[str, Any], key: str, *parts: str) -> Path:
    """Return an absolute path underneath one of the configured directories."""
    base = Path(cfg["paths"][key])
    return base.joinpath(*parts)
