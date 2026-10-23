"""Strict hostname-only input, with stable deduplication."""

import ipaddress
from pathlib import Path
import re
import unicodedata

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
MAX_TARGETS = 10000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_LINE_CHARS = 4096


def normalize_hostname(value: str) -> str:
    name = value.strip()
    if len(name) > 1024 or any(unicodedata.category(c).startswith("C") for c in name):
        raise ValueError("hostname contains control/invisible characters or is too long")
    if not name or any(c in name for c in "/\\:@?#%") or any(c.isspace() for c in name):
        raise ValueError("expected a hostname, without a scheme, port, path, or credentials")
    # A single trailing DNS root dot is accepted. IDNs use Python's IDNA codec.
    if name.endswith("."):
        name = name[:-1]
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid internationalized hostname") from exc
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(x) for x in labels):
        raise ValueError("invalid hostname: use DNS labels of 1–63 characters and a fully qualified name")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not hostname targets")
    if labels[-1].isdigit():
        raise ValueError("a numeric top-level label is not supported")
    return name


def load_targets(path: Path, *, preserve_original: bool = False) -> list[str]:
    if not path.is_file():
        raise ValueError(f"input is not a regular file: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input file exceeds the 16 MiB limit")
    targets: dict[str, str] = {}
    try:
        with path.open(encoding="utf-8-sig") as source:
            number = 0
            characters = 0
            while line := source.readline(MAX_LINE_CHARS + 1):
                number += 1
                characters += len(line)
                if len(line) > MAX_LINE_CHARS or characters > MAX_INPUT_BYTES:
                    raise ValueError(f"{path}:{number}: input line or file size limit exceeded")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                try:
                    targets.setdefault(normalize_hostname(line), line.strip())
                    if len(targets) > MAX_TARGETS:
                        raise ValueError(f"at most {MAX_TARGETS} unique targets are supported")
                except ValueError as exc:
                    raise ValueError(f"{path}:{number}: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read input file {path}: {exc}") from exc
    if not targets:
        raise ValueError("input file contains no hostnames")
    return list(targets.values()) if preserve_original else list(targets)
