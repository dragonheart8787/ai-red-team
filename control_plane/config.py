"""Configuration and credential loading.

Nothing in this repository carries a default that contains a credential. A
connection string with a password baked in as a fallback is a credential in the
source tree — and once committed it stays in the history whether or not a later
commit removes it. Everything sensitive comes from the environment, optionally
seeded from a gitignored ``.env`` that ``scripts/init_db.sh`` generates.

Missing configuration raises with an instruction rather than falling back to
something that happens to work on the developer's machine: a silent default is
how a local password becomes a deployed one.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"

_loaded = False


def load_dotenv(path: Path | None = None, *, override: bool = False) -> None:
    """Seed os.environ from a ``.env`` file if one exists.

    Real environment variables win by default, so a deployment that sets
    DATABASE_URL properly is never overridden by a stray local file.
    """
    global _loaded
    target = path or ENV_FILE
    if _loaded and path is None:
        return
    if path is None:
        _loaded = True
    if not target.exists():
        return

    for line in target.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if override or key not in os.environ:
            os.environ[key] = value


def require_env(name: str, *, hint: str = "") -> str:
    """Return an environment variable or explain how to set it."""
    load_dotenv()
    value = os.environ.get(name)
    if not value:
        message = f"{name} is not set."
        if hint:
            message += f" {hint}"
        raise RuntimeError(message)
    return value
