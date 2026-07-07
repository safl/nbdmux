"""Operator-overridable settings for nbdmux.

Mirrors :mod:`bty.web._settings_store` in shape. A thin key-value
store over a ``settings`` table in the same ``state.db``
:class:`nbdmux.server.Store` writes exports to. Values here are
persistent overrides for the knobs an operator wants to change
without redeploying:

- :data:`KEY_WITHCACHE_URL` -- the withcache upstream nbdmux fetches
  from during the warm pipeline. Env: :data:`ENV_WITHCACHE_URL`.
- :data:`KEY_WITHCACHE_BROWSER_URL` -- operator-facing URL for
  cross-links from the nbdmux UI to the withcache UI (distinct
  from the API URL since the internal container hostname is
  rarely browser-reachable). Env:
  :data:`ENV_WITHCACHE_BROWSER_URL`. Falls back to the API URL
  when unset.
- :data:`KEY_LOG_LEVEL` -- uvicorn / logging level. Env:
  :data:`ENV_LOG_LEVEL`. Default: ``info``.

Resolution order is always **override (this table) -> env -> default**
so operators can drop a env / systemd-unit config or bind-mount a
different bty.toml without hunting the DB.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

KEY_WITHCACHE_URL = "withcache.url"
ENV_WITHCACHE_URL = "NBDMUX_WITHCACHE_URL"

# Operator-facing browser URL for the withcache upstream. Distinct
# from KEY_WITHCACHE_URL because the address nbdmux uses to reach
# withcache from inside the container network (e.g.
# ``http://withcache:8081``) is rarely the same address the
# operator's browser can resolve (e.g. ``http://lab-host:8081``).
# Falls back to KEY_WITHCACHE_URL when unset so single-host deploys
# work with no extra config.
KEY_WITHCACHE_BROWSER_URL = "withcache.browser_url"
ENV_WITHCACHE_BROWSER_URL = "NBDMUX_WITHCACHE_BROWSER_URL"

KEY_LOG_LEVEL = "log.level"
ENV_LOG_LEVEL = "NBDMUX_LOG_LEVEL"
DEFAULT_LOG_LEVEL = "info"

# uvicorn accepts a small closed set; the Settings form rejects
# anything else so a hand-edit of state.db that puts garbage in the
# row surfaces on resolve rather than mid-boot.
LOG_LEVELS: tuple[str, ...] = ("critical", "error", "warning", "info", "debug", "trace")


class SettingValueError(ValueError):
    """Raised when a stored value can't be parsed to the canonical
    form the resolver promises. Same shape as bty's SettingValueError
    so the Settings form handles both alike."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def init(conn: sqlite3.Connection) -> None:
    """Create the ``settings`` table if it's not there yet.

    Called from the FastAPI app factory on startup. Idempotent; the
    same schema policy the exports table has applies here (pre-1.0,
    no migration apparatus, rotate on version mismatch)."""
    conn.executescript(_SCHEMA)


def get(conn: sqlite3.Connection, key: str) -> str | None:
    """Read the raw stored value or None when the key isn't set.

    Callers wanting the resolved effective value use the ``resolve_*``
    helpers below; this one is for the Settings render's "Override"
    column and for the POST handler's pre-write inspection."""
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    v: Any = row[0]
    if v is None:
        return None
    return str(v)


def set_value(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Upsert the row. Empty string is a valid override value
    (distinct from unset); callers wanting the "revert to env /
    default" semantics use :func:`clear`."""
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def clear(conn: sqlite3.Connection, key: str) -> None:
    """Remove the row so the resolver falls through to env / default."""
    conn.execute("DELETE FROM settings WHERE key = ?", (key,))


def resolve_withcache_url(conn: sqlite3.Connection) -> str | None:
    """DB override > $NBDMUX_WITHCACHE_URL > None.

    None means "warm-via-src_url will 400 with the configuration
    error"; pre-warmed ``{name, file}`` POSTs still work. The DB
    override lets operators tune via the Settings page without
    dropping an env / systemd unit."""
    override = get(conn, KEY_WITHCACHE_URL)
    if override:
        return override
    env = (os.environ.get(ENV_WITHCACHE_URL) or "").strip()
    return env or None


def resolve_withcache_browser_url(conn: sqlite3.Connection) -> str | None:
    """DB override > $NBDMUX_WITHCACHE_BROWSER_URL > resolved
    withcache.url. Used to render operator-facing cross-links to
    the withcache UI from nbdmux pages so the link is reachable
    from the operator's browser even when the API URL points at an
    internal container hostname."""
    override = get(conn, KEY_WITHCACHE_BROWSER_URL)
    if override:
        return override
    env = (os.environ.get(ENV_WITHCACHE_BROWSER_URL) or "").strip()
    if env:
        return env
    return resolve_withcache_url(conn)


def resolve_log_level(conn: sqlite3.Connection) -> str:
    """DB override > $NBDMUX_LOG_LEVEL > "info".

    Raises :class:`SettingValueError` when the stored / env value
    isn't in :data:`LOG_LEVELS`; the Settings form normalises to
    the canonical form before persisting so the raise only fires
    on a hand-edit of state.db or a bogus env var."""
    override = get(conn, KEY_LOG_LEVEL)
    if override:
        raw = override
    else:
        env = (os.environ.get(ENV_LOG_LEVEL) or "").strip()
        if not env:
            return DEFAULT_LOG_LEVEL
        raw = env
    lowered = raw.lower()
    if lowered not in LOG_LEVELS:
        raise SettingValueError(
            f"log level {raw!r} not in {LOG_LEVELS}; "
            "clear the row via /ui/settings or delete state.db to reset"
        )
    return lowered
