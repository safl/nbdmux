"""nbdmux -- HTTP-controlled NBD-export multiplexer.

Two surfaces:

- ``nbdmux-server`` (``nbdmux.server:main``) -- the daemon. Manages an
  ``nbd-server`` subprocess that exposes registered local files as
  named NBD exports on a TCP port (default 10809). Operator dashboard
  + HTTP control API on a separate port (default 8082).
- ``nbdmux.client`` -- a tiny stdlib-only library for other tools
  (e.g. bty) to register / list / unregister exports without
  reimplementing the HTTP API.

Designed for the same niche as ``withcache``: a small lab, a single
sidecar container. Since v0.3.0 the daemon runs on FastAPI +
Jinja + Bootstrap 5 + htmx (matching bty-web + the eventual
withcache port); ``nbdmux.client`` stays stdlib-only so downstream
consumers (bty) don't inherit the framework floor. The system-
level dependency is ``nbd-server`` (Debian / Ubuntu:
``apt install nbd-server``; Fedora: ``dnf install nbd``).
"""

from .client import add_export, is_healthy, list_exports, remove_export, warm_export

__version__ = "0.9.0"

__all__ = [
    "__version__",
    "add_export",
    "is_healthy",
    "list_exports",
    "remove_export",
    "warm_export",
]
