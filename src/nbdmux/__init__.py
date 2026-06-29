"""nbdmux -- HTTP-controlled NBD-export multiplexer.

Two surfaces:

- ``nbdmux-server`` (``nbdmux.server:main``) -- the daemon. Manages an
  ``nbdkit`` subprocess that exposes registered local files as named
  NBD exports on a TCP port (default 10809). Operator dashboard +
  HTTP control API on a separate port (default 4040).
- ``nbdmux.client`` -- a tiny stdlib-only library for other tools
  (e.g. bty) to register / list / unregister exports without
  reimplementing the HTTP API.

Designed for the same niche as ``withcache``: a small lab, a single
sidecar container, no third-party Python deps. The system-level
dependency is ``nbdkit`` (Debian / Ubuntu / Fedora ship it as
``nbdkit-server`` + ``nbdkit-plugin-file``).
"""

from .client import add_export, list_exports, remove_export

__version__ = "0.1.0"

__all__ = ["__version__", "add_export", "list_exports", "remove_export"]
