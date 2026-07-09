# nbdmux

HTTP-controlled NBD-export multiplexer for a small lab. Register local
disk-image files as named NBD exports over an HTTP control plane; nbdmux
keeps an `nbdkit` subprocess alive that serves the images directory on
a single TCP port. Every export gets nbdkit's `cow` filter so ramboot
targets can mount partitions read-write while the backing image stays
untouched. Targets `nbd-client` against that port from an initramfs and
boot the image with overlayfs over tmpfs on top for whole-tree writes
(see [bty][bty]'s `ramboot` boot mode for the canonical consumer).

Designed as a peer to [withcache][withcache]: small lab, single sidecar
container, no third-party Python deps. Operationally:

```
[ bty-web ] --HTTP--> [ nbdmux ]  --supervises-->  [ nbdkit ]
                          |                              |
                          |                            TCP 10809
                          |                              |
                          v                              v
                     SQLite state                  [ target's
                     (exports table)                nbd-client ]
```

## Components

| Path                       | What it is                                                              |
|----------------------------|-------------------------------------------------------------------------|
| `src/nbdmux/server.py`     | The daemon: exports table (SQLite) + Warmer worker + NbdServer supervisor + events audit log |
| `src/nbdmux/_app.py`       | FastAPI app factory + operator UI wiring (Bootstrap 5 + Bootstrap Icons + HTMX, matches bty + withcache chrome) |
| `src/nbdmux/client.py`     | Stdlib-only Python client library for other tools                       |
| `deploy/Containerfile`     | Single-image deploy (Ubuntu 26.04 base for nbdkit >= 1.44)               |
| `deploy/compose.yml`       | Reference compose stack                                                 |

## System dependency

nbdmux runs [nbdkit](https://libguestfs.org/nbdkit.1.html) (Red Hat's
NBD toolkit) as a subprocess, in `file dir=` mode plus the `cow`
filter. `cow` requires nbdkit >= 1.44 to be safe under multi-export
(see the "Export safe?" column in `nbdkit-filter-cow(1)`), which is
why the container base is Ubuntu 26.04 (nbdkit 1.46). Install at the
OS level for development:

```sh
# Ubuntu 24.04+ / Debian forky+
sudo apt install nbdkit

# Fedora
sudo dnf install nbdkit
```

The container deploy bundles it. Also make sure the `nbd` kernel
module + `nbd-client` are available on the consuming Linux box (the
target you're booting); those are in the classical `nbd` package.

## Install

```sh
pipx install nbdmux            # or: uv tool install nbdmux
```

Run the daemon (development; the container deploy is the recommended
production path):

```sh
nbdmux-server --data-dir ./data --port 8082 --nbd-port 10809
```

Register an image. Two body shapes are accepted:

**Pre-warmed** -- point at a file the operator has already placed
on disk:

```sh
curl -X POST http://localhost:8082/exports \
     -H 'Content-Type: application/json' \
     -d '{"name": "debian-sysdev", "file": "/path/to/debian-sysdev.img", "readonly": true}'
```

**Warm via withcache** -- nbdmux fetches ``src_url`` through the
configured withcache, decompresses on the fly (gzip / zstd / xz),
and lands the raw .img under ``<images-dir>/<name>.img``. Requires
``NBDMUX_WITHCACHE_URL`` set on the daemon:

```sh
curl -X POST http://localhost:8082/exports \
     -H 'Content-Type: application/json' \
     -d '{"name": "debian-sysdev", "src_url": "https://catalog/debian-sysdev.img.zst", "readonly": true}'
```

Then on a target Linux box:

```sh
modprobe nbd
nbd-client <nbdmux-host> 10809 -name debian-sysdev /dev/nbd0
fdisk -l /dev/nbd0   # the .img's partition table
```

## HTTP control plane

| Method | Path                     | Body                                          | Returns        |
|--------|--------------------------|-----------------------------------------------|----------------|
| GET    | `/exports`               | -                                             | array of exports |
| POST   | `/exports`               | `{name, file, readonly?: bool}` (pre-warmed) OR `{name, src_url}` (warm via withcache) | the new export |
| DELETE | `/exports/{name}`        | -                                             | 204 (warm-created also unlinks the .img) |
| POST   | `/admin/create_export`   | form-encoded `src_url=...`                    | 303 to `/ui/exports?error=<msg>` on failure, else `/ui/exports` |
| GET    | `/healthz`               | -                                             | `ok` (200) when nbdkit is up, `nbdkit not running` (503) when down |
| GET    | `/ui/dashboard`          | -                                             | landing page: exports + warm + upstream summary |
| GET    | `/ui/exports`            | -                                             | exports table + create-export picker |
| GET    | `/ui/events`             | -                                             | append-only audit log (filter + pagination) |
| POST   | `/admin/events/{id}/ack` | -                                             | 303 to `/ui/events` (marks failure acknowledged) |

`POST /admin/create_export` is what the operator UI's create-export
subnav form submits to. The form only carries ``src_url``; the
export name is derived from the URL basename (sanitised to the
export-name allowlist) so operators don't pick names by hand.
Validation failures 303 back to `/ui/exports?error=<msg>` and the
page renders the error inline.

## Operator UI

`http://<host>:8082/` lands on the Dashboard (exports + warm pipeline +
upstream summary + Health tripwire + last N audit events). The Exports
tab shows all registered exports and, top-right on the subnav strip, a
create-export `<select>` populated from `<NBDMUX_WITHCACHE_URL>/catalog`.
The Events tab surfaces the append-only audit log with a free-text
filter and per-page pagination; failure rows carry an ack button that
clears them from the dashboard tripwire. Settings edits withcache API
URL, withcache browser URL (for operator-facing cross-links), and log
level. Chrome uses Bootstrap 5 + Bootstrap Icons + HTMX bundled offline;
the same as bty and withcache, only the primary hue differs (magenta,
the terminus of the trio's navy -> dark-magenta -> magenta gradient).

## Withcache floor

Requires **withcache >= 0.12.0**. Since 0.11.0 `GET /catalog` returns
only downloaded entries; 0.12.0 consolidates the UI and 0.13.0 adds the
events log. Older withcache releases still fetch a catalog but staged
entries would show in the picker and warm at fetch time; keep the floor
current.

## Auth

Single-tenant, server-signed cookie -- same pattern as withcache. Set
`NBDMUX_ADMIN_PASSWORD` to gate the operator UI + the HTTP control
plane; unset = open with a startup warning.

`NBDMUX_SESSION_SECRET` pins the HMAC key that signs session cookies.
Unset (or blank) = the daemon generates a fresh 64-hex key at first
start and persists it under `<data-dir>/session-secret`. Set it
explicitly to keep cookies valid across a container rebuild that
wipes the data volume, or to rotate the secret on demand.

The NBD port itself is unauthenticated (nbdkit's default posture);
LAN-only assumption, firewall is the operator's responsibility.

## License

BSD-3-Clause.

[bty]: https://github.com/safl/bty
[withcache]: https://github.com/safl/withcache
