# nbdmux

HTTP-controlled NBD-export multiplexer for a small lab. Register local
disk-image files as named NBD exports over an HTTP control plane; nbdmux
keeps an `nbd-server` subprocess alive that serves all registered
exports on a single TCP port. Targets `nbd-client` against that port
from an initramfs and boot the image with overlayfs over tmpfs for
writes (see [bty][bty]'s `ramboot` boot mode for the canonical consumer).

Designed as a peer to [withcache][withcache]: small lab, single sidecar
container, no third-party Python deps. Operationally:

```
[ bty-web ] --HTTP--> [ nbdmux ]  --supervises-->  [ nbd-server ]
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
| `src/nbdmux/server.py`     | The daemon. HTTP control plane + nbd-server subprocess management + operator UI |
| `src/nbdmux/client.py`     | Stdlib-only Python client library for other tools                           |
| `deploy/Containerfile`     | Single-image deploy (Python + nbd-server)                                   |
| `deploy/compose.yml`       | Reference compose stack                                                 |

## System dependency

nbdmux runs `nbd-server` (from the classical `nbd` project) as a
subprocess. Install at the OS level:

```sh
# Debian / Ubuntu
sudo apt install nbd-server

# Fedora
sudo dnf install nbd
```

The container deploy bundles it. Also make sure the `nbd` kernel
module + `nbd-client` are available on the consuming Linux box (the
target you're booting); they're in the same `nbd` package.

## Install

```sh
pipx install nbdmux            # or: uv tool install nbdmux
```

Run the daemon (development; the container deploy is the recommended
production path):

```sh
nbdmux-server --data-dir ./data --port 4040 --nbd-port 10809
```

Register an image:

```sh
curl -X POST http://localhost:4040/exports \
     -H 'Content-Type: application/json' \
     -d '{"name": "debian-sysdev", "file": "/path/to/debian-sysdev.img", "readonly": true}'
```

Then on a target Linux box:

```sh
modprobe nbd
nbd-client <nbdmux-host> 10809 -name debian-sysdev /dev/nbd0
fdisk -l /dev/nbd0   # the .img's partition table
```

## HTTP control plane

| Method | Path                | Body                                          | Returns        |
|--------|---------------------|-----------------------------------------------|----------------|
| GET    | `/exports`          | -                                             | array of exports |
| POST   | `/exports`          | `{name, file, readonly?: bool}`               | the new export |
| DELETE | `/exports/{name}`   | -                                             | 204            |
| GET    | `/healthz`          | -                                             | `ok`           |
| GET    | `/`                 | -                                             | operator dashboard |

## Auth

Single-tenant, server-signed cookie -- same pattern as withcache. Set
`NBDMUX_ADMIN_PASSWORD` to gate the operator UI + the HTTP control
plane. Unset = open with a startup warning.

The NBD port itself is unauthenticated (nbd-server's classical model);
LAN-only assumption, firewall is the operator's responsibility.

## License

BSD-3-Clause.

[bty]: https://github.com/safl/bty
[withcache]: https://github.com/safl/withcache
