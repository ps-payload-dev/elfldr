# elfldr

This is an ELF loader for PS4 and PS5 systems that have been jailbroken. It runs
payloads in separate processes, supports SPRX dynamic linking, and resolves
symbols at runtime. Since payloads are executed in individual processes, the ELF
loader keeps on running even if a payload crashes.

This project combines the ELF loaders of [John Törnblom](https://github.com/john-tornblom):
his [PS4 elfldr project][ps4-upstream] and [PS5 elfldr project][ps5-upstream].
It builds with the unified [payload SDK][sdk] and uses [lib-ptrace][ptrace].
The PS4 and PS5 loaders are built from this shared project so applications can
consume the same API and platform implementations.

## Building

Install the [payload SDK][sdk] for the console you want to
build and Git on your Debian-based system. The Makefile fetches
[lib-ptrace][ptrace] automatically:

```console
sudo apt-get install git
```

Set the SDK path for the console you are building. Replace `#` with `4` or `5`:

```console
export PS#_PAYLOAD_SDK=/opt/ps-payload-sdk/ps#
```

Build either console or both:

```console
make PLATFORM=ps4
make PLATFORM=ps5
```

Builds go to `build/ps4` and `build/ps5`, with object files in each platform's
`objects/` directory. PS4 produces `elfldr-ps4.elf`, `elfldr-ps4.bin`, and
`lib-elfldr.a`; PS5 produces `elfldr-ps5.elf` and `lib-elfldr.a`. The static
library contains the platform loader, shared loader, and memory helpers. Clean
with `make PLATFORM=ps4 clean` or `make PLATFORM=ps5 clean`, and format the sources with `make PLATFORM=ps5 format`.

One GitHub Actions workflow builds both consoles using [payload SDK][sdk]
and uploads separate `elfldr-ps4` and `elfldr-ps5` artifacts so you can download
the build for your console.

## Quick-start

Start a firmware-compatible exploit that provides an ELF loader on port 9020.
PS5 examples include the [BD-J loader][bdj] and [Specter's WebKit approach][webkit].
On PS4, this lapse example loads `bin_loader.lua` on port 9026:

```bash
PS4_HOST=ps4
SEND_LUA=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/send_lua.py
LAPSE=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/lapse.lua
BIN_LOADER=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/bin_loader.lua

wget -qO- "$LAPSE" | python3 <(wget -qO- "$SEND_LUA") "$PS4_HOST" 9026 /dev/stdin
wget -qO- "$BIN_LOADER" | python3 <(wget -qO- "$SEND_LUA") "$PS4_HOST" 9026 /dev/stdin
```

Deploy the build to the exploit on port 9020:

```console
PS4_HOST=127.0.0.1 PS4_PORT=9020 make PLATFORM=ps4 test
PS5_HOST=127.0.0.1 PS5_PORT=9020 make PLATFORM=ps5 test
```

## Usage examples

The loader listens on port 9021. Send it a local payload, a console file path,
or a URL:

```console
HOST=127.0.0.1
PORT=9021

# Local file
nc -q0 "$HOST" "$PORT" < payload.elf

# File on the console
echo 'file:/data/payload.elf' | nc -q0 "$HOST" "$PORT"

# URL
echo 'https://example.com/payload.elf' | nc -q0 "$HOST" "$PORT"
```

The HTTP interface also accepts a payload URI or local file upload:

```console
curl "http://$HOST:$PORT?uri=file:/data/payload.elf"
curl --data-binary @payload.elf "http://$HOST:$PORT/payload.elf"
```

Payload URIs accept `args` for command-line arguments and `pipe=0` (also
`false` or `no`) to prevent standard output from being redirected to the
connection. The loader accepts `-p PORT` to change its port and `-q` to skip
the start-up notification.

## Use as a library

The build also produces `build/ps#/lib-elfldr.a` and the public header
`headers/elfldr.h`. Link the matching `lib-ptrace` archive after
`lib-elfldr.a`:

```make
CFLAGS += -I/path/to/elfldr/headers -I/path/to/lib-ptrace/headers
LDFLAGS += /path/to/elfldr/build/ps4/lib-elfldr.a \
           /path/to/lib-ptrace/build/ps4/libptrace.a
```

The context-aware spawn call accepts the working directory and environment:

```c
char *argv[] = { "/data/homebrew/example.elf", NULL };
char *envp[] = { NULL };
pid_t pid = elfldr_spawn("/data/homebrew", -1, argv, envp, elf, elf_size);
```

The header also accepts the legacy four-argument call used by existing
consumers; it defaults the working directory to `/` and inherits the default
environment. The exported helpers can set a target's working directory,
environment, process name, stdio, and heap size after it is attached. Loader
diagnostics are sent through the console kernel log so callers can collect them
without a UART.

Use `patch_ps4_ptrace()` from lib-ptrace when a PS4 application needs to set up
the kernel ptrace gates. It is PS4-only and safe to call repeatedly within a
process; already-patched sites are recognized by their byte patterns.

## Dependencies

The Makefile clones [lib-ptrace][ptrace] into `deps/` and builds
it for the selected console. To use an existing checkout:

```console
make PLATFORM=ps5 PTRACE_DIR=~/src/lib-ptrace
```

## Reporting Bugs

If you encounter problems with elfldr, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of
code, please file an issue before you start to work on your changes. This will
allow us to discuss the solution properly before you commit time and effort.

## License

elfldr is licensed under the GPLv3+.

[ps4-upstream]: https://github.com/ps4-payload-dev/elfldr
[ps5-upstream]: https://github.com/ps5-payload-dev/elfldr
[bdj]: https://github.com/john-tornblom/bdj-sdk/tree/master/samples/ps5-payload-loader
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[sdk]: https://github.com/ps-payload-dev/sdk
[ptrace]: https://github.com/ps-payload-dev/lib-ptrace
[issues]: https://github.com/ps-payload-dev/elfldr/issues/new
