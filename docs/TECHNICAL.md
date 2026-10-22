# Technical notes

How Tailscale, a Go program, runs on a PS5, and what was learned about the
console along the way. Everything here was measured on one console
(firmware 13.42, `kern.osreldate` 900000); treat it as observations, not a
specification.

## Architecture

`tailscale.elf` is one payload made of two parts.

**The launcher** (`launcher/`, C, built with ps5-payload-sdk):

1. The SDK's crt runs first. Among other things it patches the process so
   that system calls may be issued from any address. Without that, the kernel
   only accepts syscalls made from libkernel, and Go makes its own.
2. `main.c` raises privileges, moves the process to the lowest scheduling
   priority (see [Scheduling](#scheduling)) and sets `GOMAXPROCS=4`.
3. `goload.c` maps the embedded Go program (a position-independent ELF),
   applies its `R_X86_64_RELATIVE` relocations, makes its text executable,
   builds the argc/argv/envp/auxv block a FreeBSD kernel would pass, switches
   to a fresh 1 MB stack and jumps to the Go entry point. The embedded copy
   is then released with `madvise(MADV_FREE)`.

The launcher keeps a log, `/data/tailscale/launcher.log` (`report.c`): the
firmware version, each step that fails, and a last line before it jumps into
the Go program. A failure is also shown as a notification, because a payload
manager does not show what a payload prints. Just before the jump, stderr is
pointed at that log, so that a Go runtime that dies before the daemon has
opened its own log leaves its message there. What cannot be reported this
way is a failure in the SDK's crt, which runs before any of this.

**The daemon** (`tsd/`, Go): a `tsnet` server.

- Inbound: tsnet's fallback TCP handler pipes each tailnet connection to
  `127.0.0.1:<same port>`. It dials the local port before accepting, so
  ports with no listener are refused properly.
- Inbound UDP (`inboundudp.go`): tsnet has no catch-all for UDP, so the ports
  in `udpPorts` are listened on with `tsnet.Server.ListenPacket` on the
  node's tailnet addresses and relayed to `127.0.0.1`. The default list is
  PS5 Remote Play's (9295, 9296, 9297, 9302); its service answers clients
  that arrive from loopback. Both UDP directions share `udprelay.go`: one
  connection to the target per client address, dropped after two idle
  minutes.
- Outbound: local forwards (`localforward.go`) listen on localhost and relay
  TCP and UDP to a tailnet host through `tsnet.Server.Dial`. UDP is relayed
  per client address with an idle timeout. Each Sunshine host is a preset of
  seven such forwards on the ports that host really uses, derived from
  Sunshine's port setting (HTTPS -5, HTTP +0, RTSP +21, video +9, control
  +10, audio +11, microphone +13). The ports cannot be remapped, because the
  host tells the Moonlight client which ports to use; several hosts can only
  coexist on 127.0.0.1 if their Sunshine ports differ.
- A status page and JSON API on port 8090 (`web.go`, `settings.go`), an
  optional HTTP proxy, PS5 notifications by writing a request to
  `/dev/notification0`.
- Password (`auth.go`): PBKDF2-SHA256 hash in the config, session cookie,
  one attempt per second. Requests from loopback are exempt. For that to be
  safe, connections for the status page that arrive over the tailnet are not
  piped to localhost like other ports but handed to the page's HTTP server
  directly, so it sees the tailnet address.
- Settings are applied live where possible. The launcher needs one of them,
  the priority, before any Go code runs, so the daemon leaves it in
  `/data/tailscale/priority` for the next start.
- Update notice (`update.go`): the latest release tag from the GitHub API,
  twice a day, compared with the running version. A newer release is shown
  on the page and announced once on the console; the announced version is
  kept in `/data/tailscale/update-notified`.
- Installing an update (`selfupdate.go`, `relsig/`): on request only. The
  release's `tailscale-<version>.elf.sig` names a version and a SHA-256 and carries an
  Ed25519 signature over both. The daemon checks the signature against the
  public key built into it, that the version is the release's and newer than
  its own, downloads the payload to `/data/tailscale/update/`, compares the
  hash, optionally replaces the copy named by `payloadPath` (temporary file,
  then rename), and writes the payload to the ELF loader on 127.0.0.1:9021.
  The new instance stops the old one as with any payload sent again, and
  removes the download when it starts. The connection to the loader is kept
  open until the old process exits, because it is the new payload's standard
  output.
- Taildrop (`taildrop.go`): tsnet does not link Taildrop in; importing
  `tailscale.com/feature/taildrop` does. Received files wait in
  `state/files/<login>-uid-<n>/`. The daemon long-polls for them, copies each
  to `receiveDir` under a name that does not exist yet, and deletes it from
  the holding area.
- The device list says how each peer is reached, from the peer's status:
  a current direct address means direct, otherwise the relay region. The
  "test" link runs a disco ping (`LocalClient.Ping`), which measures the path
  WireGuard would use without sending IP traffic, and reports the latency.
- Tests run on GitHub for every push (`.github/workflows/test.yml`), on
  Linux and Windows. They do not build the payload.
- Who may connect (`access.go`): with `allowFrom` set to `own`, the TCP
  handler and the UDP relays ask Tailscale who the sender is (WhoIs) and
  serve only nodes of the same user as the console, from the console's own
  tailnet. Answers are kept for a minute per address. Anything that cannot
  be established is refused.
- Key expiry (`keyexpiry.go`): the date comes from the node's own status.
  The page warns from 14 days before, and the console shows a notification
  at 14, 3 and 1 days.
- When a listener reports that it had to reopen its socket (the PS5's
  network was reconfigured), the daemon asks Tailscale to rebind and re-STUN
  instead of waiting for its interface polling. See [Rest mode](#rest-mode)
  for the one time this has been seen.
- A payload that is sent again stops the running instance (through the
  status page, or failing that by the pid it recorded) and takes over.

**The icon helper** (`appicon/`, C) is a second, tiny payload embedded in the
launcher. The first time `tailscale.elf` runs, the launcher sends it to the
ELF loader on `127.0.0.1:9021`, where it runs as a process of its own,
registers a home screen app whose `param.json` has a `deeplinkUri` to the
status page, reports the result and exits. The launcher then writes
`/data/tailscale/icon-installed` and never does it again. It is a separate
payload so that the system libraries it needs are never loaded into the
long-running daemon process, where their threads could receive signals meant
for the Go runtime.

The same helper removes the icon (`sceAppInstUtilAppUnInstall`). A payload
sent to the ELF loader gets no arguments, so the mode is a byte in the file
after the marker `TSICON-MODE=`. The launcher leaves a copy of the helper in
`/data/tailscale/icon-helper.elf`; for Uninstall the daemon flips that byte
and sends it to the loader (`tsd/homeicon.go`).

There is no installer. Nothing is copied anywhere and no payload autoloader
is touched: the payload is run from wherever the user keeps it.

### Changing the coordination server while running

Tailscale reads its coordination server (ControlURL) only when it starts,
but the setting is worth applying without a re-sent payload, so
`restartTailscale` closes the running `tsnet.Server` and starts a new one
in the same process. Two things make that safe:

- The status page, the pid file and the launcher's priority file are all
  outside the tsnet server, so the page keeps serving and watching through
  the change. The watchers that outlive a server (`watch`, `recoverLogin`,
  `exposeUDP`, `watchKeyExpiry`, `collectFiles`) and every request handler
  look the server and its local client up through `daemon.tailscale()` and
  `daemon.localClient()`, which return the current ones or nil; with nil,
  each loop waits and forwards refuse rather than assume anything.
- Tailscale's state directory keeps one login profile per coordination
  server, keyed by its address, so a new server is a fresh login and
  switching back to a server used before finds its login waiting. Nothing
  of the old server's state is reused for the new one.

Verified on a development machine against two stand-in control servers on
`127.0.0.1`: with the second one set on the status page, all control
traffic (its `GET /key` requests and the resulting "fetch control key: 404"
health) moved from the first to the second within the restart, the page
stayed up, and the config file kept the new address. Not yet tried against
a real Headscale on the console.

## The PS5 as a Go target

Go is built for `GOOS=freebsd GOARCH=amd64` with cgo off and
`-buildmode=pie`, from a Go 1.27.1 tree with
`patches/go1.27.1-ps5.patch`. What the patch changes and why:

| File | Change | Reason |
| --- | --- | --- |
| `internal/platform/supported.go` | Allow internally linked PIE on freebsd/amd64. | The image must load at any address and no C toolchain is involved. |
| `runtime/defs_freebsd_amd64.go` | 48 bytes of padding in `ucontext` before `uc_mcontext`. | The PS5's signal context has extra fields there. Without it, nil-dereference panics and preemption read garbage. |
| `runtime/defs_freebsd_amd64.go`, `sys_freebsd_amd64.s` | `kevent` 363 with the 32 byte struct. | The FreeBSD 12 `kevent` (560) does not exist. |
| `runtime/sys_freebsd_amd64.s`, `os_freebsd.go` | `pipe2` built from `pipe` and `fcntl`. | `pipe2` (542) does not exist. |
| `runtime/os_freebsd.go` | CPU count from `hw.ncpu`. | `kern.smp.maxcpus` does not exist. |
| `syscall/asm_unix_amd64.s`, `asm9_unix2_amd64.s`, `ps5_freebsd_amd64.go` | Syscall emulation layer. | See below. |
| `internal/routebsd/interface_freebsd.go` | Find the link address using `if_data`'s own length field. | Sony's `if_data` is 0xb0 bytes, so interface names came back empty. |
| `os/executable_sysctl.go` | `os.Executable` falls back to a name from argv[0]. | The kernel has no path for a payload; tsnet treats the error as fatal. |

### The syscall table

The kernel implements the FreeBSD 9 system call numbers. **Every number from
532 up is a Sony syscall with an unrelated meaning**, so nothing FreeBSD
added later exists: `pipe2`, `accept4`, `ppoll`, `utimensat`, `futimens`,
`getrandom`, the 64-bit inode `fstat`/`fstatat`/`getdirentries`/`statfs`
family, the extended `kevent`. Issuing those numbers would call something
else entirely.

Go's `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6` and `Syscall9` are
patched to divert numbers >= 532 to `ps5_freebsd_amd64.go`, which rebuilds
them from FreeBSD 9 calls and converts the structures (old `stat`, `dirent`
and `statfs` layouts). Anything not emulated returns `ENOSYS`. Because
`golang.org/x/sys/unix` and `internal/syscall/unix` go through the same entry
points, they are covered too. `socket` and `socketpair` are also diverted, to
apply `SOCK_NONBLOCK`/`SOCK_CLOEXEC` with `fcntl`.

### Other kernel behaviour

- Page size is 16384. The Go linker aligns segments to 4096; the loader
  applies protection per 16 KiB page.
- Working as on FreeBSD: `thr_new`, `_umtx_op`, `sigaction`, `sigaltstack`,
  `thr_kill`, kqueue including `EVFILT_USER`, `mmap` reservations with
  `PROT_NONE` (64 MB and 4 GB tried), `MAP_FIXED`, `madvise(MADV_FREE)`,
  `sysctl` for `hw.pagesize`, `hw.ncpu`, `kern.arandom`, `kern.boottime`,
  `NET_RT_IFLIST` and `NET_RT_DUMP`, `AF_ROUTE` sockets.
- Directory reads: `/data` (nullfs) and `/user` (bfs) only accept a buffer of
  exactly 65536 bytes for `getdirentries`. The emulation always reads 64 KiB
  blocks and hands the converted entries out across calls.
- Unix domain sockets cannot be bound on `/data`.
- There is no `/etc/resolv.conf` and no CA bundle. Go's resolver falls back
  to `127.0.0.1:53`, which only answers if a DNS payload runs on the
  console. The daemon therefore installs its own resolver (`dns.go`): it
  probes `127.0.0.1:53`, the default gateway and three public resolvers,
  uses the first that answers, and checks again every five minutes or when
  the network changes. A query is believed only when the plain server has a
  real answer for it; anything else — silence, an error, or a negative
  answer (SERVFAIL, NXDOMAIN, or "no error but no addresses", which is what
  a blocking resolver or a transparent interceptor hands back for a name it
  refuses to resolve) — is asked a second time over DNS-over-HTTPS
  (RFC 8484): the published addresses of `cloudflare-dns.com` and
  `dns.google` are dialed
  directly with the endpoint's name carried as the TLS server name, so the
  DoH endpoints need no name lookup of their own and no UDP port 53 path
  exists for a network to intercept. The daemon imports `x509roots/fallback`
  for TLS roots.
- Every DoH endpoint is asked **at once**, not one after another. Go's
  resolver gives a single attempt at one name server about 5 s before it
  re-dials, and the whole fallback must answer inside that: plain server
  (2 s) plus DoH (2.5 s, all endpoints in parallel) is at worst 4.5 s. A
  serial probe could not fit: the answer arrived after the resolver had
  hung up, the attempt died, and a control lookup failed at exactly the
  DNS cache's outer 10 s budget twice over — and fell through to the DERP
  bootstrap DNS, which cannot know a private server's name. A DoH reply is
  also parsed and checked (`dnsAnswerProblems`): it counts only if it is a
  response, carries the very name and record kind asked, with a success
  rcode and at least one answer. An interceptor's error page over port 443
  is therefore a failure, not an answer, and the failure of every endpoint
  is reported together in one log line.
- A name the network's DNS will not resolve at all — usually the user's
  own coordination server — can be fixed to an address on the status page
  (**Names your network cannot resolve**, `name=address`, comma-separated;
  `config.json` field `nameAddresses`). A fixed name is answered from the
  address without asking any name server; the record kind with no address
  set gets a clean empty answer so Go's resolver finds the name and stops
  asking. Fixed addresses apply to the running process at once; no restart
  is needed.
- After the picker is installed, and whenever the coordination server or
  the fixed addresses change, the daemon resolves the coordination
  server's name itself (`checkControl`) and logs the outcome, so a
  diagnostics file says at once whether the console can find its own
  server instead of waiting for Tailscale to time out twice.
- The picker is installed into both resolvers that matter: `net.DefaultResolver`
  (the daemon's own HTTP, the update check) and `dnscache.Get().Forward`
  (Tailscale's DNS cache). The control client copies the cache's forwarder
  when it is built and does not read `net.DefaultResolver`, so replacing
  only the default resolver would leave coordination-server lookups on the
  plain path — where, for a Headscale name, they fall through to the DERP
  bootstrap DNS (`control: trying bootstrapDNS(...) ...` in the log), whose
  map contains Tailscale's own host names only and can never answer for a
  custom server. Both are wired from `dnsPicker.install()` at start-up,
  before any Tailscale server is built.
- A payload's stdin, stdout and stderr are the ELF loader's TCP connection.
  Go kills a process whose write to fd 1 or 2 fails with `EPIPE`, so the
  daemon moves that connection to another descriptor and points 1 and 2 at
  its log file.
- The SDK's `kernel_mprotect()` rewrites the protection of the whole kernel
  map entry that contains the address. The loader first splits the text range
  off with an ordinary `mprotect()`.
- `sendfile` on a socket fails with "socket is not connected". Go uses it
  whenever a file is copied straight to a TCP connection (`io.Copy(conn,
  file)`, `http.ServeContent` with a file), so the daemon hides the file
  behind a plain reader in those places.
- When the network is reconfigured (connection settings changed, Wi-Fi to
  Ethernet), listening sockets fail with errno 163, a Sony-specific code, and
  do not recover. The daemon's listeners reopen themselves
  (`tsd/listener.go`).

## Scheduling

This is the part to read before running any new test on a console.

Payload threads start as FIFO threads at priority 700 (`rtprio_thread`
reports class 10, priority 700; the range is 256 to 767 and lower runs
first). A FIFO thread that never blocks is never descheduled. A Go test with
a busy loop on each of the 16 logical cores froze the console completely:
the kernel still answered ping, but no user process ran, and only a
power-cycle recovered it.

`rtprio_thread(RTP_SET)` silently ignores priorities outside that range, so
the usual `RTP_PRIO_NORMAL, 0` does nothing and reports success. These are
accepted and read back: class 3 (time-sharing) at 767, class 2 (round-robin)
at 767, class 10 (FIFO) at 767. New threads inherit the setting.

The launcher sets class 3, priority 767 before Go starts, reads it back, and
refuses to start if it did not take. With that, Go's signal-based preemption
works across cores (4 spinning goroutines, 5 garbage collections in about
350 ms). Test builds can add a watchdog thread that kills the process after
a fixed time (`build-payload.ps1 -Watchdog`).

The "high" priority setting uses class 2 (round-robin) at priority 700
instead: equal to games and system threads, but equal-priority round-robin
threads take turns. With it, the same test passes (5 collections in about
300 ms) and the console stays responsive: the status page answered within
60 ms throughout while four goroutines spun.

## Rest mode

Observed first for a rest of about a minute on Ethernet. The process is not
killed: it is frozen with the rest of the console and continues afterwards.

- Going to sleep, the network is taken down first. Every socket fails with
  errno 163 at the same moment: the status page listener, Tailscale's relay
  connection and its connection to the coordination server. The listener
  reopened at once, the daemon asked for a rebind, and Tailscale saw "all
  links down" and paused.
- Nothing is logged while the console sleeps, and it is not reachable on the
  tailnet.
- On waking, Tailscale's monitor noticed the jump in the clock, rebound its
  sockets, reconnected to its relay and had its endpoints back within about
  300 ms. The status page, forwarded TCP ports and the Remote Play UDP ports
  answered through the tailnet address afterwards without anything being
  restarted.

A rest of nine and a half hours went the same way: the monitor reported the
time jump on waking and the same process carried on. Rest mode on Wi-Fi has
not been tried.

## Home screen icon

`/user/app/TSCL00001/sce_sys/param.json` with `applicationCategoryType` 65536
and a `deeplinkUri`, plus `icon0.png`, registered with
`sceAppInstUtilAppInstallTitleDir`. The console opens the link in its
browser.

Linking `libSceAppInstUtil` alone leaves the payload stopped before it runs.
It needs `-lSceIpmi -lSceAppInstUtil -lSceUserService -lSceSystemService`, in
that order, as in the SDK's `install_app` sample.

## Known problems

- Once, switching the console from Wi-Fi to Ethernet during a Moonlight
  stream through the forwards froze the console. At that moment two daemon
  instances were running because of a bug that has since been fixed; whether
  that, the Moonlight client or something else caused the freeze is not
  known.
- Once, a first login completed in the browser but the daemon's follow-up
  request was answered with "auth path not found". The daemon now requests a
  new link when it sees that error; the recovery path has not been observed
  in practice.
- Tailscale's sockets recovered after rest mode took the network down and
  brought it back. A change of interface (Wi-Fi to Ethernet or back) while
  the daemon runs has not been observed since the rebind request was added.
