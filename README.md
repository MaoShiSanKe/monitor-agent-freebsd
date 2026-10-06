# monitor-agent-freebsd

FreeBSD monitoring agent for the [monitor](https://github.com/monitor-probe/monitor) hub.
A port of the official [monitor-probe/agent](https://github.com/monitor-probe/agent)
(Linux) — the WebSocket protocol layer is carried over from it (MIT), and the
collection layer is rewritten against the FreeBSD kernel: sysctl(3/8),
getfsstat(2), getifaddrs(3). The agent itself runs on any FreeBSD 12+ host,
root or not; it was built and first deployed in the most restricted setting
there is — a serv00 FreeBSD 14 jail without root — so less constrained hosts
just work.

## Why

monitor ships Linux agents only. On FreeBSD hosts — serv00 free hosting runs
FreeBSD 14 jails — there was nothing that speaks the hub's protocol. This fills
that gap with the same 2087-line code philosophy: two source files, no runtime
dependencies, one static binary.

## Jails: what the numbers mean

serv00 accounts live in FreeBSD jails sharing the host kernel. Readings are
**host-wide** where the kernel is shared, the same view `top` gives inside a
jail:

| Metric | Scope |
|---|---|
| CPU, load, memory | host (all tenants) |
| TCP/UDP connection counts | whatever the jail can see (usually a small subset; the host's table is closed to jails) |
| Network traffic counters | host, by default — see `--iface` |
| Disk | the jail's visible mounts |
| Process count | the jail's own |
| Swap | usually 0 from a jail (no swap devices visible) |

`--iface` restricts traffic counting to named interfaces (comma-separated,
`-name` excludes). By default every non-virtual interface is summed, which in
a jail is the whole host's traffic.

## Build

On the FreeBSD host (FreeBSD 14, any release with the base `rust` package or
rustup):

```sh
git clone <this repo>
cd monitor-agent-freebsd
cargo build --release
# target/release/monitor-agent-freebsd
```

Cross-compiling from other platforms is possible but untested; native build is
the supported path.

## Run

```sh
./monitor-agent-freebsd --server https://your.hub.example --token <node token>
```

Options: `--interval <secs>` (default 1), `--iface <list>`, `--insecure`.
The token travels in an `Authorization: Bearer` header, never the URL.
A baseline reading is taken one second after connecting, so the first
report already measures real CPU and network instead of reporting zeros.

### Keep it running without root

A jail user has no init system. crontab + daemon(8) survives host reboots
(`daemon` lives in `/usr/sbin` on FreeBSD 14):

```sh
install -d ~/bin
cp target/release/monitor-agent-freebsd ~/bin/
crontab -e
# add:
```

```
@reboot /usr/sbin/daemon -r /home/you/bin/monitor-agent-freebsd --server https://your.hub.example --token <token> >> /home/you/monitor-agent.log 2>&1
```

`daemon -r` restarts the agent if it exits; the reconnect backoff in the agent
covers hub-side outages. To update a running install, rebuild, then stop the
old process **before** copying — FreeBSD refuses to overwrite a running
binary (`Text file busy`), and `pkill -f monitor-agent-freebsd` also matches
the `daemon` supervisor's own command line, so the supervisor dies with it
and nothing restarts the agent:

```sh
cd ~/monitor-agent-freebsd && git pull && cargo build --release
pkill -f bin/monitor-agent
cp target/release/monitor-agent-freebsd ~/bin/
# the supervisor died with the pkill above; start it again the crontab way
/usr/sbin/daemon -r /home/you/bin/monitor-agent-freebsd --server https://your.hub.example --token <token> >> /home/you/monitor-agent.log 2>&1 &
```

Alternatively, write the new binary to a temp name, swap with `mv` (rename
is allowed on a running binary), and let the surviving supervisor restart
the agent itself.

## Protocol

Identical to the official agent: one WebSocket to `/api/agent/ws`, JSON-RPC
2.0 notifications (`hello`, `report`, `ping.result` in; `ping.tasks` out),
fields and semantics documented in the hub source (`src/agent_ws.rs`).

## License

MIT. The protocol layer derives from
[monitor-probe/agent](https://github.com/monitor-probe/agent); see the header
of `src/main.rs`.
