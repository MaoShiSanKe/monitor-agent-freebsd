# monitor-agent-freebsd

FreeBSD monitoring agent for the [monitor](https://github.com/monitor-probe/monitor) hub.
A port of the official [monitor-probe/agent](https://github.com/monitor-probe/agent)
(Linux) — the WebSocket protocol layer is carried over from it (MIT), and the
collection layer is rewritten against the FreeBSD kernel: sysctl(3/8),
getfsstat(2), getifaddrs(3).

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
| TCP/UDP connection counts | host |
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
covers hub-side outages. To update a running install: rebuild, copy the new
binary over `~/bin/monitor-agent-freebsd`, then `pkill -f monitor-agent-freebsd`
— `daemon -r` brings it back on the new file within a second.

## Protocol

Identical to the official agent: one WebSocket to `/api/agent/ws`, JSON-RPC
2.0 notifications (`hello`, `report`, `ping.result` in; `ping.tasks` out),
fields and semantics documented in the hub source (`src/agent_ws.rs`).

## License

MIT. The protocol layer derives from
[monitor-probe/agent](https://github.com/monitor-probe/agent); see the header
of `src/main.rs`.
