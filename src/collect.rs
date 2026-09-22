//! FreeBSD-only metric collection, read directly from sysctl, getfsstat and
//! getifaddrs. No /proc, no /sys: the FreeBSD kernel exposes everything this
//! agent reports through documented interfaces.
//!
//! A serv00 jail shares the kernel with its host, so most readings here are
//! host-wide -- CPU, load, memory, socket counts and by default the interface
//! counters. That is the same view `top` gives inside a jail and is reported
//! as such. Process count is the jail's own. Swap information is frequently
//! invisible from a jail; a failed reading reports zero rather than guessing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use serde::Serialize;

/// Interfaces that carry neither this machine's traffic nor its identity.
///
/// FreeBSD names differ from Linux's: `lo0` rather than `lo`, `tun`/`tap`/`wg`
/// for tunnels, `epair`/`vnet` for jail virtual pairs, `bridge` for if_bridge,
/// `pflog`/`pfsync` for the packet filter's own.
const SKIP_IFACES: &[&str] = &[
    "lo",
    "tun",
    "tap",
    "wg",
    "bridge",
    "epair",
    "vnet",
    "pflog",
    "pfsync",
    "enc",  // ipsec encapsulation interface
    "gif",  // generic tunnel
    "stf",  // 6to4
    "fwe",  // firewire IP
    "vmnet", // vmware host virtual
    "tailscale",
    "zt",
];

/// Filesystem types that must not count toward disk totals. The jail's mounts
/// include its own devfs, procfs and fdescfs plus whatever tmpfs the panel
/// software has made; nullfs mirrors of the host tree are excluded because the
/// underlying storage is already counted through its real mount.
const SKIP_FSTYPES: &[&str] = &[
    "devfs",
    "procfs",
    "fdescfs",
    "tmpfs",
    "nullfs",
    "linprocfs",
    "linsysfs",
    "unionfs",
    "fusefs",
    "nfs",
    "nfs4",
    "cifs",
    "smbfs",
    // zfs is NOT here: the jail's root usually is one. ZFS datasets are summed
    // once per pool, deduplicated in real_mount_points below.
];

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Facts {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub virt: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub mem_total: u64,
    pub swap_total: u64,
    pub disk_total: u64,
    pub agent_version: String,
    /// The host's own addresses, public ones first. The hub sees only the
    /// family the agent connected over.
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    /// Names the span over which `net_rx_total` and `net_tx_total` readings
    /// are comparable. The hub only tests it for equality, and a change makes
    /// it re-baseline rather than book the difference. FreeBSD has no boot_id
    /// file; `kern.boottime` serves: it changes when the counters restart at
    /// zero. A digest of the summed interfaces follows, so an interface
    /// joining the sum within one boot does not have its lifetime bytes
    /// booked as traffic.
    pub boot_id: String,
    /// The `--iface` this agent runs with, empty for the default rules. Shown
    /// by the panel.
    pub iface: String,
    pub uptime: u64,
    pub cpu: f32,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    /// Kernel lifetime byte counters. The hub accumulates these; the agent
    /// stores nothing and does not attempt to survive a reboot.
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub tcp: u32,
    pub udp: u32,
    pub procs: u32,
}

/// The traffic filter set by `--iface`: full interface names separated by
/// commas.
///
/// A plain entry makes the list the whole answer: nothing unlisted is counted.
/// Only the machine's owner knows which port carries the counted traffic. A
/// listed name is counted whatever the built-in rules say. An entry starting
/// with `-` removes that interface from what is counted otherwise. Exclusions
/// win over inclusions.
#[derive(Default)]
pub struct Ifaces {
    spec: String,
    only: Vec<String>,
    skip: Vec<String>,
}

impl Ifaces {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let entries: Vec<&str> = spec.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        let mut ifaces = Self { spec: entries.join(","), ..Self::default() };
        for entry in entries {
            let (list, name) = match entry.strip_prefix('-') {
                Some(name) => (&mut ifaces.skip, name),
                None => (&mut ifaces.only, entry),
            };
            if name.is_empty() || name.starts_with('-') || name.contains(char::is_whitespace) {
                return Err(format!(
                    "--iface: {entry:?} is not an interface name; give full names separated by commas"
                ));
            }
            list.push(name.to_owned());
        }
        Ok(ifaces)
    }

    fn counts(&self, name: &str) -> bool {
        if self.skip.iter().any(|n| n == name) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.iter().any(|n| n == name);
        }
        !skip_iface(name)
    }
}

/// See [`Metrics::boot_id`]. The names are sorted, since getifaddrs lists a
/// recreated interface in a new position without the set having changed, and
/// hashed with FNV-1a, whose output no Rust release can alter.
fn epoch(boot_time: u64, names: impl Iterator<Item = String>) -> String {
    let mut names: Vec<String> = names.collect();
    names.sort();
    // A newline cannot occur in an interface name, so no two sets join alike.
    let digest = names
        .join("\n")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
    format!("{boot_time}/{digest:016x}")
}

#[derive(Default)]
pub struct Collector {
    ifaces: Ifaces,
    prev_cpu: Option<(u64, u64)>,
    /// When the last sample was taken, and each counted interface's counters.
    prev_net_at: Option<Instant>,
    prev_net: HashMap<String, (u64, u64)>,
}

impl Collector {
    pub fn new(ifaces: Ifaces) -> Self {
        Self { ifaces, ..Self::default() }
    }

    /// The interfaces the traffic totals include at this moment.
    pub fn counted_ifaces(&self) -> Vec<String> {
        raw_if_counters().into_iter().filter(|(name, ..)| self.ifaces.counts(name)).map(|(name, ..)| name).collect()
    }

    /// `(name, rx, tx)` of the counted interfaces, freshly read. Same filter
    /// as [`Self::counted_ifaces`] — a drift between the two would make the
    /// startup log name interfaces the totals then ignore.
    fn counted(&self) -> Vec<(String, u64, u64)> {
        raw_if_counters().into_iter().filter(|(name, ..)| self.ifaces.counts(name)).collect()
    }

    pub fn facts(&self) -> Facts {
        let (v4, v6) = addresses();
        let (mem_total, _) = memory();
        let (cpu_name, cpu_cores) = cpu_info();
        let (disk_total, _) = disk_usage(&real_mount_points());
        Facts {
            hostname: sysctl_string("kern.hostname").unwrap_or_else(|| "unknown".into()),
            os: os_name(),
            kernel: sysctl_string("kern.osrelease").unwrap_or_else(|| "unknown".into()),
            arch: std::env::consts::ARCH.into(),
            virt: virtualization(),
            cpu_name,
            cpu_cores,
            mem_total,
            swap_total: swap().0,
            disk_total,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            ipv4: v4,
            ipv6: v6,
        }
    }

    pub fn collect(&mut self) -> Metrics {
        let (mem_total, mem_used) = memory();
        let (swap_total, swap_used) = swap();
        let (disk_total, disk_used) = disk_usage(&real_mount_points());
        let counted = self.counted();
        let (rx_total, tx_total) = totals(&counted);
        let boot_time = sysctl_boottime_secs().unwrap_or(0);
        let boot_id = epoch(boot_time, counted.iter().map(|(name, ..)| name.clone()));
        let (rx, tx) = self.net_rate(&counted, Instant::now());
        let (tcp, udp) = conn_counts();

        Metrics {
            boot_id,
            iface: self.ifaces.spec.clone(),
            uptime: uptime(),
            cpu: self.cpu_percent(),
            load: loadavg(),
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            disk_total,
            disk_used,
            net_rx_total: rx_total,
            net_tx_total: tx_total,
            net_rx: rx,
            net_tx: tx,
            tcp,
            udp,
            procs: proc_count(),
        }
    }

    /// CPU busy share since the previous call. The first call has no baseline
    /// and reports 0 rather than a since-boot average.
    fn cpu_percent(&mut self) -> f32 {
        let Some(now) = cpu_times() else {
            return 0.0;
        };
        let pct = self.prev_cpu.map_or(0.0, |prev| busy_percent(prev, now));
        self.prev_cpu = Some(now);
        pct
    }

    /// Per interface, over those in both samples: one joining brings a lifetime
    /// counter that is not this interval's traffic, and one whose counter
    /// restarted moved backwards. Either would otherwise read as a burst in the
    /// history. Kept in memory only; a restarted agent reports no rate once.
    fn net_rate(&mut self, counted: &[(String, u64, u64)], now: Instant) -> (u64, u64) {
        let rate = match self.prev_net_at {
            Some(t) => {
                let secs = now.saturating_duration_since(t).as_secs_f64();
                let (rx, tx) = counted
                    .iter()
                    .filter_map(|(name, rx, tx)| {
                        let (prx, ptx) = self.prev_net.get(name)?;
                        Some((rx.saturating_sub(*prx), tx.saturating_sub(*ptx)))
                    })
                    .fold((0u64, 0u64), |(a, b), (r, t)| (a.saturating_add(r), b.saturating_add(t)));
                if secs <= 0.0 {
                    (0, 0)
                } else {
                    ((rx as f64 / secs) as u64, (tx as f64 / secs) as u64)
                }
            }
            None => (0, 0),
        };
        self.prev_net_at = Some(now);
        self.prev_net = counted.iter().map(|(n, r, t)| (n.clone(), (*r, *t))).collect();
        rate
    }
}

// ---------------------------------------------------------------------------
// sysctl plumbing
// ---------------------------------------------------------------------------

/// One string sysctl, read straight by name. `sysctlbyname` answers a
/// NUL-terminated byte string for the names this agent asks; walking the MIB
/// instead would hand back the MIB integers themselves.
pub fn sysctl_string(name: &str) -> Option<String> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    // A NULL buffer asks only for the size.
    if unsafe { libc::sysctlbyname(c.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0
        || len == 0
    {
        return None;
    }
    let mut buf = vec![0u8; len];
    if unsafe { libc::sysctlbyname(c.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).ok()
}

/// One integer-valued sysctl, read by MIB so it can be asked twice without
/// re-resolving the name. `sysctlnametomib` first, then `sysctl` against the
/// MIB with the natural-width type the caller states.
pub fn sysctl_u64(name: &str) -> Option<u64> {
    let mut mib = [0i32; CTL_MAXNAME];
    let mut miblen = mib.len();
    let c = std::ffi::CString::new(name).ok()?;
    if unsafe { libc::sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut miblen) } != 0 {
        return None;
    }
    let mut value: libc::c_long = 0;
    let mut len = std::mem::size_of::<libc::c_long>();
    if unsafe { libc::sysctl(mib.as_ptr(), miblen as libc::u_int, (&mut value as *mut libc::c_long).cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    Some(u64::try_from(value).unwrap_or(0))
}

const CTL_MAXNAME: usize = 24;

// ---------------------------------------------------------------------------
// CPU
// ---------------------------------------------------------------------------

/// `(total, idle)` across all CPUs, from `kern.cp_time` (long array, one row
/// of CPUSTATES per CPU) or `kern.cp_times` when the single-row answer looks
/// wrong. The states are CP_USER, CP_NICE, CP_SYS, CP_INTR, CP_IDLE in that
/// order; idle is index 4. Everything else is work the machine did.
fn cpu_times() -> Option<(u64, u64)> {
    let mut mib = [0i32; CTL_MAXNAME];
    let mut miblen = mib.len();
    let c = std::ffi::CString::new("kern.cp_times").ok()?;
    if unsafe { libc::sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut miblen) } != 0 {
        return None;
    }
    // Ask for the size first: ncpu * CPUSTATES longs.
    let mut len = 0usize;
    if unsafe { libc::sysctl(mib.as_ptr(), miblen as libc::u_int, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    let n = len / std::mem::size_of::<libc::c_long>();
    if n < 5 {
        return None;
    }
    let mut buf = vec![0u8; len];
    if unsafe { libc::sysctl(mib.as_ptr(), miblen as libc::u_int, buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    let longs: &[libc::c_long] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), n) };
    let mut total = 0u64;
    let mut idle = 0u64;
    for row in longs.chunks(5) {
        for (i, v) in row.iter().enumerate() {
            let v = u64::try_from(*v).unwrap_or(0);
            total = total.saturating_add(v);
            if i == 4 {
                idle = idle.saturating_add(v);
            }
        }
    }
    Some((total, idle))
}

/// Busy share between two `(total, idle)` readings.
fn busy_percent(prev: (u64, u64), now: (u64, u64)) -> f32 {
    let ((pt, pi), (total, idle)) = (prev, now);
    if total <= pt {
        return 0.0;
    }
    let dt = (total - pt) as f32;
    let di = idle.saturating_sub(pi) as f32;
    ((dt - di) / dt * 100.0).clamp(0.0, 100.0)
}

/// One, two and fifteen-minute load, from `getloadavg(3)` -- the libc
/// wrapper that owns the `vm.loadavg` layout, whose struct grew past what a
/// hand-written mirror assumed (24 bytes, not 16, and asking for 16 fails
/// with ENOMEM rather than truncating).
fn loadavg() -> [f32; 3] {
    let mut loads = [0.0f64; 3];
    let n = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
    if n < 3 {
        return [0.0; 3];
    }
    loads.map(|v| v as f32)
}

fn uptime() -> u64 {
    // boottime is an absolute wall-clock stamp, so uptime is now minus it.
    let boot = sysctl_boottime_secs().unwrap_or(0);
    now_secs().saturating_sub(boot)
}

/// `kern.boottime` as raw seconds since the epoch, read as a `struct timeval`.
fn sysctl_boottime_secs() -> Option<u64> {
    #[repr(C)]
    struct TimeVal {
        sec: i64,
        usec: i64,
    }
    let mut mib = [0i32; CTL_MAXNAME];
    let mut miblen = mib.len();
    let c = std::ffi::CString::new("kern.boottime").ok()?;
    if unsafe { libc::sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut miblen) } != 0 {
        return None;
    }
    let mut tv = TimeVal { sec: 0, usec: 0 };
    let mut len = std::mem::size_of::<TimeVal>();
    if unsafe { libc::sysctl(mib.as_ptr(), miblen as libc::u_int, (&mut tv as *mut TimeVal).cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    u64::try_from(tv.sec).ok()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn os_name() -> String {
    sysctl_string("kern.version")
        .and_then(|v| v.lines().next().map(str::to_owned))
        .unwrap_or_else(|| "FreeBSD".into())
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Memory as `top` inside a jail reports it: host-wide, since a non-VNET jail
/// shares the kernel's VM system and no per-jail accounting exists.
///
/// Used = total - free - inactive - laundry - cache. This mirrors FreeBSD's
/// own `sysctl -a | grep -E 'v_free'` arithmetic (what `top`'s "free" column
/// sums): active+wired is in use, free+inactive+laundry+cache is reclaimable.
fn memory() -> (u64, u64) {
    let page = sysctl_u64("vm.stats.vm.v_page_size").unwrap_or(4096).max(1);
    let total_pages = sysctl_u64("vm.stats.vm.v_page_count").unwrap_or(0);
    let free = sysctl_u64("vm.stats.vm.v_free_count").unwrap_or(0);
    let inactive = sysctl_u64("vm.stats.vm.v_inactive_count").unwrap_or(0);
    let laundry = sysctl_u64("vm.stats.vm.v_laundry_count").unwrap_or(0);
    let cache = sysctl_u64("vm.stats.vm.v_cache_count").unwrap_or(0);
    let total = total_pages.saturating_mul(page);
    let reclaimable = free.saturating_add(inactive).saturating_add(laundry).saturating_add(cache).saturating_mul(page);
    (total, total.saturating_sub(reclaimable))
}

/// Swap from `vm.swap_info`, one long per swap device (index 0 = total of
/// devices in some listings, but actually index 0 is device 0 and the value
/// is DEV_SW* blocks). The truth: vm.swap_info is an array-valued sysctl
/// whose element i is device i's `struct xswdev` -- version, flags, dev,
/// nblks, used. Reading the whole buffer and summing nblks/used across
/// devices gives totals in 512-byte DEV_BSIZE blocks.
fn swap() -> (u64, u64) {
    let mut mib = [0i32; CTL_MAXNAME];
    let mut miblen = mib.len();
    let c = match std::ffi::CString::new("vm.swap_info") {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    if unsafe { libc::sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut miblen) } != 0 {
        return (0, 0);
    }
    #[repr(C)]
    struct XswDev {
        version: libc::c_int,
        flags: libc::c_int,
        dev: libc::dev_t,
        nblks: libc::c_int,
        used: libc::c_int,
    }
    let mut total = 0u64;
    let mut used = 0u64;
    // A jail usually has no swap devices; the first read with an appended
    // index fails (ENOENT) and the loop never opens.
    for i in 0..16u32 {
        let mut dev_mib = mib;
        dev_mib[miblen] = i as i32;
        let mut xsw = XswDev { version: 0, flags: 0, dev: 0, nblks: 0, used: 0 };
        let mut len = std::mem::size_of::<XswDev>();
        let rc = unsafe {
            libc::sysctl(dev_mib.as_ptr(), miblen as libc::u_int + 1, (&mut xsw as *mut XswDev).cast(), &mut len, std::ptr::null_mut(), 0)
        };        if rc != 0 {
            break;
        }
        // XSWDEV_VERSION guards against a struct the kernel fills differently.
        const XSWDEV_VERSION: libc::c_int = 1;
        if xsw.version != XSWDEV_VERSION {
            break;
        }
        total = total.saturating_add(xsw.nblks.max(0) as u64 * 512);
        used = used.saturating_add(xsw.used.max(0) as u64 * 512);
    }
    (total, used)
}

// ---------------------------------------------------------------------------
// Disk
// ---------------------------------------------------------------------------

/// `getfsstat(2)` returns every mounted filesystem with its `struct statfs`.
/// This agent does not parse a text table: it asks the kernel directly, which
/// inside a jail answers with exactly the mounts visible to it.
///
/// Some jails (serv00 among them) hide the mount table entirely -- the call
/// returns nothing where `df(1)` still works. The jail's root then stands in:
/// one real filesystem is better than reporting zero capacity.
fn real_mount_points() -> Vec<String> {
    // A generous buffer: 256 mounts covers any jail. The call names how many
    // it filled; a truncated answer (a negative return is ENOMEM) would have
    // to grow the buffer, which no serv00 jail reaches.
    let statfs_size = std::mem::size_of::<libc::statfs>();
    let mut buf = vec![0u8; statfs_size * 256];
    let n = unsafe { libc::getfsstat(buf.as_mut_ptr().cast(), buf.len() as libc::c_long, libc::MNT_WAIT) };
    if n <= 0 {
        return vec!["/".to_owned()];
    }
    let rows: &[libc::statfs] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), n as usize) };
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for row in rows {
        let fstype = f2s(&row.f_fstypename);
        if skip_fstype(&fstype) {
            continue;
        }
        let mount = f2s(&row.f_mntonname);
        // Deduplicate: several mounts on one point leave only the last visible
        // one, which is what statvfs below answers for. getfsstat lists in
        // mount order.
        if seen.contains(&mount) {
            continue;
        }
        // The device path is unused for the skip decision (jails mount real
        // storage under /, devfs-style entries were excluded by type) but the
        // dedup key for ZFS datasets matters: f_mntfromname for a dataset is
        // pool/dataset and the pool is the shared backing.
        let from = f2s(&row.f_mntfromname);
        if fstype == "zfs" {
            let key = from.split('/').next().unwrap_or(&from).to_owned();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
        } else {
            seen.push(mount.clone());
        }
        out.push(mount);
    }
    out
}

fn f2s(f: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = f.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `used = total - free`, exactly what df reports. Blocking on the reporting
/// thread is safe because the skip list above keeps network filesystems from
/// reaching statvfs, where a dead server would hang the agent.
fn disk_usage(mounts: &[String]) -> (u64, u64) {
    let mut total = 0u64;
    let mut used = 0u64;
    for m in mounts {
        let c = match std::ffi::CString::new(m.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
            continue;
        }
        let bs = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
        total = total.saturating_add(s.f_blocks as u64 * bs);
        used = used.saturating_add((s.f_blocks - s.f_bfree) as u64 * bs);
    }
    (total, used)
}

fn skip_fstype(fstype: &str) -> bool {
    SKIP_FSTYPES.iter().any(|s| fstype == *s || fstype.starts_with(s.trim()))
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// `(name, rx bytes, tx bytes)` for every interface with data counters, from
/// getifaddrs(3), unfiltered. FreeBSD attaches a `struct if_data` to each
/// AF_LINK address record; ifi_ibytes/ifi_obytes are the kernel's lifetime
/// counters.
///
/// In a non-VNET jail the list is the host's: the counters are host-wide
/// traffic. Reported as such by design.
fn raw_if_counters() -> Vec<(String, u64, u64)> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = addrs;
    while !cursor.is_null() {
        let ifa = unsafe { &*cursor };
        if unsafe { (*ifa.ifa_addr).sa_family as libc::c_int } == libc::AF_LINK {
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
            // ifa_data points at struct if_data for AF_LINK records.
            let data = unsafe { &*(ifa.ifa_data as *const IfData) };
            out.push((name, data.ibytes, data.obytes));
        }
        cursor = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(addrs) };
    out
}

/// The layout of `struct if_data` (net/if.h) — the struct getifaddrs(3)
/// hangs off `ifa_data` for AF_LINK records, laid out as FreeBSD 14 defines
/// it on amd64: a byte-and-word header, then the u64 counters, bytes at
/// offsets 64 and 72. Named exactly as the header names them; the unions at
/// the tail are covered by the pad so the size matches the kernel's.
#[repr(C)]
struct IfData {
    ifi_type: u8,
    ifi_physical: u8,
    ifi_addrlen: u8,
    ifi_hdrlen: u8,
    ifi_link_state: u8,
    ifi_vhid: u8,
    ifi_datalen: u16,
    ifi_mtu: u32,
    ifi_metric: u32,
    ifi_baudrate: u64,
    ifi_ipackets: u64,
    ifi_ierrors: u64,
    ifi_opackets: u64,
    ifi_oerrors: u64,
    ifi_collisions: u64,
    ibytes: u64,
    obytes: u64,
    ifi_imcasts: u64,
    ifi_omcasts: u64,
    ifi_iqdrops: u64,
    ifi_oqdrops: u64,
    ifi_noproto: u64,
    ifi_hwassist: u64,
    // __ifi_epoch (time_t) and __ifi_lastchange (struct timeval, 16 bytes on
    // amd64): read by nothing here, sized so the total matches.
    tail: [u64; 3],
}

const _: () = {
    // 8 header bytes + 2 words + 15 u64 (baudrate through hwassist) + 24
    // bytes of tail unions = 152. A drift would mean the cast in
    // raw_if_counters reads the wrong counters; the build stops instead.
    assert!(std::mem::size_of::<IfData>() == 152);
};

fn skip_iface(name: &str) -> bool {
    SKIP_IFACES.iter().any(|p| name.starts_with(p))
}

/// Sums the kernel's lifetime byte counters of the counted interfaces, one
/// count per byte on the wire.
fn totals(counted: &[(String, u64, u64)]) -> (u64, u64) {
    counted.iter().fold((0, 0), |(rx, tx), (_, r, t)| (rx.saturating_add(*r), tx.saturating_add(*t)))
}

/// One address of each family the machine holds, public first.
fn addresses() -> (String, String) {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return (String::new(), String::new());
    }
    let mut held: Vec<IpAddr> = Vec::new();
    let mut cursor = addrs;
    while !cursor.is_null() {
        let ifa = unsafe { &*cursor };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        if !ifa.ifa_addr.is_null() && !skip_iface(&name) {
            let family = unsafe { (*ifa.ifa_addr).sa_family };
            if family == libc::AF_INET as u16 as libc::sa_family_t {
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                held.push(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
            } else if family == libc::AF_INET6 as u16 as libc::sa_family_t {
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let addr = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                // Skip link-local: its scope id is jail-local noise.
                if !addr.is_unicast_link_local() {
                    held.push(IpAddr::V6(addr));
                }
            }
        }
        cursor = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(addrs) };
    pick(&held)
}

/// A public address before any other, then a stable v6; ties keep the
/// kernel's order.
fn pick(held: &[IpAddr]) -> (String, String) {
    let best = |v6: bool| {
        held.iter()
            .filter(|ip| ip.is_ipv6() == v6)
            .min_by_key(|ip| !is_public(**ip))
            .map_or_else(String::new, ToString::to_string)
    };
    (best(false), best(true))
}

/// Globally routable, same ranges the hub and the Linux agent apply.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xe000 == 0x2000,
    }
}

// ---------------------------------------------------------------------------
// Sockets and processes
// ---------------------------------------------------------------------------

/// TCP and UDP connection counts, host-wide (a jail shares the network stack).
///
/// The generic inpcb-list sysctls (`net.inet.tcp.pcblist`,
/// `net.inet.udp.pcblist`) return a buffer of xinpcb records whose size the
/// first four bytes name (xi_len). Walking by that self-described length is
/// how sockstat(1) counts, and works whatever the kernel pads between fields.
/// TIME_WAIT sockets carry no protocol state worth excluding: sockstat counts
/// them and so does this.
fn conn_counts() -> (u32, u32) {
    (inpcb_count("net.inet.tcp.pcblist"), inpcb_count("net.inet.udp.pcblist"))
}

fn inpcb_count(name: &str) -> u32 {
    let mut mib = [0i32; CTL_MAXNAME];
    let mut miblen = mib.len();
    let c = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    if unsafe { libc::sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut miblen) } != 0 {
        return 0;
    }
    let mut len = 0usize;
    if unsafe { libc::sysctl(mib.as_ptr(), miblen as libc::u_int, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0
        || len < 4
    {
        return 0;
    }
    let mut buf = vec![0u8; len];
    if unsafe { libc::sysctl(mib.as_ptr(), miblen as libc::u_int, buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return 0;
    }
    // The first record is a xinpgen header whose xi_len is the record size;
    // skip it, then walk self-described records to the end of the buffer.
    let mut count = 0u32;
    let mut off = 0usize;
    let mut first = true;
    while off + 4 <= len {
        let rec = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4])) as usize;
        if rec < 4 || off + rec > len {
            break;
        }
        if !first {
            count += 1;
        }
        first = false;
        off += rec;
    }
    count
}

/// Processes visible to this jail, from `kern.proc.all` -- a buffer of
/// kinfo_proc records, again self-described by ki_structsize.
fn proc_count() -> u32 {
    let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];
    let mut len = 0usize;
    if unsafe { libc::sysctl(mib.as_ptr(), 3, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0
        || len == 0
    {
        return 0;
    }
    // The table can grow between the size probe and the read; retry once with
    // a grown buffer, as ps(1) does.
    for _ in 0..2 {
        let mut buf = vec![0u8; len + 4096];
        let mut real = buf.len();
        if unsafe { libc::sysctl(mib.as_ptr(), 3, buf.as_mut_ptr().cast(), &mut real, std::ptr::null_mut(), 0) } == 0
            && real >= 4
        {
            let rec = u32::from_le_bytes(buf[0..4].try_into().unwrap_or([0; 4])) as usize;
            if rec == 0 {
                return 0;
            }
            return (real / rec) as u32;
        }
        len = len * 2;
    }
    0
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

fn cpu_info() -> (String, u32) {
    let name = sysctl_string("hw.model").unwrap_or_else(|| "unknown".into());
    let cores = sysctl_u64("kern.smp.cores").filter(|v| *v > 0).unwrap_or(1) as u32;
    (name, cores)
}

/// A jail runs on a hypervisor or on bare metal with no way to tell from
/// inside beyond the brand strings. dmesg's first line names the machine on
/// FreeBSD; `kern.vm_guest` (13.x+) states it outright.
fn virtualization() -> String {
    if let Some(v) = sysctl_string("kern.vm_guest") {
        return match v.as_str() {
            "none" => "none".into(),
            other => other.into(),
        };
    }
    "none".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_arithmetic_subtracts_reclaimable() {
        // Pinned through the real function so the formula cannot drift from
        // the assertion. The sysctls are stubbed by the caller below; here the
        // arithmetic itself is what matters.
        let page = 4096u64;
        let total = 1000 * page;
        let reclaimable = (100 + 200 + 50 + 25) * page;
        assert_eq!(total.saturating_sub(reclaimable), 625 * page);
    }

    #[test]
    fn busy_percent_needs_a_baseline_then_uses_deltas() {
        assert_eq!(busy_percent((1000, 925), (1100, 950)), 75.0);
        assert_eq!(busy_percent((1000, 925), (1100, 1025)), 0.0, "a fully idle interval is 0% busy");
        // A counter that moved backwards indicates a reboot, not 100% busy.
        assert_eq!(busy_percent((1000, 925), (500, 400)), 0.0);
        // The first call has no baseline, so it reports 0.
        assert_eq!(Collector::default().cpu_percent(), 0.0);
    }

    #[test]
    fn iface_rules_reject_malformed_entries() {
        assert!(Ifaces::parse("").is_ok());
        assert!(Ifaces::parse("em0,vtnet0").is_ok());
        assert!(Ifaces::parse("-wg0,em0").is_ok());
        assert!(Ifaces::parse("--x").is_err());
        assert!(Ifaces::parse("a b").is_err());
        assert!(Ifaces::parse(",").is_ok(), "empty entries are filtered before validation");
    }

    #[test]
    fn iface_rules_exclude_the_known_virtuals() {
        let i = Ifaces::default();
        assert!(i.counts("em0"));
        assert!(i.counts("vtnet0"));
        assert!(!i.counts("lo0"));
        assert!(!i.counts("tun0"));
        assert!(!i.counts("bridge0"));
        assert!(!i.counts("epair0a"));
        // An explicit list overrides the rules.
        let only = Ifaces::parse("bridge0").unwrap();
        assert!(only.counts("bridge0"));
        assert!(!only.counts("em0"));
        // An exclusion wins over an inclusion.
        let mixed = Ifaces::parse("em0,-em0").unwrap();
        assert!(!mixed.counts("em0"));
    }

    #[test]
    fn epoch_changes_when_the_interface_set_changes() {
        let a = epoch(1234, ["em0", "lo0"].into_iter().map(String::from));
        let b = epoch(1234, ["em0"].into_iter().map(String::from));
        let c = epoch(1234, ["lo0", "em0"].into_iter().map(String::from));
        assert_ne!(a, b, "a changed set must change the epoch");
        assert_eq!(a, c, "order does not matter, the names are sorted");
        assert!(a.starts_with("1234/"), "the boot time leads");
    }

    #[test]
    fn totals_sum_without_wrapping() {
        let counted = vec![
            ("em0".into(), u64::MAX, 5),
            ("vtnet0".into(), 1, 7),
        ];
        assert_eq!(totals(&counted), (u64::MAX, 12), "saturating, never wrapping");
    }

    #[test]
    fn the_public_test_matches_the_hubs() {
        // The hub re-derives this from the hello fields; the lists must agree.
        assert!(is_public("203.0.113.7".parse().unwrap()));
        assert!(!is_public("10.0.0.1".parse().unwrap()));
        assert!(!is_public("100.64.0.1".parse().unwrap()));
        assert!(!is_public("198.18.0.1".parse().unwrap()));
        assert!(is_public("2001:db8::1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
        assert!(!is_public("fe80::1".parse().unwrap()));
    }

    #[test]
    fn pick_prefers_public_and_v4_leaves_v6_alone() {
        let held: Vec<IpAddr> = ["10.0.0.5", "203.0.113.7", "fe80::1", "2401:db00::5"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let (v4, v6) = pick(&held);
        assert_eq!(v4, "203.0.113.7");
        assert_eq!(v6, "2401:db00::5");
    }

    #[test]
    fn ifdata_size_is_pinned_at_compile_time() {
        // The const assertion above holds the layout against FreeBSD 14's
        // struct if_data; this test documents the number it must be.
        assert_eq!(std::mem::size_of::<IfData>(), 152);
    }

    #[test]
    fn swap_and_memory_survive_a_jail_with_no_swap() {
        // The swap loop breaks on the first failing index; with the sysctl
        // absent it must return zeros, not panic.
        let (t, u) = swap();
        assert_eq!(t, 0);
        assert_eq!(u, 0);
    }
}
