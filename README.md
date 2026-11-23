# net-analysis

A desktop tool that scans nearby **Wi-Fi access points**, **Bluetooth devices** and **LAN hosts**, works out what each device is, and watches for threats such as **evil-twin / spoofed APs**. Results are shown in a 3D interface with three switchable views.

Written in Rust: a headless engine plus a [Bevy](https://bevyengine.org) + egui frontend. It targets Windows first, and the code is structured so Linux can follow.

> Only scan, probe or capture on networks you own or are authorized to test.

## Status

| Milestone | Scope | State |
|---|---|---|
| **M0** | Workspace, data model, engine + simulator, CLI, 3D shell with 3 views | ✅ done |
| **M1** | Windows Wi-Fi scanning (wlanapi), 802.11 IE parser, OUI vendor lookup | ✅ done |
| **M2** | Bluetooth LE + Classic scanning, AD parser, vendor-protocol decoders | ✅ done |
| **M3** | LAN discovery: ARP table, mDNS, SSDP/UPnP, NetBIOS, opt-in port/banner probes | ✅ done |
| **M4** | Guard: trusted-network baselines, evil twin, downgrade, Karma, PMF, alerts | ✅ done |
| M5 | Packet capture (Npcap/libpcap): DHCP/TCP fingerprints, ARP spoof, rogue DHCP | next |
| M6 | Linux port (nl80211, BlueZ, rtnetlink), monitor-mode detectors | |
| M7 | Time scrubber, export, packaging, CI | |

**Wi-Fi (M1).** Each AP is decoded from its beacon/probe information elements:
- security (WPA3/WPA2/WPA/WEP/OWE/Enterprise) and PMF
- WPS make/model/device type
- Wi-Fi generation and channel width (HT/VHT/HE/EHT)
- BSS load, country and vendor IEs
- a stable capability fingerprint
- TSF radio uptime. Apple's randomized TSF is detected and ignored.

Vendor identity combines the BSSID OUI, WPS and brand vendor IEs.

**Bluetooth (M2).** Three kinds of sighting go through one portable decoder:
- LE advertisements. Each device's advert and scan response are merged, and RSSI is averaged into one update per second.
- Paired LE devices connected to this PC. Connected peripherals stop advertising, so the OS supplies their name and appearance.
- Classic devices: connected ones every 10 s, plus a short discovery inquiry every 90 s.

Identification uses:
- **Apple Continuity**: AirPods/Beats model, Watch, Handoff/Nearby, Find My "separated" trackers.
- **Microsoft CDP** (Windows/Xbox/Android device type) and **Swift Pair**.
- **Google Fast Pair**, **Eddystone / Find Hub** trackers, Tile, Chipolo and SmartTag.
- GAP **appearance** and Classic **Class of Device**.
- SIG **company IDs** and member UUIDs.
- The OUI of public addresses, and name patterns.

Address types are tracked: public, random static, or rotating private (RPA/NRPA). Rotating devices get a new identity every ~15 min, which is expected, not suspicious.

**LAN (M3).** Discovery is passive or uses standard protocols by default:
- the OS neighbor (ARP) table
- this machine (maker and model read from firmware) and the default gateway
- **mDNS / DNS-SD** queries, which collect service types, instance names and TXT records
- **SSDP** plus each device's own **UPnP description**: name, manufacturer, model, device type
- **NetBIOS** name queries to hosts already seen

**Active probes** are opt-in: the top-bar switch with a confirmation, or `na lan --active`. They nudge every address on the local subnets and check a short fixed list of TCP ports on each host, reading SSH/FTP greetings and HTTP `Server` headers and titles. Only use them on networks you own or are authorized to test.

Identification uses:
- self-descriptions (UPnP fields, Chromecast `md`/`fn`, Apple model identifiers, IPP printer `ty`)
- service types
- host names
- NetBIOS
- banners and ports
- the OUI

A host first seen only by IP merges into its MAC-keyed device once ARP resolves it. A LAN MAC that sits next to a BSSID (the router, or a phone hotspot) is linked to that AP.

**Guard (M4).** Every access point is checked against a baseline of your **trusted networks**. Trust comes from three places:
- your **saved Wi-Fi profiles**, which give each network's expected security. Only names and security settings are read, never keys.
- **connecting with a password**. Only an AP that knows the key can complete a WPA2/WPA3/Enterprise handshake, so the connected AP and its sibling radios (MACs next to it, same settings) are learned automatically. Connecting to an open network proves nothing, so it teaches nothing.
- **you**, with *Trust this access point* / *Trust "network"* in the inspector. Trusting a flagged AP asks first.

Baselines are stored in `%LOCALAPPDATA%\net-analysis\guard.json` (`~/.local/share/net-analysis/` on Linux). The simulator never touches that file.

| Detector | Severity |
|---|---|
| **Security downgrade**: a trusted name advertised open, or WPA2 where the network is WPA3-only | Critical |
| **Karma test**: every 10 minutes (or *Run Karma test*), probe for a random name like `Lounge-3F9A1C`; anything that answers is a Karma/MANA rogue AP | Critical |
| **Evil twin**: an unknown BSSID for a trusted network whose vendor prefix differs, that clones a known BSSID with the local bit flipped, or whose capability fingerprint differs from the known APs on that band | High (Medium if only the fingerprint differs) |
| **One radio, several names**: one BSSID announcing 2+ (Medium) or 3+ (High) network names | Medium / High |
| **No 802.11w** where the known APs protect management frames | Medium |
| **Mixed security** (no baseline): an open AP sharing a name with password-protected ones | Medium |

A locally-administered BSSID and a just-booted radio (TSF uptime) only *corroborate*: they add weight and explanation to a real finding but never raise an alert on their own, because phone hotspots and mesh systems do both legitimately.

Each AP gets a risk score (noisy-OR of its findings) and its findings in plain language. Risky devices pulse red and wear a halo in every view. An alert fires once per device, and again only if it gets worse. The bottom panel shows the guard status, a timeline of alerts, and each alert's reasoning.

**Simulator.** `--sim` replaces the real scanners with a synthetic world: a home mesh, neighbours, LAN hosts and BLE devices. After 20 s an **evil twin** of `HomeNet` appears (open, locally-administered BSSID, just-booted TSF). After 5 s a **Karma AP** starts cycling through public network names and answers the guard's decoy probes. A "SIMULATED DATA" badge shows while it runs.

## Setup

Requires a stable Rust toolchain (MSVC on Windows). Then fetch the reference data, the IEEE OUI registry and Bluetooth SIG assigned numbers (git-ignored):

```sh
pwsh scripts/fetch-data.ps1     # Windows
sh scripts/fetch-data.sh        # Linux / macOS
```

**Windows 11 24H2+ Wi-Fi scanning** needs all three switches under *Settings → Privacy & security → Location*:
1. **Location services**
2. **Let apps access your location**
3. **Let desktop apps access your location**

If any is off, the Wi-Fi source shows *unavailable* with this hint. It retries every few seconds, so scanning starts as soon as the switches are on.

**Bluetooth** needs no permission or admin rights on Windows, just Bluetooth turned on. If it's off, the source shows *unavailable* and resumes when it comes back.

**LAN discovery** needs no admin rights. Windows Firewall's default "allow unicast response to multicast" setting lets mDNS and SSDP replies through.

**Linux** (build/run; LAN discovery already works; Wi-Fi and Bluetooth scanning arrive in M6): Bevy needs a few system packages, and a VM needs a software Vulkan/GL driver:

```sh
sudo apt install build-essential pkg-config libudev-dev libasound2-dev \
                 libwayland-dev libxkbcommon-dev mesa-vulkan-drivers
# If the window fails to create a GPU surface in a VM, try:  WGPU_BACKEND=gl
```

## Running

```sh
# 3D app (release is much smoother)
cargo run -p na-app --release                     # real scanners
cargo run -p na-app --release -- --sim            # simulator instead
cargo run -p na-app --release -- --sim --extra 500     # load test
# Scripted tour: saves a PNG of each view, then exits (visual smoke test)
cargo run -p na-app -- --sim --twin-after 3 --screenshot-dir shots

# Headless CLI
cargo run -p na-cli -- wifi                       # scan APs (table)
cargo run -p na-cli -- wifi --secs 15 --json
cargo run -p na-cli -- ble                        # LE + Classic devices (15 s, one inquiry)
cargo run -p na-cli -- ble --secs 30 --fast       # continuous scan: more adverts, costs Wi-Fi airtime
cargo run -p na-platform --example bt_probe 10 inquiry   # raw platform output, no decoding
cargo run -p na-cli -- lan                        # LAN hosts (passive + standard discovery)
cargo run -p na-cli -- lan --secs 30 --active     # + subnet sweep and port/banner probes (your networks only)
cargo run -p na-platform --example net_probe      # interfaces, gateway, ARP table
cargo run -p na-cli -- guard                      # trusted networks, Karma test, findings (20 s)
cargo run -p na-cli -- guard --sim                # same against the simulated evil twin + Karma AP
cargo run -p na-cli -- sim --secs 5

# Tests
cargo test --workspace
```

Cross-check the scanner against the OS with `netsh wlan show networks mode=bssid` on Windows.

### Controls
- **Left-drag**: orbit. **Right-drag**: pan. **Scroll**: zoom.
- **Click** a device to inspect it. **Esc** clears the selection.
- Click a source chip in the top bar to start or stop that source. Hover a chip to see why a source is unavailable.
- **Active probes** in the top bar turns LAN probing on, after a confirmation, and off again.
- Click an alert (or its dot on the timeline) to select the device and expand the alert's reasoning.
- **Run Karma test** in the bottom panel runs the test immediately.

## Layout

```
crates/
  na-model/      shared types: Device, Observation, Evidence, Identity, Alert, ApInfo…
  na-platform/   OS access behind portable traits (blocking, raw data only)
    src/wifi/windows.rs        Native Wi-Fi API (wlanapi.dll)
    src/bluetooth/windows.rs   WinRT LE watcher + device enumeration, Win32 Classic inquiry
    src/net/                   interfaces/gateway (netdev), ARP table (GetIpNetTable2, /proc/net/arp), SMBIOS
  na-engine/     tokio engine on its own thread: sources → DeviceStore → identify → guard
    src/parse/ie.rs           802.11 information-element decoder + fingerprint
    src/parse/ble_ad.rs       BLE advertising-data decoder
    src/parse/{dns,upnp,netbios}.rs   mDNS/DNS-SD, SSDP + UPnP description + HTTP, NBSTAT
    src/sources/wifi.rs       Wi-Fi source (blocking scan thread, permission retry)
    src/sources/ble.rs        Bluetooth source (advert merging, connected poll, Classic inquiry)
    src/sources/lan/          LAN source: host table, discovery rounds, opt-in sweep/probes
    src/sources/sim.rs        synthetic world incl. evil-twin scenario
    src/identify/             OUI + Bluetooth SIG registries, AP and Bluetooth evidence
                              (Continuity, CDP, Fast Pair, appearance, CoD), LAN rules
                              (UPnP, TXT, services, banners, host names), noisy-OR classifier
    src/guard/                baselines (JSON + saved-profile import), AP detectors,
                              Karma test, risk scores and alerts
  na-cli/        `na` binary: headless JSON/table output for testing
  na-app/        Bevy + egui frontend
    src/bridge.rs   engine events → Registry resource + one entity per device
    src/views/      radar / constellation / spectrum: each only writes LayoutTargets
    src/tween.rs    eases entities toward targets, so view switches morph
    src/scene.rs    cameras, bloom, colour language, material updates, risk halos
    src/ui/         top bar, device list, inspector (incl. raw IEs / AD, guard), alerts/timeline/log, overlay
scripts/         fetch-data.{ps1,sh}
```

**Design rule:** the engine owns all data. The frontend never talks to scanners. It sends `EngineCommand`s and consumes `EngineEvent`s. All three views are projections of the same registry. Selection, filters and the inspector are shared between them.

## Platform notes

- **Locally-administered BSSIDs are common and legitimate**: phone hotspots, mesh systems and multi-SSID APs use them. On its own, one is weak evidence of spoofing.
- **The Karma test** sends an ordinary directed probe request (what every phone does for its saved networks), so it's fine on any network. Some drivers ignore directed scans; a test that couldn't send is reported as *couldn't run*, never as *clean*.
- **A perfect clone** (same BSSID, same security and capabilities) is indistinguishable from beacons alone. Packet capture (M5) and monitor mode (M6) add the gateway, DHCP, and deauth/sequence checks that can catch one.
- **Bluetooth and Wi-Fi share an antenna** on most laptop cards. The default LE scan uses Windows' coexistence-friendly duty cycle. `--fast` and Classic inquiry briefly take airtime from Wi-Fi, so inquiry runs only every 90 s for 5 s.
- **Classic discovery** finds only devices that are discoverable right now: pairing mode, or a Bluetooth settings page open. Phones and headphones in normal use don't answer.
- **Packet capture**: needs [Npcap](https://npcap.com) on Windows, or libpcap with `cap_net_raw,cap_net_admin` on Linux.
- **Monitor mode** (deauth/beacon-anomaly detection) is Linux-only in practice. Check support with `netsh wlan show wirelesscapabilities` on Windows or `iw list` on Linux. A VM can't use the host's PCIe Wi-Fi card, but a **USB Wi-Fi adapter can be passed through** to it (e.g. MT7921AU, MT7612U, AR9271).
