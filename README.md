# net-analysis

A desktop tool that scans nearby **Wi-Fi access points**, **Bluetooth devices** and **LAN hosts**, works out what each device is, and watches for threats such as **evil-twin / spoofed APs**. Results are shown in a 3D interface with three switchable views.

Written in Rust: a headless engine plus a [Bevy](https://bevyengine.org) + egui frontend. It targets Windows first, and the code is structured so Linux can follow.

> Only scan, probe or capture on networks you own or are authorized to test.

## Status

| Milestone | Scope | State |
|---|---|---|
| **M0** | Workspace, data model, engine + simulator, CLI, 3D shell with 3 views | ✅ done |
| M1 | Windows Wi-Fi scanning (wlanapi), 802.11 IE parser | next |
| M2 | Bluetooth LE / classic | |
| M3 | LAN discovery (ARP, mDNS, SSDP, NetBIOS, port/banner probes) | |
| M4 | Guard: evil twin, downgrade, Karma, PMF, baselines, alerts | |
| M5 | Packet capture (Npcap/libpcap): DHCP/TCP fingerprints, ARP spoof, rogue DHCP | |
| M6 | Linux port (nl80211, BlueZ, rtnetlink), monitor-mode detectors | |
| M7 | Time scrubber, export, packaging, CI | |

For now, every device comes from the built-in **simulator**. It models a home mesh network, neighbouring APs, LAN hosts and BLE devices that come and go. After 20 s an **evil twin** of `HomeNet` appears: open security, a locally-administered BSSID and a just-booted TSF. The UI shows a "SIMULATED DATA" badge while the simulator is running.

## Running

Requires a stable Rust toolchain (MSVC on Windows).

```sh
# 3D app (release is much smoother)
cargo run -p na-app --release
cargo run -p na-app --release -- --extra 500      # load test with 500 extra devices
cargo run -p na-app --release -- --twin-after 0   # disable the evil twin
# Scripted tour: saves a PNG of each view, then exits (visual smoke test)
cargo run -p na-app -- --twin-after 3 --screenshot-dir shots

# Headless CLI
cargo run -p na-cli -- sim --secs 5
cargo run -p na-cli -- sim --secs 5 --json

# Tests
cargo test --workspace
```

### Controls
- **Left-drag**: orbit. **Right-drag**: pan. **Scroll**: zoom.
- **Click** a device to inspect it. **Esc** clears the selection.
- Click a source chip in the top bar to start or stop that source.

## Layout

```
crates/
  na-model/    shared types: Device, Observation, Evidence, Identity, Alert, ApInfo…
  na-engine/   tokio engine on its own thread: sources → DeviceStore → identify → (guard)
    src/sources/sim.rs        synthetic world incl. evil-twin scenario
    src/identify/classifier   noisy-OR evidence combiner → Identity
  na-cli/      `na` binary: headless JSON/table output for testing
  na-app/      Bevy + egui frontend
    src/bridge.rs   engine events → Registry resource + one entity per device
    src/views/      radar / constellation / spectrum: each only writes LayoutTargets
    src/tween.rs    eases entities toward targets, so view switches morph
    src/scene.rs    cameras, bloom, colour language, material updates
    src/ui/         top bar, device list, inspector, alerts/log, viewport overlay
```

**Design rule:** the engine owns all data. The frontend never talks to scanners. It sends `EngineCommand`s and consumes `EngineEvent`s. All three views are projections of the same registry. Selection, filters and the inspector are shared between them.

## Platform notes (for upcoming milestones)

- **Windows 11 24H2+**: Wi-Fi BSSID scan results require *Location services* to be enabled for desktop apps.
- **Packet capture**: needs [Npcap](https://npcap.com) on Windows, or libpcap with `cap_net_raw,cap_net_admin` on Linux.
- **Monitor mode** (deauth/beacon-anomaly detection) is realistically Linux-only and needs a compatible USB adapter (e.g. MT7921AU, MT7612U, AR9271).
