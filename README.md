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
| M3 | LAN discovery (ARP, mDNS, SSDP, NetBIOS, port/banner probes) | next |
| M4 | Guard: evil twin, downgrade, Karma, PMF, baselines, alerts | |
| M5 | Packet capture (Npcap/libpcap): DHCP/TCP fingerprints, ARP spoof, rogue DHCP | |
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

**Simulator.** `--sim` replaces the real scanners with a synthetic world: a home mesh, neighbours, LAN hosts and BLE devices. After 20 s an **evil twin** of `HomeNet` appears (open, locally-administered BSSID, just-booted TSF). A "SIMULATED DATA" badge shows while it runs.

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

**Linux** (build/run; Wi-Fi and Bluetooth scanning arrive in M6): Bevy needs a few system packages, and a VM needs a software Vulkan/GL driver:

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
cargo run -p na-cli -- sim --secs 5

# Tests
cargo test --workspace
```

Cross-check the scanner against the OS with `netsh wlan show networks mode=bssid` on Windows.

### Controls
- **Left-drag**: orbit. **Right-drag**: pan. **Scroll**: zoom.
- **Click** a device to inspect it. **Esc** clears the selection.
- Click a source chip in the top bar to start or stop that source. Hover a chip to see why a source is unavailable.

## Layout

```
crates/
  na-model/      shared types: Device, Observation, Evidence, Identity, Alert, ApInfo…
  na-platform/   OS access behind portable traits (blocking, raw data only)
    src/wifi/windows.rs        Native Wi-Fi API (wlanapi.dll)
    src/bluetooth/windows.rs   WinRT LE watcher + device enumeration, Win32 Classic inquiry
  na-engine/     tokio engine on its own thread: sources → DeviceStore → identify → (guard)
    src/parse/ie.rs           802.11 information-element decoder + fingerprint
    src/parse/ble_ad.rs       BLE advertising-data decoder
    src/sources/wifi.rs       Wi-Fi source (blocking scan thread, permission retry)
    src/sources/ble.rs        Bluetooth source (advert merging, connected poll, Classic inquiry)
    src/sources/sim.rs        synthetic world incl. evil-twin scenario
    src/identify/             OUI + Bluetooth SIG registries, AP and Bluetooth evidence
                              (Continuity, CDP, Fast Pair, appearance, CoD), noisy-OR classifier
  na-cli/        `na` binary: headless JSON/table output for testing
  na-app/        Bevy + egui frontend
    src/bridge.rs   engine events → Registry resource + one entity per device
    src/views/      radar / constellation / spectrum: each only writes LayoutTargets
    src/tween.rs    eases entities toward targets, so view switches morph
    src/scene.rs    cameras, bloom, colour language, material updates
    src/ui/         top bar, device list, inspector (incl. raw IEs / AD), alerts/log, overlay
scripts/         fetch-data.{ps1,sh}
```

**Design rule:** the engine owns all data. The frontend never talks to scanners. It sends `EngineCommand`s and consumes `EngineEvent`s. All three views are projections of the same registry. Selection, filters and the inspector are shared between them.

## Platform notes

- **Locally-administered BSSIDs are common and legitimate**: phone hotspots, mesh systems and multi-SSID APs use them. On its own, one is weak evidence of spoofing.
- **Bluetooth and Wi-Fi share an antenna** on most laptop cards. The default LE scan uses Windows' coexistence-friendly duty cycle. `--fast` and Classic inquiry briefly take airtime from Wi-Fi, so inquiry runs only every 90 s for 5 s.
- **Classic discovery** finds only devices that are discoverable right now: pairing mode, or a Bluetooth settings page open. Phones and headphones in normal use don't answer.
- **Packet capture**: needs [Npcap](https://npcap.com) on Windows, or libpcap with `cap_net_raw,cap_net_admin` on Linux.
- **Monitor mode** (deauth/beacon-anomaly detection) is Linux-only in practice. Check support with `netsh wlan show wirelesscapabilities` on Windows or `iw list` on Linux. A VM can't use the host's PCIe Wi-Fi card, but a **USB Wi-Fi adapter can be passed through** to it (e.g. MT7921AU, MT7612U, AR9271).
