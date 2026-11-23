//! Windows Bluetooth via WinRT (LE advertisements, connected LE devices) and
//! Win32 `bluetoothapis.dll` (classic inquiry, paired/connected classic devices).
//!
//! Desktop apps need no capability or admin rights for any of this. The WinRT
//! factory initialises COM (multithreaded) on first use from any thread.

use std::time::Duration;

use na_model::MacAddr;
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementScanParameters,
    BluetoothLEAdvertisementType,
    BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementWatcherStoppedEventArgs,
    BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::{
    BluetoothAdapter, BluetoothAddressType, BluetoothConnectionStatus, BluetoothError,
    BluetoothLEDevice,
};
use windows::Devices::Enumeration::DeviceInformation;
use windows::Devices::Radios::RadioState;
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::DataReader;
use windows_sys::Win32::Devices::Bluetooth::{
    BLUETOOTH_DEVICE_INFO, BLUETOOTH_DEVICE_SEARCH_PARAMS, BluetoothFindDeviceClose,
    BluetoothFindFirstDevice, BluetoothFindNextDevice,
};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, FILETIME, GetLastError, SYSTEMTIME};
use windows_sys::Win32::System::Time::SystemTimeToFileTime;

use super::{
    AdSection, AdapterInfo, AddressKind, BtError, ClassicDevice, ConnectedLe, LeCallback, LeEvent,
    LeScanner, RawAdvert, ScanDuty,
};

/// 100 ns ticks between 1601-01-01 and 1970-01-01, in milliseconds.
const FILETIME_UNIX_OFFSET_MS: u64 = 11_644_473_600_000;

fn os(context: &'static str) -> impl FnOnce(windows::core::Error) -> BtError {
    move |e| BtError::Os { code: e.code().0, context }
}

pub fn adapter_info() -> Result<AdapterInfo, BtError> {
    let op = BluetoothAdapter::GetDefaultAsync().map_err(os("BluetoothAdapter::GetDefaultAsync"))?;
    // A machine without Bluetooth completes with a null adapter, which surfaces as an error.
    let adapter = op.join().map_err(|_| BtError::NoAdapter)?;
    let radio_on = adapter
        .GetRadioAsync()
        .and_then(|op| op.join())
        .and_then(|r| r.State())
        .map(|s| s == RadioState::On)
        .unwrap_or(true); // radio state unknown: let the scan itself report problems
    Ok(AdapterInfo {
        low_energy: adapter.IsLowEnergySupported().unwrap_or(false),
        classic: adapter.IsClassicSupported().unwrap_or(false),
        radio_on,
    })
}

fn map_bt_error(e: BluetoothError) -> BtError {
    match e {
        BluetoothError::RadioNotAvailable => BtError::RadioOff,
        BluetoothError::ResourceInUse => BtError::Unavailable("Bluetooth radio is in use by another app".into()),
        BluetoothError::DisabledByPolicy => BtError::Unavailable("Bluetooth is disabled by policy".into()),
        BluetoothError::DisabledByUser => BtError::Unavailable("Bluetooth access is disabled in Settings".into()),
        BluetoothError::ConsentRequired => BtError::Unavailable("Bluetooth access needs user consent".into()),
        BluetoothError::NotSupported | BluetoothError::TransportNotSupported => {
            BtError::Unsupported("this adapter can't scan for LE advertisements".into())
        }
        other => BtError::Unavailable(format!("Bluetooth scan stopped (error {})", other.0)),
    }
}

fn address_kind(t: windows::core::Result<BluetoothAddressType>) -> AddressKind {
    match t {
        Ok(BluetoothAddressType::Public) => AddressKind::Public,
        Ok(BluetoothAddressType::Random) => AddressKind::Random,
        _ => AddressKind::Unknown,
    }
}

pub struct WinLeScanner {
    watcher: BluetoothLEAdvertisementWatcher,
    tokens: Option<(i64, i64)>,
}

impl WinLeScanner {
    pub fn open(duty: ScanDuty) -> Result<Self, BtError> {
        let watcher = BluetoothLEAdvertisementWatcher::new().map_err(os("BluetoothLEAdvertisementWatcher::new"))?;
        // Active scanning requests scan responses, which carry most device names.
        watcher
            .SetScanningMode(BluetoothLEScanningMode::Active)
            .map_err(os("SetScanningMode"))?;
        // Bluetooth 5 extended advertising (Windows 10 2004+). Older builds simply ignore it.
        let _ = watcher.SetAllowExtendedAdvertisements(true);
        // Explicit scan parameters need Windows 11 24H2+; older builds keep their default.
        let params = match duty {
            ScanDuty::Balanced => BluetoothLEAdvertisementScanParameters::CoexistenceOptimized(),
            ScanDuty::LowLatency => BluetoothLEAdvertisementScanParameters::LowLatency(),
        };
        if let Ok(p) = params {
            let _ = watcher.SetScanParameters(&p);
        }
        Ok(Self { watcher, tokens: None })
    }
}

impl LeScanner for WinLeScanner {
    fn start(&mut self, on_event: LeCallback) -> Result<(), BtError> {
        self.stop();
        let cb = on_event.clone();
        let received = self
            .watcher
            .Received(&TypedEventHandler::new(
                move |_, args: windows::core::Ref<BluetoothLEAdvertisementReceivedEventArgs>| {
                    if let Some(args) = args.as_ref()
                        && let Ok(adv) = convert_advert(args)
                    {
                        cb(LeEvent::Advert(adv));
                    }
                    Ok(())
                },
            ))
            .map_err(os("watcher.Received"))?;
        let cb = on_event;
        let stopped = self
            .watcher
            .Stopped(&TypedEventHandler::new(
                move |_, args: windows::core::Ref<BluetoothLEAdvertisementWatcherStoppedEventArgs>| {
                    let err = args
                        .as_ref()
                        .and_then(|a| a.Error().ok())
                        .unwrap_or(BluetoothError::OtherError);
                    cb(LeEvent::Stopped(map_bt_error(err)));
                    Ok(())
                },
            ))
            .map_err(os("watcher.Stopped"))?;
        self.tokens = Some((received, stopped));
        self.watcher.Start().map_err(os("watcher.Start"))
    }

    fn stop(&mut self) {
        if let Some((received, stopped)) = self.tokens.take() {
            // Unhook first so our own Stop() isn't reported as a failure.
            let _ = self.watcher.RemoveStopped(stopped);
            let _ = self.watcher.RemoveReceived(received);
            let _ = self.watcher.Stop();
        }
    }
}

impl Drop for WinLeScanner {
    fn drop(&mut self) {
        self.stop();
    }
}

fn convert_advert(args: &BluetoothLEAdvertisementReceivedEventArgs) -> windows::core::Result<RawAdvert> {
    let adv_type = args.AdvertisementType().ok();
    let connectable = args.IsConnectable().unwrap_or(matches!(
        adv_type,
        Some(BluetoothLEAdvertisementType::ConnectableUndirected | BluetoothLEAdvertisementType::ConnectableDirected)
    ));
    let scan_response = args
        .IsScanResponse()
        .unwrap_or(adv_type == Some(BluetoothLEAdvertisementType::ScanResponse));
    let received_at_ms = args
        .Timestamp()
        .ok()
        .and_then(|t| u64::try_from(t.UniversalTime).ok())
        .map(|ticks| (ticks / 10_000).saturating_sub(FILETIME_UNIX_OFFSET_MS))
        .unwrap_or_else(na_model::now_millis);

    let list = args.Advertisement()?.DataSections()?;
    let mut sections = Vec::with_capacity(list.Size()? as usize);
    for i in 0..list.Size()? {
        let s = list.GetAt(i)?;
        let buf = s.Data()?;
        let mut data = vec![0u8; buf.Length()? as usize];
        if !data.is_empty() {
            DataReader::FromBuffer(&buf)?.ReadBytes(&mut data)?;
        }
        sections.push(AdSection { ad_type: s.DataType()?, data });
    }

    Ok(RawAdvert {
        address: MacAddr::from_u64(args.BluetoothAddress()?),
        address_kind: address_kind(args.BluetoothAddressType()),
        rssi_dbm: args.RawSignalStrengthInDBm()?,
        tx_power_dbm: args.TransmitPowerLevelInDBm().ok().and_then(|r| r.Value().ok()),
        connectable,
        scan_response,
        sections,
        received_at_ms,
    })
}

pub fn connected_le_devices() -> Result<Vec<ConnectedLe>, BtError> {
    let selector = BluetoothLEDevice::GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus::Connected)
        .map_err(os("BluetoothLEDevice::GetDeviceSelectorFromConnectionStatus"))?;
    let infos = DeviceInformation::FindAllAsyncAqsFilter(&selector)
        .and_then(|op| op.join())
        .map_err(os("DeviceInformation::FindAllAsync"))?;
    let mut out = Vec::new();
    for info in &infos {
        let Ok(id) = info.Id() else { continue };
        let Ok(dev) = BluetoothLEDevice::FromIdAsync(&id).and_then(|op| op.join()) else {
            continue;
        };
        if let Ok(addr) = dev.BluetoothAddress() {
            let name = dev
                .Name()
                .ok()
                .or_else(|| info.Name().ok())
                .map(|h| h.to_string_lossy())
                .filter(|n| !n.is_empty());
            out.push(ConnectedLe {
                address: MacAddr::from_u64(addr),
                address_kind: address_kind(dev.BluetoothAddressType()),
                name,
                appearance: dev.Appearance().and_then(|a| a.RawValue()).ok().filter(|&v| v != 0),
            });
        }
        let _ = dev.Close();
    }
    Ok(out)
}

pub fn classic_devices(inquiry: Option<Duration>) -> Result<Vec<ClassicDevice>, BtError> {
    // The inquiry timeout is in units of 1.28 s (1..=48).
    let multiplier = inquiry.map_or(0, |d| (d.as_secs_f32() / 1.28).round().clamp(1.0, 48.0) as u8);
    let params = BLUETOOTH_DEVICE_SEARCH_PARAMS {
        dwSize: size_of::<BLUETOOTH_DEVICE_SEARCH_PARAMS>() as u32,
        fReturnAuthenticated: 1,
        fReturnRemembered: 1,
        fReturnUnknown: 1,
        fReturnConnected: 1,
        fIssueInquiry: i32::from(inquiry.is_some()),
        cTimeoutMultiplier: multiplier,
        hRadio: std::ptr::null_mut(),
    };
    let new_info = || BLUETOOTH_DEVICE_INFO { dwSize: size_of::<BLUETOOTH_DEVICE_INFO>() as u32, ..Default::default() };

    let mut info = new_info();
    // SAFETY: both structs are initialised with their dwSize; the handle is closed below.
    let find = unsafe { BluetoothFindFirstDevice(&params, &mut info) };
    if find.is_null() {
        let code = unsafe { GetLastError() };
        return if code == ERROR_NO_MORE_ITEMS {
            Ok(Vec::new())
        } else {
            Err(BtError::Os { code: code as i32, context: "BluetoothFindFirstDevice" })
        };
    }
    let mut out = Vec::new();
    loop {
        out.push(convert_classic(&info));
        info = new_info();
        // SAFETY: `find` is a valid search handle until BluetoothFindDeviceClose.
        if unsafe { BluetoothFindNextDevice(find, &mut info) } == 0 {
            break;
        }
    }
    unsafe { BluetoothFindDeviceClose(find) };
    Ok(out)
}

fn convert_classic(info: &BLUETOOTH_DEVICE_INFO) -> ClassicDevice {
    let len = info.szName.iter().position(|&c| c == 0).unwrap_or(info.szName.len());
    let name = String::from_utf16_lossy(&info.szName[..len]).trim().to_owned();
    // SAFETY: every bit pattern is a valid u64.
    let addr = unsafe { info.Address.Anonymous.ullLong };
    ClassicDevice {
        address: MacAddr::from_u64(addr),
        name: (!name.is_empty()).then_some(name),
        class_of_device: info.ulClassofDevice,
        connected: info.fConnected != 0,
        remembered: info.fRemembered != 0,
        authenticated: info.fAuthenticated != 0,
        last_seen_ms: systemtime_to_unix_ms(&info.stLastSeen),
    }
}

/// The OS stores Bluetooth timestamps in UTC.
fn systemtime_to_unix_ms(st: &SYSTEMTIME) -> Option<u64> {
    if st.wYear == 0 {
        return None;
    }
    let mut ft = FILETIME::default();
    // SAFETY: plain struct conversion.
    if unsafe { SystemTimeToFileTime(st, &mut ft) } == 0 {
        return None;
    }
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    (ticks / 10_000).checked_sub(FILETIME_UNIX_OFFSET_MS)
}
