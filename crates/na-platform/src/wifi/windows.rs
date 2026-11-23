//! Windows backend: the Native Wi-Fi API (`wlanapi.dll`).
//!
//! On Windows 11 24H2 and later, BSS data is location-gated. Calls fail with
//! `ERROR_ACCESS_DENIED` unless Location services, "Let apps access your
//! location" and "Let desktop apps access your location" are all on.

use std::ffi::c_void;
use std::ptr;

use na_model::MacAddr;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WiFi::{
    DOT11_SSID, WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO,
    WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
    WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface, WlanScan, dot11_BSS_type_any,
    wlan_interface_state_connected, wlan_intf_opcode_current_connection,
};
use windows_sys::core::GUID;

use super::{RawBss, WifiError, WifiInterface, WifiScanner};

const LOCATION_HINT: &str = "Windows denied access to Wi-Fi scan data. Enable Settings → Privacy & \
security → Location: 'Location services', 'Let apps access your location' and 'Let desktop apps \
access your location'.";

/// Milliseconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_OFFSET_MS: u64 = 11_644_473_600_000;

pub struct WlanScanner {
    handle: HANDLE,
}

impl WlanScanner {
    pub fn open() -> Result<Self, WifiError> {
        let mut negotiated = 0u32;
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: valid out-pointers; version 2 = Vista+ API.
        check(
            unsafe { WlanOpenHandle(2, ptr::null(), &mut negotiated, &mut handle) },
            "WlanOpenHandle",
        )?;
        Ok(Self { handle })
    }

    fn enum_interfaces(&self) -> Result<Vec<(GUID, String)>, WifiError> {
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
        // SAFETY: valid handle and out-pointer. The list is freed by WlanMem.
        check(
            unsafe { WlanEnumInterfaces(self.handle, ptr::null(), &mut list) },
            "WlanEnumInterfaces",
        )?;
        let list = WlanMem(list);
        // SAFETY: the API guarantees dwNumberOfItems entries follow the header.
        unsafe {
            let n = (*list.0).dwNumberOfItems as usize;
            let first = ptr::addr_of!((*list.0).InterfaceInfo).cast::<WLAN_INTERFACE_INFO>();
            Ok((0..n)
                .map(|i| {
                    let info = &*first.add(i);
                    (info.InterfaceGuid, wide_to_string(&info.strInterfaceDescription))
                })
                .collect())
        }
    }

    fn connected_bssid(&self, guid: &GUID) -> Option<MacAddr> {
        let mut size = 0u32;
        let mut data: *mut c_void = ptr::null_mut();
        // SAFETY: valid handle/guid and out-pointers. Fails harmlessly when not connected.
        let rc = unsafe {
            WlanQueryInterface(
                self.handle,
                guid,
                wlan_intf_opcode_current_connection,
                ptr::null(),
                &mut size,
                &mut data,
                ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS || data.is_null() {
            return None;
        }
        let mem = WlanMem(data.cast::<WLAN_CONNECTION_ATTRIBUTES>());
        // SAFETY: on success the API returned a WLAN_CONNECTION_ATTRIBUTES.
        let attrs = unsafe { &*mem.0 };
        (attrs.isState == wlan_interface_state_connected)
            .then_some(MacAddr(attrs.wlanAssociationAttributes.dot11Bssid))
    }

    fn bss_for(&self, guid: &GUID, description: &str, out: &mut Vec<RawBss>) -> Result<(), WifiError> {
        let mut list: *mut WLAN_BSS_LIST = ptr::null_mut();
        // SAFETY: valid handle/guid/out-pointer. A null SSID means "all BSSs" (bSecurityEnabled ignored).
        check(
            unsafe {
                WlanGetNetworkBssList(
                    self.handle,
                    guid,
                    ptr::null(),
                    dot11_BSS_type_any,
                    0,
                    ptr::null(),
                    &mut list,
                )
            },
            "WlanGetNetworkBssList",
        )?;
        let list = WlanMem(list);
        // SAFETY: dwNumberOfItems entries follow the header. Each entry's IE blob lives
        // at entry + ulIeOffset for ulIeSize bytes, inside the same allocation.
        unsafe {
            let n = (*list.0).dwNumberOfItems as usize;
            let total = (*list.0).dwTotalSize as usize;
            let base = list.0.cast::<u8>();
            let first = ptr::addr_of!((*list.0).wlanBssEntries).cast::<WLAN_BSS_ENTRY>();
            for i in 0..n {
                let entry = first.add(i);
                let e = &*entry;
                let ie_start = entry.cast::<u8>().add(e.ulIeOffset as usize);
                let in_bounds = (ie_start as usize + e.ulIeSize as usize) <= base as usize + total;
                let ies = if in_bounds {
                    std::slice::from_raw_parts(ie_start, e.ulIeSize as usize).to_vec()
                } else {
                    Vec::new()
                };
                let ssid_len = (e.dot11Ssid.uSSIDLength as usize).min(32);
                out.push(RawBss {
                    interface: description.to_owned(),
                    ssid: e.dot11Ssid.ucSSID[..ssid_len].to_vec(),
                    bssid: MacAddr(e.dot11Bssid),
                    rssi_dbm: e.lRssi,
                    frequency_khz: e.ulChCenterFrequency,
                    beacon_interval_tu: e.usBeaconPeriod,
                    capability: e.usCapabilityInformation,
                    tsf_us: e.ullTimestamp,
                    received_at_ms: filetime_to_unix_ms(e.ullHostTimestamp),
                    ies,
                });
            }
        }
        Ok(())
    }
}

impl WifiScanner for WlanScanner {
    fn interfaces(&mut self) -> Result<Vec<WifiInterface>, WifiError> {
        Ok(self
            .enum_interfaces()?
            .into_iter()
            .map(|(guid, description)| WifiInterface {
                id: guid_to_string(&guid),
                connected_bssid: self.connected_bssid(&guid),
                description,
            })
            .collect())
    }

    fn trigger_scan(&mut self, ssid: Option<&[u8]>) -> Result<(), WifiError> {
        let interfaces = self.enum_interfaces()?;
        if interfaces.is_empty() {
            return Err(WifiError::NoInterface);
        }
        let dot11 = ssid.map(|s| {
            let mut d = DOT11_SSID { uSSIDLength: s.len().min(32) as u32, ucSSID: [0; 32] };
            d.ucSSID[..d.uSSIDLength as usize].copy_from_slice(&s[..d.uSSIDLength as usize]);
            d
        });
        let ssid_ptr = dot11.as_ref().map_or(ptr::null(), |d| d as *const DOT11_SSID);
        for (guid, _) in &interfaces {
            // SAFETY: valid handle/guid. ssid_ptr is null or points to a live DOT11_SSID.
            check(
                unsafe { WlanScan(self.handle, guid, ssid_ptr, ptr::null(), ptr::null()) },
                "WlanScan",
            )?;
        }
        Ok(())
    }

    fn bss_list(&mut self) -> Result<Vec<RawBss>, WifiError> {
        let interfaces = self.enum_interfaces()?;
        if interfaces.is_empty() {
            return Err(WifiError::NoInterface);
        }
        let mut out = Vec::new();
        for (guid, description) in &interfaces {
            self.bss_for(guid, description, &mut out)?;
        }
        Ok(out)
    }
}

impl Drop for WlanScanner {
    fn drop(&mut self) {
        // SAFETY: handle came from WlanOpenHandle and is closed exactly once.
        unsafe { WlanCloseHandle(self.handle, ptr::null()) };
    }
}

/// Owns memory returned by the WLAN API.
struct WlanMem<T>(*mut T);

impl<T> Drop for WlanMem<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer was allocated by the WLAN API.
            unsafe { WlanFreeMemory(self.0.cast::<c_void>()) };
        }
    }
}

fn check(rc: u32, context: &'static str) -> Result<(), WifiError> {
    match rc {
        ERROR_SUCCESS => Ok(()),
        ERROR_ACCESS_DENIED => Err(WifiError::PermissionDenied(LOCATION_HINT.into())),
        ERROR_SERVICE_NOT_ACTIVE => Err(WifiError::Unsupported(
            "the WLAN AutoConfig service (wlansvc) is not running".into(),
        )),
        code => Err(WifiError::Os { code, context }),
    }
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, g.data4[0], g.data4[1], g.data4[2], g.data4[3], g.data4[4],
        g.data4[5], g.data4[6], g.data4[7]
    )
}

fn filetime_to_unix_ms(ft: u64) -> Option<u64> {
    (ft / 10_000).checked_sub(FILETIME_UNIX_OFFSET_MS).filter(|&ms| ms > 0)
}
