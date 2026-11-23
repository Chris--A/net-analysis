use std::net::Ipv4Addr;

use na_model::MacAddr;
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, NlnsDelay, NlnsPermanent, NlnsProbe, NlnsReachable, NlnsStale,
};

use super::{NetError, Neighbor, NeighborState};

/// A REG_SZ value under HKEY_LOCAL_MACHINE.
pub fn reg_sz(subkey: &str, value: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    let key: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let val: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let mut buf = [0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: buffers are NUL-terminated / sized as declared.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

// windows-sys keeps the SDK's CamelCase constant names.
#[allow(non_upper_case_globals)]
pub fn neighbors() -> Result<Vec<Neighbor>, NetError> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: on success the OS allocates `table`, and FreeMibTable releases it below.
    let rc = unsafe { GetIpNetTable2(AF_INET, &mut table) };
    if rc != 0 || table.is_null() {
        return Err(NetError::Os { code: rc, context: "GetIpNetTable2" });
    }
    let mut out = Vec::new();
    // SAFETY: NumEntries rows follow the header in one allocation.
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts(std::ptr::addr_of!((*table).Table).cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2>(), n);
        for row in rows {
            let state = match row.State {
                NlnsReachable | NlnsDelay | NlnsProbe => NeighborState::Reachable,
                NlnsStale => NeighborState::Stale,
                NlnsPermanent => NeighborState::Permanent,
                _ => continue, // incomplete or unreachable: no MAC
            };
            if row.PhysicalAddressLength != 6 || row.Address.si_family != AF_INET {
                continue;
            }
            let ip = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&row.PhysicalAddress[..6]);
            out.push(Neighbor { ip, mac: MacAddr(mac), interface_index: row.InterfaceIndex, state });
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}
