//! Packet capture through the system's pcap library, loaded at run time.
//!
//! | OS      | Library                                     |
//! |---------|---------------------------------------------|
//! | Windows | Npcap's `wpcap.dll` (`System32\Npcap`)       |
//! | Linux   | `libpcap.so.1` (needs `cap_net_raw,cap_net_admin`) |
//!
//! Loading at run time means no SDK is needed to build, and a machine without
//! Npcap just reports capture as unavailable.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::sync::OnceLock;

#[derive(Debug, Clone, thiserror::Error)]
pub enum CaptureError {
    /// The pcap library isn't installed.
    #[error("{0}")]
    NotInstalled(String),
    /// Installed, but this user may not capture.
    #[error("{0}")]
    PermissionDenied(String),
    #[error("no capture device matches interface {0}")]
    NoDevice(String),
    #[error("{0}")]
    Failed(String),
}

/// A capture device as pcap names it.
#[derive(Clone, Debug)]
pub struct CaptureDevice {
    /// `\Device\NPF_{GUID}` on Windows, the interface name on Linux.
    pub name: String,
    pub description: Option<String>,
}

pub struct Packet<'a> {
    /// Capture time, Unix milliseconds.
    pub ts_ms: u64,
    pub data: &'a [u8],
}

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

const ERRBUF_SIZE: usize = 256;
const DLT_EN10MB: c_int = 1;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: c_uint,
}

#[repr(C)]
struct BpfProgram {
    len: c_uint,
    insns: *mut c_void,
}

#[cfg(windows)]
#[repr(C)]
struct TimeVal {
    sec: i32,
    usec: i32,
}

#[cfg(not(windows))]
#[repr(C)]
struct TimeVal {
    sec: i64,
    usec: i64,
}

#[repr(C)]
struct PktHdr {
    ts: TimeVal,
    caplen: u32,
    len: u32,
}

type Handle = *mut c_void;

struct Lib {
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    open_live: unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> Handle,
    compile: unsafe extern "C" fn(Handle, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(Handle, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    next_ex: unsafe extern "C" fn(Handle, *mut *mut PktHdr, *mut *const u8) -> c_int,
    sendpacket: unsafe extern "C" fn(Handle, *const u8, c_int) -> c_int,
    geterr: unsafe extern "C" fn(Handle) -> *mut c_char,
    datalink: unsafe extern "C" fn(Handle) -> c_int,
    close: unsafe extern "C" fn(Handle),
    lib_version: unsafe extern "C" fn() -> *const c_char,
}

static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();

fn lib() -> Result<&'static Lib, CaptureError> {
    LIB.get_or_init(load).as_ref().map_err(|e| CaptureError::NotInstalled(e.clone()))
}

/// Resolve every symbol, or fail with a readable message.
macro_rules! resolve {
    ($sym:expr, $($field:ident = $name:literal),+ $(,)?) => {{
        Lib {
            $($field: {
                let p = $sym(concat!($name, "\0"));
                if p.is_null() {
                    return Err(format!("the pcap library has no {}", $name));
                }
                // SAFETY: the symbol has the C signature declared for this field
                // (the target type is the field's, inferred).
                #[allow(clippy::missing_transmute_annotations)]
                unsafe { std::mem::transmute::<*const c_void, _>(p) }
            },)+
        }
    }};
}

#[cfg(windows)]
fn load() -> Result<Lib, String> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW};

    let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let path = format!(r"{system}\System32\Npcap\wpcap.dll");
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    // SAFETY: NUL-terminated path. Altered search path lets wpcap.dll find Packet.dll beside it.
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
    if module.is_null() {
        return Err("Npcap isn't installed. Install it from https://npcap.com (keep \"Restrict Npcap driver's \
                    access to Administrators only\" unticked to capture without admin rights)."
            .into());
    }
    let sym = |name: &str| -> *const c_void {
        // SAFETY: valid module handle and NUL-terminated name.
        unsafe { GetProcAddress(module, name.as_ptr()) }.map_or(std::ptr::null(), |f| f as *const c_void)
    };
    Ok(resolve!(sym,
        findalldevs = "pcap_findalldevs",
        freealldevs = "pcap_freealldevs",
        open_live = "pcap_open_live",
        compile = "pcap_compile",
        setfilter = "pcap_setfilter",
        freecode = "pcap_freecode",
        next_ex = "pcap_next_ex",
        sendpacket = "pcap_sendpacket",
        geterr = "pcap_geterr",
        datalink = "pcap_datalink",
        close = "pcap_close",
        lib_version = "pcap_lib_version",
    ))
}

#[cfg(unix)]
fn load() -> Result<Lib, String> {
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    const RTLD_NOW: c_int = 2;
    let mut module = std::ptr::null_mut();
    for name in [c"libpcap.so.1", c"libpcap.so", c"libpcap.dylib"] {
        // SAFETY: NUL-terminated library name.
        module = unsafe { dlopen(name.as_ptr(), RTLD_NOW) };
        if !module.is_null() {
            break;
        }
    }
    if module.is_null() {
        return Err("libpcap isn't installed (e.g. `sudo apt install libpcap0.8`)".into());
    }
    let sym = |name: &str| -> *const c_void {
        // SAFETY: valid handle and NUL-terminated name.
        unsafe { dlsym(module, name.as_ptr().cast()) }.cast_const()
    };
    Ok(resolve!(sym,
        findalldevs = "pcap_findalldevs",
        freealldevs = "pcap_freealldevs",
        open_live = "pcap_open_live",
        compile = "pcap_compile",
        setfilter = "pcap_setfilter",
        freecode = "pcap_freecode",
        next_ex = "pcap_next_ex",
        sendpacket = "pcap_sendpacket",
        geterr = "pcap_geterr",
        datalink = "pcap_datalink",
        close = "pcap_close",
        lib_version = "pcap_lib_version",
    ))
}

#[cfg(not(any(windows, unix)))]
fn load() -> Result<Lib, String> {
    Err("packet capture isn't supported on this OS".into())
}

fn cstr(p: *const c_char) -> Option<String> {
    // SAFETY: pcap returns NUL-terminated strings or null.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

fn classify(msg: String) -> CaptureError {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("denied") || lower.contains("permission") || lower.contains("not permitted") {
        CaptureError::PermissionDenied(format!(
            "{msg}. Capture needs admin rights, or Npcap installed without the admin-only restriction \
             (Linux: setcap cap_net_raw,cap_net_admin+eip on the binary)."
        ))
    } else {
        CaptureError::Failed(msg)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The pcap library's version string, e.g. "Npcap version 1.10.5, based on libpcap version 1.10.5".
pub fn library_version() -> Result<String, CaptureError> {
    let lib = lib()?;
    // SAFETY: returns a static string.
    Ok(cstr(unsafe { (lib.lib_version)() }).unwrap_or_default())
}

pub fn devices() -> Result<Vec<CaptureDevice>, CaptureError> {
    let lib = lib()?;
    let mut list: *mut PcapIf = std::ptr::null_mut();
    let mut err = [0 as c_char; ERRBUF_SIZE];
    // SAFETY: valid out-pointer and error buffer.
    if unsafe { (lib.findalldevs)(&mut list, err.as_mut_ptr()) } != 0 {
        return Err(classify(cstr(err.as_ptr()).unwrap_or_default()));
    }
    let mut out = Vec::new();
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: a linked list owned by pcap until freealldevs.
        let d = unsafe { &*cur };
        if let Some(name) = cstr(d.name) {
            out.push(CaptureDevice { name, description: cstr(d.description) });
        }
        cur = d.next;
    }
    if !list.is_null() {
        // SAFETY: list came from findalldevs.
        unsafe { (lib.freealldevs)(list) };
    }
    Ok(out)
}

/// The capture device for an OS interface id (adapter GUID on Windows, ifname on Linux).
pub fn device_for_interface(id: &str) -> Result<String, CaptureError> {
    let id = id.trim_matches(['{', '}']).to_ascii_lowercase();
    devices()?
        .into_iter()
        .find(|d| {
            let n = d.name.to_ascii_lowercase();
            n == id || n.trim_end_matches('}').ends_with(&id)
        })
        .map(|d| d.name)
        .ok_or(CaptureError::NoDevice(id))
}

/// An open Ethernet capture. Blocking: `next` waits up to the read timeout.
pub struct Capture {
    lib: &'static Lib,
    handle: Handle,
}

// SAFETY: a pcap handle may move between threads; it is only used by one at a time (&mut self).
unsafe impl Send for Capture {}

impl Capture {
    /// Open `device` (not promiscuous) with a BPF `filter` and a read timeout.
    pub fn open(device: &str, filter: &str, timeout_ms: i32) -> Result<Self, CaptureError> {
        let lib = lib()?;
        let dev = CString::new(device).map_err(|_| CaptureError::NoDevice(device.into()))?;
        let mut err = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: valid strings and error buffer.
        let handle = unsafe { (lib.open_live)(dev.as_ptr(), 2048, 0, timeout_ms, err.as_mut_ptr()) };
        if handle.is_null() {
            return Err(classify(cstr(err.as_ptr()).unwrap_or_else(|| "pcap_open_live failed".into())));
        }
        let cap = Self { lib, handle };
        // SAFETY: valid handle.
        if unsafe { (lib.datalink)(handle) } != DLT_EN10MB {
            return Err(CaptureError::Failed(format!("{device} isn't an Ethernet-framed device")));
        }
        let f = CString::new(filter).map_err(|_| CaptureError::Failed("bad filter".into()))?;
        let mut prog = BpfProgram { len: 0, insns: std::ptr::null_mut() };
        // SAFETY: valid handle/program/filter. Netmask 0 is fine: no broadcast tests in our filters.
        unsafe {
            if (lib.compile)(handle, &mut prog, f.as_ptr(), 1, 0) != 0 {
                return Err(CaptureError::Failed(format!("filter: {}", cap.error())));
            }
            let rc = (lib.setfilter)(handle, &mut prog);
            (lib.freecode)(&mut prog);
            if rc != 0 {
                return Err(CaptureError::Failed(format!("filter: {}", cap.error())));
            }
        }
        Ok(cap)
    }

    fn error(&self) -> String {
        // SAFETY: valid handle; the string lives until the next pcap call.
        cstr(unsafe { (self.lib.geterr)(self.handle) }).unwrap_or_default()
    }

    /// The next packet, or None when the read timeout passed without one.
    pub fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: valid handle and out-pointers. The data stays valid until the next call (&mut self).
        match unsafe { (self.lib.next_ex)(self.handle, &mut hdr, &mut data) } {
            1 => {
                // SAFETY: on success both pointers are valid.
                let h = unsafe { &*hdr };
                let ts_ms = (h.ts.sec as u64) * 1000 + (h.ts.usec as u64) / 1000;
                let data = unsafe { std::slice::from_raw_parts(data, h.caplen as usize) };
                Ok(Some(Packet { ts_ms, data }))
            }
            0 => Ok(None),
            _ => Err(CaptureError::Failed(self.error())),
        }
    }

    /// Transmit one complete Ethernet frame.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), CaptureError> {
        // SAFETY: valid handle and buffer.
        match unsafe { (self.lib.sendpacket)(self.handle, frame.as_ptr(), frame.len() as c_int) } {
            0 => Ok(()),
            _ => Err(classify(self.error())),
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: handle came from open_live and is closed once.
        unsafe { (self.lib.close)(self.handle) };
    }
}
