#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

const IPPROTO_TCP: u32 = 6;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

// These pointer-shaped fields are the Rust spelling of libbpf's BTF map
// declaration (__uint/__type). The pointees encode constants and ABI types;
// all values in the ELF .maps section remain zero-initialized.
#[repr(C)]
struct OpenPortsDef {
    // rustc still emits this raw identifier as `type_` in BTF; the build fixes it.
    r#type: *mut [u32; 1], // BPF_MAP_TYPE_HASH
    max_entries: *mut [u32; 131072],
    key: *mut u16,
    value: *mut u8,
}

#[repr(C)]
struct RedirSocketDef {
    // rustc still emits this raw identifier as `type_` in BTF; the build fixes it.
    r#type: *mut [u32; 15], // BPF_MAP_TYPE_SOCKMAP
    max_entries: *mut [u32; 2],
    key: *mut u32,
    value: *mut u64,
}

#[used]
#[no_mangle]
#[link_section = ".maps"]
static mut open_ports: OpenPortsDef = OpenPortsDef {
    r#type: core::ptr::null_mut(),
    max_entries: core::ptr::null_mut(),
    key: core::ptr::null_mut(),
    value: core::ptr::null_mut(),
};

#[used]
#[no_mangle]
#[link_section = ".maps"]
static mut redir_socket: RedirSocketDef = RedirSocketDef {
    r#type: core::ptr::null_mut(),
    max_entries: core::ptr::null_mut(),
    key: core::ptr::null_mut(),
    value: core::ptr::null_mut(),
};

#[repr(C)]
pub struct BpfSkLookup {
    sk_or_cookie: u64,
    family: u32,
    protocol: u32,
    remote_ip4: u32,
    remote_ip6: [u32; 4],
    remote_port_and_pad: u32,
    local_ip4: u32,
    local_ip6: [u32; 4],
    local_port: u32,
    ingress_ifindex: u32,
}

#[inline(always)]
unsafe fn map_lookup(map: *mut c_void, key: *const c_void) -> *mut c_void {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void =
        core::mem::transmute(1usize);
    helper(map, key)
}

#[inline(always)]
unsafe fn sk_release(sk: *mut c_void) {
    let helper: unsafe extern "C" fn(*mut c_void) = core::mem::transmute(86usize);
    helper(sk)
}

#[inline(always)]
unsafe fn sk_assign(ctx: *mut BpfSkLookup, sk: *mut c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut BpfSkLookup, *mut c_void, u64) -> i64 =
        core::mem::transmute(124usize);
    helper(ctx, sk, 0)
}

#[no_mangle]
#[link_section = "sk_lookup"]
pub unsafe extern "C" fn dispatch(ctx: *mut BpfSkLookup) -> u32 {
    if (*ctx).protocol != IPPROTO_TCP {
        return SK_PASS;
    }

    let port = (*ctx).local_port as u16;
    let slot = map_lookup(
        core::ptr::addr_of_mut!(open_ports).cast(),
        core::ptr::addr_of!(port).cast(),
    ) as *const u8;
    if slot.is_null() {
        return SK_PASS;
    }

    let key = *slot as u32;
    if key > 1 {
        return SK_DROP;
    }
    let sk = map_lookup(
        core::ptr::addr_of_mut!(redir_socket).cast(),
        core::ptr::addr_of!(key).cast(),
    );
    if sk.is_null() {
        return SK_DROP;
    }

    let err = sk_assign(ctx, sk);
    sk_release(sk);
    if err == 0 { SK_PASS } else { SK_DROP }
}

#[used]
#[no_mangle]
#[link_section = "license"]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
