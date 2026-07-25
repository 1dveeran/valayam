#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    maps::PerfEventArray,
};
use aya_log_ebpf::info;

#[map]
pub static mut EVENTS: PerfEventArray<[u8; 256]> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe]
pub fn sys_execve(ctx: ProbeContext) -> u32 {
    match try_sys_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_execve(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "sys_execve called");
    
    // Placeholder payload
    let mut payload = [0u8; 256];
    payload[0] = 1; // event type indicator

    unsafe {
        EVENTS.output(&ctx, &payload, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
