#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

/*
 * XDP is a type of eBPF program that attaches to a network interface;
 * network packet -> user XDP program -> network driver/linux kernel
 *
 * XDP action determines what happens to the packet: XDP_{PASS, DROP, ABORTED, TX, REDIRECT}
 *
 * XDP context provides access to the network packet
 */
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

// for parsing the network packet
use core::mem;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// before accessing packet data, insert bound checks required by ebpf verifier
// gets a pointer to start and end of the packet
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// the xdp program entrypoint
#[xdp]
pub fn helloaya(ctx: XdpContext) -> u32 {
    match try_helloaya(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_helloaya(ctx: XdpContext) -> Result<u32, ()> {
    let (source_ip, source_port) = extract_source(&ctx)?;

    let action = if block_ip(source_ip) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    info!(&ctx, "{}, {:i}:{}", action, source_ip, source_port);

    Ok(xdp_action::XDP_PASS)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn extract_source(ctx: &XdpContext) -> Result<(u32, u16), ()> {
    // pass the offset, EthHdr, to skip EthHdr and go to IP hdr
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;

    // from big endian to target endian
    let source_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    Ok((source_ip, source_port))
}
