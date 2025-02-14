use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // loads the file into the compiled binary, runs instantly
    // use Ebpf::load_file, to run from a file instead
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/helloaya"
    )))?;

    // boilerplate
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // populate the blocklist hashmap in the ebpf file
    let mut blocklist_dst: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let mut ips: Vec<(u8, u8, u8, u8)> = Vec::new();
    ips.push((10, 245, 192, 185));

    let blocklist_src: Vec<u32> = ips
        .iter()
        .map(|&(a, b, c, d)| Ipv4Addr::new(a, b, c, d).into())
        .collect();
    for addr in blocklist_src {
        blocklist_dst.insert(addr, 0, 0)?;
    }

    // let mut blocklist: HashMap<_, u32, u32> =
    //     HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    // let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();
    // blocklist.insert(block_addr, 0, 0)?;

    // boilerplate
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
