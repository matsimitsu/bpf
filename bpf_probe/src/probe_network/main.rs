#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use bpf_probe::probe_network::IpData;

program!(0xFFFFFFFE, "GPL");

#[map("ip_map")]
static mut ip_map: HashMap<u32, IpData> = HashMap::with_max_entries(10240);

#[xdp("probe_network")]
pub fn probe(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let data = ctx.data()?;

    let ip_agg = IpData {
        count: 0u32,
        usage: 0u32,
    };

    unsafe {
        let mut ip_sender = match ip_map.get_mut(&ip.saddr) {
            Some(c) => c,
            None => {
                ip_map.set(&ip.saddr, &ip_agg);
                ip_map.get_mut(&ip.saddr).unwrap()
            }
        };

        ip_sender.count += 1;
        ip_sender.usage += (data.len() + data.offset()) as u32;
    };

    Ok(XdpAction::Pass)
}
