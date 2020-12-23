#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use bpf_probe::probe_network::IpData;

program!(0xFFFFFFFE, "GPL");

#[map("ip_map")]
static mut ip_map: HashMap<(u32, u32), IpData> = HashMap::with_max_entries(10240);

#[xdp("probe_network")]
pub fn probe(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let data = ctx.data()?;

    let ip_data = IpData {
        count: 0u32,
        usage: 0u32,
    };
    let key = (ip.saddr, ip.daddr);
    unsafe {
        let mut ip_record = match ip_map.get_mut(&key) {
            Some(c) => c,
            None => {
                ip_map.set(&key, &ip_data);
                ip_map.get_mut(&key).unwrap()
            }
        };

        ip_record.count += 1;
        ip_record.usage += (data.len() + data.offset()) as u32;
    };

    Ok(XdpAction::Pass)
}
