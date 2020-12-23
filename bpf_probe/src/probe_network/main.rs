#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use bpf_probe::probe_network::RequestInfo;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "requests")]
static mut requests: PerfMap<RequestInfo> = PerfMap::with_max_entries(1024);

#[xdp("monitor")]
pub fn probe_network(ctx: XdpContext) -> XdpResult {
    let (ip, transport, data) = match (ctx.ip(), ctx.transport(), ctx.data()) {
        (Ok(ip), Ok(t), Ok(data)) => (unsafe { *ip }, t, data),
        _ => return Ok(XdpAction::Pass),
    };

    let info = RequestInfo {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest()
    };

    let aab = MapData::with_payload(info, data.offset() as u32, data.len() as u32);
    unsafe {
        requests.insert(
            &ctx,
            &aab,
        )
    };

    Ok(XdpAction::Pass)
}
