use bpf_probe::probe_network::Message;
use redbpf::load::Loader;
use redbpf::{cpus,PerfMap,Event};

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::thread;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::mem;
use std::ptr;
use std::os::raw::c_char;
use std::ffi::CStr;


use ureq::Agent;
use lazy_static::lazy_static;
use nix::unistd::gethostname;
use lru_cache::LruCache;
use dns_lookup::lookup_addr;
use serde_json::json;
use serde::Serialize;
use time::OffsetDateTime;
use pnet::datalink::{self, NetworkInterface};

#[derive(Debug,Clone,Serialize)]
pub struct Link {
    source_ip: String,
    dest_ip: String,
    source_hostname: String,
    dest_hostname: String,
    count: u32,
    usage: u32
}

lazy_static! {
    pub static ref HOSTNAME: String = hostname().expect("Could not get hostname");
    pub static ref IPS: Vec<String> = ips();
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let elf_bytes = include_bytes!("../../bpf_probe/target/bpf/programs/probe_network/probe_network.elf");
    let mut hostname_cache: LruCache<IpAddr, String> = LruCache::new(1000);
    let agent = Agent::new()
        .set("Content-type", "application/json")
        .build();
    let (sender, receiver) = channel();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: bpf_example_program [NETWORK_INTERFACE] [ENDPOINT");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }
    let endpoint = args[1].clone();
    let mut loader = Loader::load(elf_bytes).expect("error loading file");

    // Load all of the kprobes programs from the binary
    for program in loader.module.kprobes_mut() {
        let name = program.name().to_string();
        program.attach_kprobe(&program.name(), 0).unwrap()
    }

    let online_cpus = cpus::get_online().unwrap();
    let mut maps: Vec<PerfMap> = vec![];
    for m in loader.module.maps.iter_mut().filter(|m| m.kind == 4) {
        for cpuid in online_cpus.iter() {
            let map = PerfMap::bind(m, -1, *cpuid, 16, -1, 0).unwrap();
            maps.push(map)
        }
    }

    thread::spawn(move|| {
        let mut start = Instant::now();
        let mut cache: Vec<Message> = Vec::new();

        loop {
            for map in maps.iter() {
                if let Some(ev) = map.read() {
                    match ev {
                        Event::Lost(lost) => {
                            eprintln!("Possibly lost {} samples", lost.count);
                        }
                        Event::Sample(sample) => {
                            let msg = unsafe { std::ptr::read(sample.data.as_ptr() as *const Message) };
                            cache.push(msg);
                        }
                    };
                }
            }
            let duration = start.elapsed().as_millis();
            if duration > 10000 {
                let new_cache = mem::replace(&mut cache, Vec::new());
                start = Instant::now();
                sender.send((duration as u64, new_cache)).unwrap();

            }
        };
    });

    for (duration, data) in receiver.iter() {
        let mut links: Vec<Link> = Vec::new();

        for message in data.iter() {
            println!("Message: {:?}", message);
            let (connection, size) = message;
            let comm = unsafe { CStr::from_ptr(connection.comm.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned();

            println!("comm: {}", comm)
        }

    };

    Ok(())
}

pub fn transmit(agent: &Agent, endpoint: &str, links: &Vec<Link>, duration: &u64) -> bool {
    let json = json!({
      "hostname": HOSTNAME.to_string(),
      "ips": IPS.to_vec(),
      "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
      "duration": duration,
      "links": links,
    });
    let resp = agent.post(endpoint).send_json(json.to_owned());
    println!("[{}] {}", resp.status_line(), json);
    resp.ok()
}

fn hostname() -> Option<String> {
    let mut buf = [0u8; 64];
    let hostname_cstr = match gethostname(&mut buf) {
    Ok(hostname) => hostname,
    Err(_) => return None
    };

    let hostname_str = match hostname_cstr.to_str() {
    Ok(hostname) => hostname,
    Err(_) => return None
    };

    Some(hostname_str.to_string())
}

fn ips() -> Vec<String> {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                                .filter(interface_names_match)
                                .next()
                                .unwrap();
    interface.ips.iter().map ( |ip| ip.ip().to_string()).collect()
}
