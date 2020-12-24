use bpf_probe::probe_network::IpData;
use redbpf::load::Loader;
use redbpf::HashMap;
use redbpf::xdp::Flags;
use redbpf::Program::XDP;

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::thread;
use std::sync::mpsc::channel;
use std::thread::sleep;

use ureq::Agent;
use lazy_static::lazy_static;
use nix::unistd::gethostname;
use lru_cache::LruCache;
use dns_lookup::lookup_addr;
use serde_json::json;
use serde::Serialize;
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

fn main() -> Result<(), io::Error> {
    let elf_bytes = include_bytes!("../../bpf_probe/target/bpf/programs/probe_network/probe_network.elf");
    let mut hostname_cache: LruCache<IpAddr, String> = LruCache::new(1000);
    let agent = Agent::new()
        .set("Content-type", "application/json")
        .build();
    let (sender, receiver) = channel();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: bpf_example_program [NETWORK_INTERFACE] [ENDPOINT");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }
    let interface = args[1].clone();
    let endpoint = args[2].clone();
    let mut loader = Loader::load(elf_bytes).expect("error loading file");

    // Load all of the XDP programs from the binary
    for program in loader.module.programs.iter_mut() {
        let name = program.name().to_string();
        let _ret = match program {
            XDP(prog) => {
                println!("Attaching to {:?} interface: {:?}", &name, &interface);
                prog.attach_xdp(&interface, Flags::SkbMode) // attach the program to the Kernel space
            }
            _ => Ok(()),
        };
    }

    thread::spawn(move|| {
        let ips = HashMap::<(u32, u32), IpData>::new(loader.map("ip_map").unwrap()).unwrap();
        loop {
            sleep(Duration::from_millis(10000));
            let mut cache: Vec<(u32, u32, u32, u32)> = Vec::new();
            for (key,value) in ips.iter() {
                cache.push((key.0, key.1, value.count, value.usage));
                ips.delete(key)
            };
            sender.send(cache).unwrap();
        };
    });

    for data in receiver.iter() {
        let mut links: Vec<Link> = Vec::new();

        for (source_u32, dest_u32, count, usage) in data.into_iter() {
            let source_ip: IpAddr = IpAddr::V4(Ipv4Addr::from(source_u32));
            let dest_ip: IpAddr = IpAddr::V4(Ipv4Addr::from(dest_u32));

            let source_hostname = match hostname_cache.get_mut(&source_ip) {
                Some(hostname) => hostname.to_string(),
                None => {
                    let hostname = lookup_addr(&source_ip).unwrap_or(source_ip.to_string());
                    hostname_cache.insert(source_ip, hostname.to_string());
                  hostname
                }
            };

            let dest_hostname = match hostname_cache.get_mut(&dest_ip) {
                Some(hostname) => hostname.to_string(),
                None => {
                    let hostname = lookup_addr(&dest_ip).unwrap_or(dest_ip.to_string());
                    hostname_cache.insert(dest_ip, hostname.to_string());
                    hostname
                }
            };

            let link = Link {
                source_ip: source_ip.to_string(),
                dest_ip: dest_ip.to_string(),
                source_hostname,
                dest_hostname,
                count,
                usage
            };
            links.push(link);

        }

        transmit(&agent, &endpoint, &links);
    };

    Ok(())
}

pub fn transmit(agent: &Agent, endpoint: &str, links: &Vec<Link>) -> bool {
    let json = json!({
      "hostname": HOSTNAME.to_string(),
      "ips": IPS.to_vec(),
      "links": links,
    });
    println!("{:?}", json);
    let resp = agent.post(endpoint)
      .send_json(json);
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
    interface.ips.iter().map ( |ip| ip.to_string()).collect()
}
