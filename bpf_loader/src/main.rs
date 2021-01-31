use bpf_probe::probe_network::{Ipv6Addr as BpfIpv6Addr, Message};
use redbpf::load::Loader;

use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::os::raw::c_char;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use std::net::{IpAddr, Ipv6Addr};

use dns_lookup::lookup_addr;
use futures::stream::StreamExt;
use lazy_static::lazy_static;
use lru_cache::LruCache;
use nix::unistd::gethostname;
use pnet::datalink;
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use ureq::Agent;

#[derive(Debug, Clone, Serialize)]
pub struct Link {
    source_ip: String,
    dest_ip: String,
    source_hostname: String,
    dest_hostname: String,
    port: u32,
    command: String,
    size: u64,
    direction: String
}

impl Link {
    pub fn from_cache(cache: (&CacheKey, &u32), hostname_cache: &mut HostnameCache) -> Link {
        let (key, size) = cache;
        let (source_ip, dest_ip, port, command, direction) = key;

        let source_hostname = match hostname_cache.get_mut(&source_ip) {
            Some(hostname) => hostname.to_string(),
            None => {
                let hostname = lookup_addr(&source_ip).unwrap_or(source_ip.to_string());
                hostname_cache.insert(*source_ip, hostname.to_string());
              hostname
            }
        };

        let dest_hostname = match hostname_cache.get_mut(&dest_ip) {
            Some(hostname) => hostname.to_string(),
            None => {
                let hostname = lookup_addr(&dest_ip).unwrap_or(dest_ip.to_string());
                hostname_cache.insert(*dest_ip, hostname.to_string());
                hostname
            }
        };

        let direction = match direction {
            Direction::Send => "Send".to_string(),
            Direction::Receive => "Receive".to_string()
        };
        Self {
            source_ip: source_ip.to_string(),
            dest_ip: dest_ip.to_string(),
            source_hostname,
            dest_hostname,
            port: *port,
            command: command.to_string(),
            size: *size as u64,
            direction
        }
    }
}

pub type CacheKey = (
    IpAddr,
    IpAddr,
    u32,
    std::string::String,
    Direction,
);
pub type Cache = Arc<Mutex<HashMap<CacheKey, u32>>>;
pub type HostnameCache = LruCache<IpAddr, String>;

lazy_static! {
    pub static ref HOSTNAME: String = hostname().expect("Could not get hostname");
    pub static ref IPS: Vec<String> = ips();
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Direction {
    Send,
    Receive,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let elf_bytes =
        include_bytes!("../../bpf_probe/target/bpf/programs/probe_network/probe_network.elf");

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: bpf_example_program [ENDPOINT");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }
    let endpoint = args[1].clone();
    let mut loader = Loader::load(elf_bytes).expect("error loading file");
    let mut hostname_cache: HostnameCache = LruCache::new(1000);
    let agent = Agent::new().set("Content-type", "application/json").build();

    // Load all of the kprobes programs from the binary
    for program in loader.module.kprobes_mut() {
        program.attach_kprobe(&program.name(), 0).unwrap()
    }
    let cache: Cache = Arc::new(Mutex::new(HashMap::new()));
    let clone = cache.clone();

    thread::spawn( move || {
        loop {
            sleep(Duration::from_millis(1000));
            let mut state = clone.lock().expect("Could not lock mutex");
            let transfer_cache = mem::replace(&mut *state, HashMap::new());
            let links: Vec<Link> = transfer_cache.iter().map(|c| {
                Link::from_cache(c, &mut hostname_cache)
            }).collect();
            transmit(&agent, &endpoint, &links);
        }
    });

    while let Some((_name, events)) = loader.events.next().await {
        for event in events {
            let message = unsafe { ptr::read(event.as_ptr() as *const Message) };

            let (connection, size, direction) = match message {
                Message::Send(conn, size) => (conn, size, Direction::Send),
                Message::Receive(conn, size) => (conn, size, Direction::Receive),
            };
            let comm = unsafe { CStr::from_ptr(connection.comm.as_ptr() as *const c_char) };

            let key: CacheKey = (
                ip_to_addr(&connection.saddr),
                ip_to_addr(&connection.daddr),
                connection.sport,
                comm.to_string_lossy().into_owned(),
                direction,
            );
            let mut state = cache.lock().expect("Could not lock mutex");
            *state.entry(key).or_insert(0) += size as u32;
        }
    }

    Ok(())
}

pub fn transmit(agent: &Agent, endpoint: &str, links: &Vec<Link>) -> bool {
    let json = json!({
      "hostname": HOSTNAME.to_string(),
      "ips": IPS.to_vec(),
      "timestamp": OffsetDateTime::now_utc().unix_timestamp(),
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
        Err(_) => return None,
    };

    let hostname_str = match hostname_cstr.to_str() {
        Ok(hostname) => hostname,
        Err(_) => return None,
    };

    Some(hostname_str.to_string())
}

fn ips() -> Vec<String> {
    let mut ips = Vec::new();

    let interfaces = datalink::interfaces();
    for interface in interfaces.iter() {
        for ip in interface.ips.iter() {
            ips.push(ip.ip().to_string())
        }
    }

    ips
}

fn ip_to_addr(addr: &BpfIpv6Addr) -> IpAddr {
    let v6: &Ipv6Addr = unsafe { std::mem::transmute(addr) };

    match v6.to_ipv4() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(*v6),
    }
}
