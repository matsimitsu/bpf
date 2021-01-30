use bpf_probe::probe_network::{Connection, Ipv6Addr, Message};
use redbpf::load::{Loader,Loaded};

use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::raw::c_char;
use std::ptr;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::{Duration, Instant};

use dns_lookup::lookup_addr;
use futures::{future, stream::StreamExt};
use lazy_static::lazy_static;
use lru_cache::LruCache;
use nix::unistd::gethostname;
use pnet::datalink::{self, NetworkInterface};
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
    source_port: u32,
    dest_port: u32,
    command: String,
    timestamp: u64,
    size: u64,
}

pub type CacheKey = (
    std::string::String,
    std::string::String,
    u32,
    u32,
    std::string::String,
    Direction,
);
pub type Cache = Arc<Mutex<HashMap<CacheKey, u32>>>;

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
    let mut hostname_cache: LruCache<IpAddr, String> = LruCache::new(1000);
    let agent = Agent::new().set("Content-type", "application/json").build();

    // Load all of the kprobes programs from the binary
    for program in loader.module.kprobes_mut() {
        let name = program.name().to_string();
        program.attach_kprobe(&program.name(), 0).unwrap()
    }
    let cache: Cache = Arc::new(Mutex::new(HashMap::new()));

    let clone = cache.clone();

    thread::spawn( move || {
        println!("Spawned");
        loop {
            sleep(Duration::from_millis(1000));
            {
                let mut state = clone.lock().expect("Could not lock mutex");
                let transfer_cache = mem::replace(&mut *state, HashMap::new());
                println!("{:?}", transfer_cache);
            }
            // convert cache to link, enriching the data
            // transmit link
        }
    });

    while let Some((name, events)) = loader.events.next().await {
        for event in events {
            let message = unsafe { ptr::read(event.as_ptr() as *const Message) };
            let (connection, size, direction) = match message {
                Message::Send(c, s) => (c, s, Direction::Send),
                Message::Receive(c, s) => (c, s, Direction::Receive),
            };
            let comm = unsafe { CStr::from_ptr(connection.comm.as_ptr() as *const c_char) };

            let key: CacheKey = (
                ip_to_string(&connection.saddr),
                ip_to_string(&connection.daddr),
                connection.sport,
                connection.dport,
                comm.to_string_lossy().into_owned(),
                direction,
            );
            let size32 = u32::from(size);
            let mut state = cache.lock().expect("Could not lock mutex");
            let mut entry = *state.entry(key).or_insert(0);
            entry += size32;
        }
    }

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

fn ip_to_string(addr: &Ipv6Addr) -> String {
    let v6: &std::net::Ipv6Addr = unsafe { std::mem::transmute(addr) };

    match v6.to_ipv4() {
        Some(v4) => v4.to_string(),
        None => v6.to_string(),
    }
}
