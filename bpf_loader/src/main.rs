use bpf_probe::probe_network::IpData;
use futures::stream::StreamExt;
use redbpf::load::Loader;
use redbpf::HashMap;
use redbpf::xdp::Flags;
use std::env;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use tokio;
use tokio::signal;
use tokio::time::sleep;
use std::time::Duration;


use redbpf::Program::XDP;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: bpf_example_program [NETWORK_INTERFACE] [FILENAME]");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }
    let interface = args[1].clone();
    let file = args[2].clone();
    let mut loader = Loader::load_file(&Path::new(&file)).expect("error loading file");

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

    tokio::spawn(async move {
        let ips = HashMap::<u32, IpData>::new(loader.map("ip_map").unwrap()).unwrap();
        loop {
            sleep(Duration::from_millis(60000)).await;
            for (key,value) in ips.iter() {
                println!("{} - {:?}", key, value);
                ips.delete(key)
            };
        };
    });

    signal::ctrl_c().await
}
