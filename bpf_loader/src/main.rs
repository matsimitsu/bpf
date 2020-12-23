use bpf_probe::probe_network::RequestInfo;
use futures::stream::StreamExt;
use redbpf::load::Loader;
use redbpf::xdp::{Flags, MapData};
use std::env;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use tokio;
use tokio::signal;
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
                prog.attach_xdp(&interface, Flags::default()) // attach the program to the Kernel space
            }
            _ => Ok(()),
        };
    }

    tokio::spawn(async move {
        while let Some((_, events)) = loader.events.next().await {
            for event in events {
                let event = unsafe { &*(event.as_ptr() as *const MapData<RequestInfo>) };
                let info = &event.data();
                let ip = IpAddr::from(info.saddr.to_ne_bytes());
                println!("{} - {}", ip, event.payload().len());
            }
        }
    });

    signal::ctrl_c().await
}
