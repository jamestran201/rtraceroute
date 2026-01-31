mod core;

use clap::Parser;
use core::Traceroute;
use std::process;

/// Print the route packets take to network host
#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    host: String
}

fn main() {
    let args: Args = Args::parse();
    let res: Result<(), std::io::Error> = Traceroute{host: args.host}.run();
    if let Err(e) = res {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
