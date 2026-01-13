mod core;

use clap::Parser;
use core::Traceroute;

/// Print the route packets take to network host
#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    host: String
}

fn main() {
    let args = Args::parse();
    Traceroute{host: args.host};
}
