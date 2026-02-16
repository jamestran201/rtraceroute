mod core;

use clap::Parser;
use core::Traceroute;
use std::io::Result;

use crate::core::make_traceroute;

/// Print the route packets take to network host
#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    host: String
}

fn main() -> Result<()>{
    let args: Args = Args::parse();
    let traceroute: Traceroute = make_traceroute(args.host)?;
    traceroute.run()?;
    Ok(())
}
