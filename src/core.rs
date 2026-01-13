use std::net::{IpAddr, ToSocketAddrs};

pub(crate) struct Traceroute {
    pub host: String
}

impl Traceroute {
    pub fn run(&self) -> std::io::Result<()> {
        let ip_addr = self.resolve_ip_addr()?;
        println!("traceroute to {} ({}), 64 hops max, 40 bytes packets", &self.host, ip_addr);
        Ok(())
    }

    fn resolve_ip_addr(&self) -> std::io::Result<IpAddr> {
        let address_str = format!("{}:443", &self.host);
        let mut addrs = address_str.to_socket_addrs()?;
        let chosen_ip = match addrs.next() {
            Some(addr) => addr.ip(),
            None => return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No IP addresses resolved"
                )
            )
        };

        if addrs.next().is_some() {
            println!("Warning: {} has multiple addresses; using {}", &self.host, &chosen_ip);
        }

        Ok(chosen_ip)
    }
}