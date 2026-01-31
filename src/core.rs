use std::{net::{IpAddr, ToSocketAddrs, UdpSocket}};

// Let OS automatically assign a port
const LOCAL_ADDR: &str = "0.0.0.0:0";
const DEFAULT_MAX_HOPS: u32 = 64;
const DST_PORT: u16 = 33434;

pub(crate) struct Traceroute {
    pub host: String
}

impl Traceroute {
    pub fn run(&self) -> std::io::Result<()> {
        let ip_addr: IpAddr = self.resolve_ip_addr()?;
        println!("traceroute to {} ({}), {} hops max, 40 bytes packets", &self.host, DEFAULT_MAX_HOPS, ip_addr);

        // Send packet repeatedly max 64 hops
        let socket: UdpSocket = UdpSocket::bind(String::from(LOCAL_ADDR))?;
        let dst: String = format!("{}:{}", &ip_addr, &DST_PORT);
        let mut ttl: u32 = 0;
        while ttl <= DEFAULT_MAX_HOPS {
            ttl += 1;
            let _ = socket.set_ttl(ttl);

            if let Err(e) = socket.send_to(b"0", dst) {
                return Err(e);
            }

            println!("Receiving");
            let mut buf: [u8; 10] = [0; 10];
            let (number_of_bytes, _) = socket.recv_from(&mut buf)?;
            let filled_buf: &mut [u8] = &mut buf[..number_of_bytes];
            println!("{:?}", filled_buf);
            break;
        }

        Ok(())
    }

    fn resolve_ip_addr(&self) -> std::io::Result<IpAddr> {
        let address_str: String = format!("{}:443", &self.host);
        let mut addrs: std::vec::IntoIter<std::net::SocketAddr> = address_str.to_socket_addrs()?;
        let chosen_ip: IpAddr = match addrs.next() {
            Some(addr) => addr.ip(),
            None => return Err(
                std::io::Error::new(
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