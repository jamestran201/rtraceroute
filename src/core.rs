use socket2::{Socket, Domain, Protocol, Type};
use std::{net::{IpAddr, ToSocketAddrs, UdpSocket}, time::Duration};
use std::mem::MaybeUninit;

// Let OS automatically assign a port
const LOCAL_ADDR: &str = "0.0.0.0:0";
const DEFAULT_MAX_HOPS: u32 = 64;
const DST_PORT: u16 = 33434;
const MINIMUM_ICMP_REPLY_PACKET_LEN: usize = 20;

pub(crate) struct Traceroute {
    pub host: String
}

impl Traceroute {
    pub fn run(&self) -> std::io::Result<()> {
        let ip_addr: IpAddr = self.resolve_ip_addr()?;
        println!("traceroute to {} ({}), {} hops max, 40 bytes packets", &self.host, DEFAULT_MAX_HOPS, ip_addr);

        let send_socket: UdpSocket = UdpSocket::bind(String::from(LOCAL_ADDR))?;
        let rcv_socket: Socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        rcv_socket.set_read_timeout(Some(Duration::from_secs(3)))?;

        // Send packet repeatedly max 64 hops
        let dst: String = format!("{}:{}", &ip_addr, &DST_PORT);
        let mut ttl: u32 = 1;
        while ttl <= DEFAULT_MAX_HOPS {
            // Send probe packet
            let _ = send_socket.set_ttl(ttl);
            send_socket.send_to(b"0", &dst)?;

            // Read ICMP reply
            let icmp_type: u8 = self.parse_icmp_reply(&rcv_socket)?;
            match icmp_type {
                11 => ttl += 1,
                3 => break,
                _ => (),
            }
        }

        Ok(())
    }

    fn resolve_ip_addr(&self) -> std::io::Result<IpAddr> {
        let address_str: String = format!("{}:443", &self.host);
        let mut addrs: std::vec::IntoIter<std::net::SocketAddr> = address_str.to_socket_addrs()?;
        let chosen_ip: IpAddr = match addrs.next() {
            Some(addr) => addr.ip(),
            None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No IP addresses resolved"))
        };

        if addrs.next().is_some() {
            println!("Warning: {} has multiple addresses; using {}", &self.host, &chosen_ip);
        }

        Ok(chosen_ip)
    }

    fn parse_icmp_reply(&self, rcv_socket: &Socket) -> std::io::Result<u8> {
        let mut buf:[MaybeUninit<u8>; 2048] = [MaybeUninit::<u8>::uninit(); 2048];
        match rcv_socket.recv(&mut buf) {
            Ok(pkt_len) => {
                if pkt_len < MINIMUM_ICMP_REPLY_PACKET_LEN {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "ICMP reply packet length too short"));
                }

                // Parse IP header length
                // The first byte of the IP header contains the version and length.
                // The bitwise & 0x0F masks the version and keeps the length.
                // Multiply by 4 cause each unit of length represents 4 bytes.
                let ip_header = unsafe { buf[0].assume_init() };
                let ip_header_len: usize = (ip_header & 0x0F) as usize * 4;

                // Checks for incomplete packets -- ICMP headers have at least 8 bytes
                if pkt_len < ip_header_len + 8 {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Incomplete ICMP reply"));
                }

                let icmp_start: usize = pkt_len;
                let icmp_type: u8 = unsafe { buf[icmp_start].assume_init() };
                return std::io::Result::Ok(icmp_type);
            },
            Err(e) => return Err(e),
        }
    }
}