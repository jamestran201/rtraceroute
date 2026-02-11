use socket2::{Socket, Domain, Protocol, Type};
use std::{net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket}, time::{Duration, Instant}};
use std::mem::MaybeUninit;

// Let OS automatically assign a port
const LOCAL_ADDR: &str = "0.0.0.0:0";
const DEFAULT_MAX_HOPS: u32 = 64;
const DST_PORT: u16 = 33434;
const MINIMUM_ICMP_REPLY_PACKET_LEN: usize = 20;

struct ParsedIcmp {
    ip_addr: Ipv4Addr,
    response_code: u8
}

struct AttemptResult {
    ip_addr: Option<Ipv4Addr>,
    latency: u128,
}

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
        let mut ttl: u32 = 0;
        let mut dst_reached: bool = false;
        while ttl <= DEFAULT_MAX_HOPS && !dst_reached {
            ttl += 1;
            let _ = send_socket.set_ttl(ttl);
            let mut attempt_results: Vec<AttemptResult> = Vec::<AttemptResult>::new();

            for _ in 0..3 {
                let start_time: Instant = Instant::now();
                send_socket.send_to(b"0", &dst)?;

                let icmp_result: Result<ParsedIcmp, std::io::Error> = self.parse_icmp_reply(&rcv_socket);
                let end_time: Instant = Instant::now();
                let mut last_ip_addr: Option<Ipv4Addr> = None;

                match icmp_result {
                    Ok(parsed_icmp) => {
                        if parsed_icmp.response_code == 3 {
                            dst_reached = true;
                        }

                        last_ip_addr = Some(parsed_icmp.ip_addr);
                    },
                    Err(e) => {
                        println!("Error: {}", e);
                    }
                }

                let latency: u128 = (end_time - start_time).as_millis();
                let attempt_result: AttemptResult = AttemptResult { ip_addr: last_ip_addr,  latency: latency };
                attempt_results.push(attempt_result);
            }

            let first_ip = &attempt_results[0].ip_addr;
            let all_same_ip = attempt_results.iter().all(|attempt_result| &attempt_result.ip_addr == first_ip);

            let mut message_string: String = format!("{} ", ttl);
            if all_same_ip {
                match first_ip {
                    Some(ip) => message_string.push_str(&ip.to_string()),
                    None => message_string.push('*')
                }

                message_string.push_str(&format!(" {}ms {}ms {}ms\n", &attempt_results[0].latency, &attempt_results[1].latency, &attempt_results[2].latency))
            } else {
                for i in 0..attempt_results.len() {
                    let attempt_result = &attempt_results[i];
                    match attempt_result.ip_addr {
                        Some(ip) => message_string.push_str(&ip.to_string()),
                        None => message_string.push('*')
                    }

                    message_string.push_str(&format!(" {}ms\n", &attempt_result.latency));
                }
            }

            println!("{}", message_string);
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

    fn parse_icmp_reply(&self, rcv_socket: &Socket) -> std::io::Result<ParsedIcmp> {
        let mut buf:[MaybeUninit<u8>; 2048] = [MaybeUninit::<u8>::uninit(); 2048];
        match rcv_socket.recv(&mut buf) {
            Ok(pkt_len) => {
                if pkt_len < MINIMUM_ICMP_REPLY_PACKET_LEN {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "ICMP reply packet length too short"));
                }

                let inited_buf: [u8; 2048] = unsafe { std::mem::transmute(buf) };

                // Parse IP header length
                // The first byte of the IP header contains the version and length.
                // The bitwise & 0x0F masks the version and keeps the length.
                // Multiply by 4 cause each unit of length represents 4 bytes.
                let ip_header: u8 = inited_buf[0];
                let ip_header_len: usize = (ip_header & 0x0F) as usize * 4;

                // Checks for incomplete packets -- ICMP headers have at least 8 bytes
                if pkt_len < ip_header_len + 8 {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Incomplete ICMP reply"));
                }

                let icmp_start: usize = ip_header_len;
                let icmp_type: u8 = inited_buf[icmp_start];

                // Extract source IP (the hop/router that sent this ICMP)
                // From IP header: source address is bytes 12-15
                let src_ip: Ipv4Addr = Ipv4Addr::new(
                    inited_buf[12], inited_buf[13], inited_buf[14], inited_buf[15]
                );

                return std::io::Result::Ok(ParsedIcmp { ip_addr: src_ip, response_code: icmp_type });
            },
            Err(e) => return Err(e),
        }
    }
}