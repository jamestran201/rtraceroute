use socket2::{Socket, Domain, Protocol, Type};
use std::io::Result;
use std::{net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket}, time::{Duration, Instant}};
use std::mem::MaybeUninit;

// Let OS automatically assign a port
const LOCAL_ADDR: &str = "0.0.0.0:0";
const DEFAULT_MAX_HOPS: u32 = 64;
const DST_PORT: u16 = 33434;
const MINIMUM_ICMP_REPLY_PACKET_LEN: usize = 20;
const RECEIVE_SOCKET_TIMEOUT: u64 = 3;
const ZERO_40: [u8; 40] = [0; 40];

struct ParsedIcmp {
    ip_addr: Ipv4Addr,
    response_code: u8
}

struct ProbeResult {
    ip_addr: Option<Ipv4Addr>,
    latency: f64,
}

struct ProbeDstResult {
    probe_results: Vec<ProbeResult>,
    dst_reached: bool
}

pub(crate) struct Traceroute {
    host: String,
    send_socket: UdpSocket,
    rcv_socket: Socket,
}

pub fn make_traceroute(host: String) -> Result<Traceroute> {
    let send_socket: UdpSocket = UdpSocket::bind(String::from(LOCAL_ADDR))?;
    let rcv_socket: Socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    rcv_socket.set_read_timeout(Some(Duration::from_secs(RECEIVE_SOCKET_TIMEOUT)))?;

    return Ok(Traceroute{ host, send_socket, rcv_socket });
}

impl Traceroute {
    pub fn run(&self) -> Result<()> {
        let ip_addr: IpAddr = self.resolve_ip_addr()?;
        println!("traceroute to {} ({}), {} hops max, 40 bytes packets", &self.host, ip_addr, DEFAULT_MAX_HOPS);

        let dst: String = format!("{}:{}", &ip_addr, &DST_PORT);
        for ttl in 1..=DEFAULT_MAX_HOPS {
            let _ = self.send_socket.set_ttl(ttl);

            let probe_dst_result: ProbeDstResult = self.probe_dst(&dst)?;
            let probe_results: Vec<ProbeResult> = probe_dst_result.probe_results;

            self.print_results(&ttl, &probe_results);

            if probe_dst_result.dst_reached {
                break;
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

    fn probe_dst(&self, dst: &str) -> Result<ProbeDstResult> {
        let mut dst_reached: bool = false;
        let mut probe_results: Vec<ProbeResult> = Vec::<ProbeResult>::with_capacity(3);
        for _ in 0..3 {
            let start_time: Instant = Instant::now();
            self.send_socket.send_to(&ZERO_40, dst)?;

            let icmp_result: Result<ParsedIcmp> = self.parse_icmp_reply();
            let latency: f64 = start_time.elapsed().as_secs_f64() * 1000.0;
            let mut dst_ip_addr: Option<Ipv4Addr> = None;

            match icmp_result {
                Ok(parsed_icmp) => {
                    if parsed_icmp.response_code == 3 {
                        dst_reached = true;
                    }

                    dst_ip_addr = Some(parsed_icmp.ip_addr);
                },
                Err(_) => ()
            }

            let attempt_result: ProbeResult = ProbeResult { ip_addr: dst_ip_addr,  latency };
            probe_results.push(attempt_result);
        }

        Ok(ProbeDstResult { probe_results, dst_reached })
    }

    fn parse_icmp_reply(&self) -> Result<ParsedIcmp> {
        let mut buf = vec![0u8; 2048];
        match self.rcv_socket.recv(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
        }) {
            Ok(pkt_len) => {
                if pkt_len < MINIMUM_ICMP_REPLY_PACKET_LEN {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "ICMP reply packet length too short"));
                }

                // Parse IP header length
                // The first byte of the IP header contains the version and length.
                // The bitwise & 0x0F masks the version and keeps the length.
                // Multiply by 4 cause each unit of length represents 4 bytes.
                let ip_header: u8 = buf[0];
                let ip_header_len: usize = (ip_header & 0x0F) as usize * 4;

                // Checks for incomplete packets -- ICMP headers have at least 8 bytes
                if pkt_len < ip_header_len + 8 {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Incomplete ICMP reply"));
                }

                // Get the first byte of the ICMP header which contains the response type.
                // The response packet roughly looks like: <IP HEADER>|<ICMP_HEADER>.
                // So index at ip_header_len to skip through the IP header.
                let icmp_type: u8 = buf[ip_header_len];

                // Extract source IP (the hop/router that sent this ICMP)
                // From IP header: source address is bytes 12-15
                let src_ip: Ipv4Addr = Ipv4Addr::new(
                    buf[12], buf[13], buf[14], buf[15]
                );

                return Ok(ParsedIcmp { ip_addr: src_ip, response_code: icmp_type });
            },
            Err(e) => return Err(e),
        }
    }

    fn print_results(&self, ttl: &u32, probe_results: &Vec<ProbeResult>) {
        let first_ip: &Option<Ipv4Addr> = &probe_results[0].ip_addr;
        let all_same_ip: bool = probe_results.iter().all(|attempt_result: &ProbeResult| &attempt_result.ip_addr == first_ip);

        let mut message_string: String = format!("{:<2} ", ttl);
        if all_same_ip {
            match first_ip {
                Some(ip) => self.format_ip_addr(&mut message_string, &ip.to_string()),
                None => self.format_ip_addr(&mut message_string, "*")
            }

            message_string.push_str(&format!(" {:.3}ms {:.3}ms {:.3}ms\n", &probe_results[0].latency, &probe_results[1].latency, &probe_results[2].latency))
        } else {
            for i in 0..probe_results.len() {
                if i > 0 {
                    message_string.push_str(&format!("{:<3}", ""));
                }

                let probe_result: &ProbeResult = &probe_results[i];
                match probe_result.ip_addr {
                    Some(ip) => self.format_ip_addr(&mut message_string, &ip.to_string()),
                    None => self.format_ip_addr(&mut message_string, "*")
                }

                message_string.push_str(&format!(" {:.3}ms\n", &probe_result.latency));
            }
        }

        print!("{}", message_string);
    }

    fn format_ip_addr(&self, message_builder: &mut String, ip_addr: &str) {
        message_builder.push_str(&format!("{:<16}", ip_addr))
    }
}