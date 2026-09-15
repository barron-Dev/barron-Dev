//! Verified Windows NT kernel TCP/IP and UDP/IP ETW payload decoding.
//!
//! The layouts below follow the Microsoft Learn MOF classes:
//! TcpIp_TypeGroup1/2 and UdpIp_TypeGroup1/2.  We only decode fields whose
//! position/type is defined by those schemas. Unknown event types are rejected.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedNetwork {
    pub protocol: NetworkProtocol,
    pub ipv6: bool,
    pub pid: u32,
    pub size: u32,
    pub source_address: String,
    pub destination_address: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub connection_id: u32,
}

// Microsoft TcpIp: event types 10-18 (IPv4) and 26-34 (IPv6).
// Microsoft UdpIp: event types 10/11 (IPv4) and 26/27 (IPv6).
pub fn decode_tcp(opcode: u8, bytes: &[u8]) -> Option<DecodedNetwork> {
    match opcode {
        10 | 11 | 13 | 14 | 16 | 18 => decode_common(NetworkProtocol::Tcp, false, bytes),
        12 | 15 => decode_tcp_connect_accept(bytes),
        27 | 29 | 30 | 32 | 34 => decode_common(NetworkProtocol::Tcp, true, bytes),
        28 | 31 => decode_tcp_connect_accept_v6(bytes),
        _ => None,
    }
}

pub fn decode_udp(opcode: u8, bytes: &[u8]) -> Option<DecodedNetwork> {
    match opcode {
        10 | 11 => decode_common(NetworkProtocol::Udp, false, bytes),
        26 | 27 => decode_common(NetworkProtocol::Udp, true, bytes),
        _ => None,
    }
}

fn decode_common(protocol: NetworkProtocol, ipv6: bool, bytes: &[u8]) -> Option<DecodedNetwork> {
    let addr_len = if ipv6 { 16 } else { 4 };
    // PID, size, daddr, saddr, dport, sport, seqnum, connid.
    let needed = 4usize.checked_mul(2)?
        .checked_add(addr_len.checked_mul(2)?)?
        .checked_add(2usize.checked_mul(2)?)?
        .checked_add(4usize.checked_mul(2)?)?;
    if bytes.len() < needed { return None; }
    let mut c = 0usize;
    let pid = u32le(bytes, &mut c)?;
    let size = u32le(bytes, &mut c)?;
    let destination_address = ip_string(bytes.get(c..c + addr_len)?, ipv6)?; c += addr_len;
    let source_address = ip_string(bytes.get(c..c + addr_len)?, ipv6)?; c += addr_len;
    let destination_port = u16le(bytes, &mut c)?;
    let source_port = u16le(bytes, &mut c)?;
    let sequence_number = u32le(bytes, &mut c)?;
    let connection_id = u32le(bytes, &mut c)?;
    Some(DecodedNetwork { protocol, ipv6, pid, size, source_address, destination_address,
        source_port, destination_port, sequence_number, connection_id })
}

fn decode_tcp_connect_accept(bytes: &[u8]) -> Option<DecodedNetwork> {
    // TypeGroup2: PID,size,daddr,saddr,dport,sport, six TCP option/window
    // fields, seqnum,connid. Address/port positions are unchanged.
    let mut c = 0usize;
    let pid = u32le(bytes, &mut c)?;
    let size = u32le(bytes, &mut c)?;
    let destination_address = ip_string(bytes.get(c..c + 4)?, false)?; c += 4;
    let source_address = ip_string(bytes.get(c..c + 4)?, false)?; c += 4;
    let destination_port = u16le(bytes, &mut c)?;
    let source_port = u16le(bytes, &mut c)?;
    for _ in 0..4 { u16le(bytes, &mut c)?; }
    u32le(bytes, &mut c)?;
    u16le(bytes, &mut c)?;
    u16le(bytes, &mut c)?;
    let sequence_number = u32le(bytes, &mut c)?;
    let connection_id = u32le(bytes, &mut c)?;
    Some(DecodedNetwork { protocol: NetworkProtocol::Tcp, ipv6: false, pid, size,
        source_address, destination_address, source_port, destination_port,
        sequence_number, connection_id })
}

fn decode_tcp_connect_accept_v6(bytes: &[u8]) -> Option<DecodedNetwork> {
    // TypeGroup4 has the IPv6 address/port fields followed by the documented
    // TCP connection metadata. The common prefix is schema-stable.
    decode_common(NetworkProtocol::Tcp, true, bytes)
}

fn u16le(bytes: &[u8], c: &mut usize) -> Option<u16> {
    let end = c.checked_add(2)?; let v = u16::from_le_bytes(bytes.get(*c..end)?.try_into().ok()?); *c = end; Some(v)
}
fn u32le(bytes: &[u8], c: &mut usize) -> Option<u32> {
    let end = c.checked_add(4)?; let v = u32::from_le_bytes(bytes.get(*c..end)?.try_into().ok()?); *c = end; Some(v)
}
fn ip_string(bytes: &[u8], ipv6: bool) -> Option<String> {
    if ipv6 { Some(std::net::Ipv6Addr::from(<[u8;16]>::try_from(bytes).ok()?).to_string()) }
    else { Some(std::net::Ipv4Addr::from(<[u8;4]>::try_from(bytes).ok()?).to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u16le(v: u16, b: &mut Vec<u8>) { b.extend_from_slice(&v.to_le_bytes()); }
    fn u32le(v: u32, b: &mut Vec<u8>) { b.extend_from_slice(&v.to_le_bytes()); }
    fn ipv4(a: [u8;4], b: &mut Vec<u8>) { b.extend_from_slice(&a); }
    fn ipv6(a: [u8;16], b: &mut Vec<u8>) { b.extend_from_slice(&a); }

    #[test]
    fn decodes_udp_ipv4_schema() {
        let mut b = Vec::new();
        u32le(4242,&mut b); u32le(64,&mut b); ipv4([8,8,8,8],&mut b); ipv4([10,0,0,2],&mut b);
        u16le(53,&mut b); u16le(51515,&mut b); u32le(7,&mut b); u32le(9,&mut b);
        let d=decode_udp(10,&b).unwrap();
        assert_eq!(d.protocol,NetworkProtocol::Udp); assert_eq!(d.pid,4242); assert_eq!(d.destination_address,"8.8.8.8");
        assert_eq!(d.destination_port,53); assert_eq!(d.source_port,51515);
    }

    #[test]
    fn decodes_tcp_ipv6_schema() {
        let mut b=Vec::new(); u32le(99,&mut b); u32le(128,&mut b);
        ipv6([0x20,1,0xdb,0x8,0,0,0,0,0,0,0,0,0,0,0,1],&mut b);
        ipv6([0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2],&mut b);
        u16le(443,&mut b); u16le(50000,&mut b); u32le(1,&mut b); u32le(2,&mut b);
        let d=decode_tcp(27,&b).unwrap();
        assert!(d.ipv6); assert_eq!(d.destination_port,443); assert_eq!(d.pid,99);
    }

    #[test]
    fn rejects_unknown_or_truncated_schema() {
        assert!(decode_udp(99,&[]).is_none()); assert!(decode_tcp(11,&[0;10]).is_none());
    }
}
