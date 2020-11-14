//! DNS implementation in Rust with no dependencies other than Rand<br>
//! See [DNS RFC Notes](https://github.com/willfleetw/rusty_dns/blob/main/docs/DNS_RFC_Notes.md) for notes on DNS protocols.

//TODO Better error piping? Should we create a error type and handle each case explicitly?

/// DNS packet structures and operations.
pub mod dns_packet;

/// DNS Domain Name operations.
pub mod domain_name;

/// Default DNS protocol port.
pub const DNS_PORT: u8 = 53;

/// The size of a valid DNS packet header.
pub const DNS_HEADER_SIZE: usize = 12;

/// DNS OPCODE values.
pub mod opcodes {
    /// A standard query (QUERY).
    pub const DNS_OPCODE_QUERY: u8 = 0;
    /// An inverse query (IQUERY).
    pub const DNS_OPCODE_IQUERY: u8 = 1;
    /// A server status request (STATUS).
    pub const DNS_OPCODE_STATUS: u8 = 2;
}

/// RCODE values.
pub mod rcodes {
    /// No error condition.
    pub const DNS_RCODE_NO_ERROR: u8 = 0;
    /// Format error - The name server was uanble to interpret the query.
    pub const DNS_RCODE_FORMAT_ERROR: u8 = 1;
    /// Server failure - The name server was uanble to process this query.
    pub const DNS_RCODE_SERVER_ERROR: u8 = 2;
    /// Name error - Meaningful only for responses from an authoritative server.
    /// This code signifies that the domain name referenced in the query does not exist.
    pub const DNS_RCODE_NAME_ERROR: u8 = 3;
    /// Not implemented - The name server does not support the requested kind of query.
    pub const DNS_RCODE_NOT_IMPLEMENTED: u8 = 4;
    /// Refused - The name server refuses to perform the specified operation.
    pub const DNS_RCODE_REFUSED: u8 = 5;
}

/// CLASS values, all of which are a subset of QCLASS values.
/// # NOTE
/// All CLASS values are a subset of QCLASS values.
pub mod classes {
    /// The Internet class.
    pub const DNS_CLASS_IN: u16 = 1;
    /// The CSNET class (Obsolete).
    pub const DNS_CLASS_CS: u16 = 2;
    /// The CHAOS class.
    pub const DNS_CLASS_CH: u16 = 3;
    /// The HESIOD class.
    pub const DNS_CLASS_HS: u16 = 4;
}

/// QCLASS values, used in the question section of a DNS packet.
/// # NOTE
/// All CLASS values are a subset of QCLASS values.
pub mod qclasses {
    /// QCLASS ANY can be used in a question to represent any possible desired class.
    pub const DNS_QCLASS_ANY: u16 = 255;
}

/// TYPE values, all of which are a subset of QTYPE values.
/// # NOTE
/// All TYPE values are a subset of QTYPES.
pub mod types {
    /// An IPv4 host address.
    pub const DNS_TYPE_A: u16 = 1;
    /// An authoritative name server.
    pub const DNS_TYPE_NS: u16 = 2;
    /// A mail destination (Obsolete - replaced by MX).
    pub const DNS_TYPE_MD: u16 = 3;
    /// A mail forwarder (Obsolete - replaced by MX).
    pub const DNS_TYPE_MF: u16 = 4;
    /// The canonical name for an alias.
    pub const DNS_TYPE_CNAME: u16 = 5;
    /// Marks the start of a zone of authority.
    pub const DNS_TYPE_SOA: u16 = 6;
    /// A mailbox domain name.
    pub const DNS_TYPE_MB: u16 = 7;
    /// A mail group member.
    pub const DNS_TYPE_MG: u16 = 8;
    /// A mail rename domain name.
    pub const DNS_TYPE_MR: u16 = 9;
    /// An experimental RR containing any possible data.
    pub const DNS_TYPE_NULL: u16 = 10;
    /// A well known service description.
    pub const DNS_TYPE_WKS: u16 = 11;
    /// A domain name pointer.
    pub const DNS_TYPE_PTR: u16 = 12;
    /// Host information.
    pub const DNS_TYPE_HINFO: u16 = 13;
    /// Mailbox or mail list information.
    pub const DNS_TYPE_MINFO: u16 = 14;
    /// Mail exchange.
    pub const DNS_TYPE_MX: u16 = 15;
    /// Text strings.
    pub const DNS_TYPE_TXT: u16 = 16;
    /// An IPv6 host address.
    pub const DNS_TYPE_AAAA: u16 = 28;
    /// Specifies location of a service for a specific protocol.
    pub const DNS_TYPE_SRV: u16 = 33;
}

/// QTYPE values, used in the question section of a DNS packet.
/// # NOTE
/// All TYPE values are a subset of QTYPES.
pub mod qtypes {
    /// A request for a transfer of an entire zone.
    pub const DNS_QTYPE_AXFR: u16 = 252;
    /// A request for mailbox-related records (MB, MG, or MR).
    pub const DNS_QTYPE_MAILB: u16 = 253;
    /// A request mail agent resource records (Obsolete - see MX).
    pub const DNS_QTYPE_MAILA: u16 = 254;
    /// A request for all records.
    pub const DNS_QTYPE_ANY: u16 = 255;
}

/// Example DNS query packets in network format
pub mod query_examples {
    pub const BASIC_QUERY: &'static [u8] = &[
        0x24, 0xB1, //ID
        0x01, 0x80, //QR=0,OPCODE=0,AA=0,TC=0,RD=1,RA=1,Z=0,RCODE=0
        0x00, 0x01, //QDCOUNT
        0x00, 0x00, //ANCOUNT
        0x00, 0x00, //NSCOUNT
        0x00, 0x00, //ARCOUNT
        0x03, 0x77, 0x77, 0x77, // www
        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // root
        0x00, 0x01, //QTYPE=1
        0x00, 0x01, //QCLASS=1
    ];

    pub const BASIC_QUERY_RESPONSE: &'static [u8] = &[
        0x24, 0xB1, //ID
        0x81, 0x80, //QR=1,OPCODE=0,AA=0,TC=0,RD=1,RA=1,Z=0,RCODE=0
        0x00, 0x01, //QDCOUNT
        0x00, 0x01, //ANCOUNT
        0x00, 0x00, //NSCOUNT
        0x00, 0x00, //ARCOUNT
        0x03, 0x77, 0x77, 0x77, // www
        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // root
        0x00, 0x01, //QTYPE=1
        0x00, 0x01, //QCLASS=1
        0xC0, 0x0C, 0x00, 0x01, //TYPE=1
        0x00, 0x01, //CLASS=1
        0x00, 0x00, 0x02, 0x58, // TTL=600
        0x00, 0x04, //RDLENGTH=4
        0xD8, 0x3A, 0xD9, 0x24, //RDATA = 216.58.217.36
    ];

    pub const NAME_COMPRESSION_QUERY: &'static [u8] = &[
        0x24, 0xB1, //ID
        0x01, 0x80, //QR=0,OPCODE=0,AA=0,TC=0,RD=1,RA=1,Z=0,RCODE=0
        0x00, 0x02, //QDCOUNT
        0x00, 0x00, //ANCOUNT
        0x00, 0x00, //NSCOUNT
        0x00, 0x00, //ARCOUNT
        0x03, 0x77, 0x77, 0x77, // www
        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // root
        0x00, 0x01, //QTYPE=1
        0x00, 0x01, //QCLASS=1
        0x07, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x65, 0x72, // pointer
        0xC0, 0x0C, // offset pointer to www.google.com.
        0x00, 0x02, //QTYPE=2
        0x00, 0x03, //QCLASS=3
    ];
}

/// Send a DNS packet to the given destination, returns the response
pub fn send_dns_query_to(
    dns_packet: &dns_packet::DnsPacket,
    destination: &String,
) -> Result<dns_packet::DnsPacket, String> {
    let client_socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("Client could not bind");

    let serialized_dns_packet = dns_packet.serialize()?;

    client_socket
        .send_to(&serialized_dns_packet, destination)
        .expect("Client could not send data");

    match client_socket.set_read_timeout(Some(std::time::Duration::from_secs(2))) {
        Ok(_) => {}
        Err(_) => {
            return Err("Could not set query socket timeout".into());
        }
    }

    let mut buf: [u8; 65535] = [0; 65535];
    let (amt, _) = client_socket
        .recv_from(&mut buf)
        .expect("Client could not recieve data from google dns");
    let buf = &buf[..amt];

    let dns_response = dns_packet::DnsPacket::parse_dns_packet(&buf.into())?;

    Ok(dns_response)
}

/// Resolve a domain name via DNS through a Google recursive resolver
pub fn resolve_domain_name(domain_name: &String) -> Result<std::net::Ipv4Addr, String> {
    let dns_packet = dns_packet::DnsPacket::new(domain_name, types::DNS_TYPE_A)?;

    let dns_response = send_dns_query_to(&dns_packet, &String::from("8.8.8.8:53"))?;

    match dns_response.header.rcode {
        rcodes::DNS_RCODE_NO_ERROR => {}
        _ => {
            return Err(format!(
                "Recursive resolver could not find {}, returned RCODE={}",
                domain_name, dns_response.header.rcode
            ));
        }
    }

    let position = dns_response
        .answer
        .iter()
        .position(|record| record.rrtype == types::DNS_TYPE_A)
        .ok_or("DNS response had no A records")?;

    match dns_response.answer[position].rdata {
        crate::dns_packet::dns_resource_record::DnsResourceRecordData::A(address) => {
            return Ok(address);
        }
        _ => {
            return Err("Did not match A resource record".into());
        }
    }
}
