use crate::{opcodes::*, rcodes::*, *};
use rand::prelude::*;

/// DNS Packet Header.
#[derive(Debug)]
pub struct DnsHeader {
    /// The ID for the DNS query and corresponding response.
    pub id: u16,
    /// The QR flag is false if the DNS packet is a query, true if it is a response.
    pub qr: bool,
    /// OPCODE for the query. Valid values are 0-2. See DNS_RFC_Notes.
    pub opcode: u8,
    /// The AA flag is false if the answer is non-authoritative, true otherwise.
    pub aa: bool,
    /// The TC flag is true if the DNS packet was truncated due to message length.
    pub tc: bool,
    /// The RD flag is set if recursion is desired during query resolution.
    pub rd: bool,
    /// The RA flag is set in a response if the answering server supports recursive query.
    pub ra: bool,
    /// The Z field is reserved per the DNS protocol, and must always be 0.
    pub z: u8,
    /// The RCODE field is the response from the answering server during query resolution.
    pub rcode: u8,
    /// QDCOUNT is the number of entries in the question section of the DNS packet.
    pub qdcount: u16,
    /// ANCOUNT is the number of entries in the answer section of the DNS packet.
    pub ancount: u16,
    /// NSCOUNT is the number of name server resource records in the authority section of the DNS packet.
    pub nscount: u16,
    /// ARCOUNT is the numer of entries in the additional section of the DNS packet.
    pub arcount: u16,
}

impl DnsHeader {
    pub fn new() -> Result<DnsHeader, String> {
        let header = DnsHeader {
            id: random(),
            qr: false,
            opcode: DNS_OPCODE_QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: DNS_RCODE_NO_ERROR,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        Ok(header)
    }

    /// Parse a DNS header from the start of a raw DNS packet.
    pub fn parse_dns_header(dns_packet_buf: &Vec<u8>) -> Result<DnsHeader, String> {
        if dns_packet_buf.len() < DNS_HEADER_SIZE {
            return Err("buf too short".into());
        }

        let id: u16 = (dns_packet_buf[0] as u16) << 8 | dns_packet_buf[1] as u16;
        let qr: bool = (dns_packet_buf[2] & 0x80) == 0x80;
        let opcode: u8 = (dns_packet_buf[2] & 0x78) >> 3;
        let aa: bool = (dns_packet_buf[2] & 0x4) == 0x4;
        let tc: bool = (dns_packet_buf[2] & 0x2) == 0x2;
        let rd: bool = (dns_packet_buf[2] & 0x1) == 0x1;
        let ra: bool = (dns_packet_buf[3] & 0x80) == 0x80;
        let z: u8 = (dns_packet_buf[3] & 0x70) >> 4;
        let rcode: u8 = dns_packet_buf[3] & 0xF;
        let qdcount: u16 = (dns_packet_buf[4] as u16) << 8 | dns_packet_buf[5] as u16;
        let ancount: u16 = (dns_packet_buf[6] as u16) << 8 | dns_packet_buf[7] as u16;
        let nscount: u16 = (dns_packet_buf[8] as u16) << 8 | dns_packet_buf[9] as u16;
        let arcount: u16 = (dns_packet_buf[10] as u16) << 8 | dns_packet_buf[11] as u16;

        let dns_header: DnsHeader = DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        };

        Ok(dns_header)
    }

    /// Serialize the DNS header into a DNS protocol conformant, network ready buffer.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(((self.id >> 8) & 0xFF) as u8);
        buf.push((self.id & 0xFF) as u8);

        buf.push(
            (self.qr as u8) << 7
                | self.opcode << 3
                | (self.aa as u8) << 2
                | (self.tc as u8) << 1
                | self.rd as u8,
        );

        buf.push((self.ra as u8) << 7 | self.z << 4 | (self.rcode as u8) & 0xF);

        buf.push(((self.qdcount >> 8) & 0xFF) as u8);
        buf.push((self.qdcount & 0xFF) as u8);

        buf.push(((self.ancount >> 8) & 0xFF) as u8);
        buf.push((self.ancount & 0xFF) as u8);

        buf.push(((self.nscount >> 8) & 0xFF) as u8);
        buf.push((self.nscount & 0xFF) as u8);

        buf.push(((self.arcount >> 8) & 0xFF) as u8);
        buf.push((self.arcount & 0xFF) as u8);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_examples::*;

    #[test]
    fn test_parse_dns_header() -> Result<(), String> {
        let query = &Vec::from(BASIC_QUERY);
        let dns_header = DnsHeader::parse_dns_header(query)?;

        assert_eq!(dns_header.id, 0x24B1);
        assert!(!dns_header.qr);
        assert_eq!(dns_header.opcode, DNS_OPCODE_QUERY);
        assert!(!dns_header.aa);
        assert!(!dns_header.tc);
        assert!(dns_header.rd);
        assert!(dns_header.ra);
        assert_eq!(dns_header.z, 0);
        assert_eq!(dns_header.rcode, DNS_RCODE_NO_ERROR);
        assert_eq!(dns_header.qdcount, 1);
        assert_eq!(dns_header.ancount, 0);
        assert_eq!(dns_header.nscount, 0);
        assert_eq!(dns_header.arcount, 0);

        Ok(())
    }
}
