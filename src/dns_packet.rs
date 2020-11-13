//TODO Create resource record structure to handle individual rr types (A, AAAA, SOA, etc.)
//TODO Enable printing for easy display

use crate::*;
use std::collections::HashMap;

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

/// DNS Packet Question.
#[derive(Debug)]
pub struct DnsQuestion {
    /// The domain name for the resource record that is being queried for.
    pub qname: String,
    /// The type of the resource record that is being queried for.
    pub qtype: u16,
    /// The class of the resource record that is being queried for.
    pub qclass: u16,
}

impl DnsQuestion {
    /// Parse an entry for the DNS packet question section from a raw dns packet.
    pub fn parse_dns_question(
        dns_packet_buf: &Vec<u8>,
        start: usize,
    ) -> Result<(DnsQuestion, usize), String> {
        let (qname, end) =
            DnsPacket::parse_domain_name(dns_packet_buf, start, dns_packet_buf.len())?;

        if end + 3 >= dns_packet_buf.len()
        // after successfull parse, end should always be first byte of qtype
        {
            return Err("question too short".into());
        }

        let qtype: u16 = (dns_packet_buf[end] as u16) << 8 | dns_packet_buf[end + 1] as u16;
        let qclass: u16 = (dns_packet_buf[end + 2] as u16) << 8 | dns_packet_buf[end + 3] as u16;

        let dns_question: DnsQuestion = DnsQuestion {
            qname,
            qtype,
            qclass,
        };

        Ok((dns_question, end + 4))
    }

    /// Parse the DNS question section from a raw dns packet.
    pub fn parse_questions(
        dns_packet_buf: &Vec<u8>,
        header: &DnsHeader,
        mut start: usize,
    ) -> Result<(Vec<DnsQuestion>, usize), String> {
        let mut questions: Vec<DnsQuestion> = Vec::new();

        for _ in 0..header.qdcount {
            let (question, end) = DnsQuestion::parse_dns_question(dns_packet_buf, start)?;

            start = end;
            questions.push(question);
        }

        Ok((questions, start))
    }

    /// Serialize the DNS question section into a DNS protocol conformant, network ready buffer.
    pub fn serialize(
        &self,
        start: usize,
        domain_name_offsets: &mut HashMap<String, u16>,
    ) -> Result<(Vec<u8>, usize), String> {
        let mut buf = Vec::new();

        DnsPacket::serialize_domain_name(&self.qname, &mut buf, start, domain_name_offsets)?;

        buf.push(((self.qtype >> 8) & 0xFF) as u8);
        buf.push((self.qtype & 0xFF) as u8);

        buf.push(((self.qclass >> 8) & 0xFF) as u8);
        buf.push((self.qclass & 0xFF) as u8);

        let start = start + buf.len();
        Ok((buf, start))
    }
}

/// DNS Resource Record.
#[derive(Debug)]
pub struct DnsResourceRecord {
    /// Name of the resource record.
    pub name: String,
    /// Type of the resoruce record.
    pub rrtype: u16,
    /// Class of the resource record.
    pub class: u16,
    /// TTL (Time to Live) of the resource record.
    pub ttl: u32,
    /// Length in bytes of the resource record data.
    pub rdlength: u16,
    /// The actual data for the resource record.
    pub rdata: Vec<u8>,
}
// any class/type combo not supported results in FORMERR responses?

impl DnsResourceRecord {
    /// Create a DNS resource record.
    pub fn new(
        name: String,
        rrtype: u16,
        class: u16,
        ttl: u32,
        rdlength: u16,
        rdata: Vec<u8>,
    ) -> Result<DnsResourceRecord, String> {
        let dns_resource_record = DnsResourceRecord {
            name,
            rrtype,
            class,
            ttl,
            rdlength,
            rdata,
        };

        Ok(dns_resource_record)
    }

    /// Parse a DNS resource record section (i.e. Answer, Additional) from a raw DNS packet.
    pub fn parse_resource_records(
        buf: &Vec<u8>,
        mut start: usize,
        rrcount: u16,
    ) -> Result<(Vec<DnsResourceRecord>, usize), String> {
        let mut resource_records = Vec::new();

        // This should be a seperate function.
        for _ in 0..rrcount {
            let (name, end) = DnsPacket::parse_domain_name(buf, start, buf.len())?;

            start = end;

            if start + 9 >= buf.len() {
                return Err("resource record too short, missing fields".into());
            }

            let rrtype = (buf[start] as u16) << 8 | buf[start + 1] as u16;
            let class = (buf[start + 2] as u16) << 8 | buf[start + 3] as u16;
            let ttl = (buf[start + 4] as u32) << 24
                | (buf[start + 5] as u32) << 16
                | (buf[start + 6] as u32) << 8
                | buf[start + 7] as u32;
            let rdlength = (buf[start + 8] as u16) << 8 | (buf[start + 9] as u16);

            start += 10;

            if start + rdlength as usize > buf.len() {
                return Err("resource record too short, no rdata".into());
            }

            // we need to figure out how to hold a thing of any type
            // most likely will be some inheritence, which supports some parse/serialize funcs
            let rdata = Vec::from(&buf[start..start + rdlength as usize]);

            let dns_resource_record =
                DnsResourceRecord::new(name, rrtype, class, ttl, rdlength, rdata)?;

            resource_records.push(dns_resource_record);

            start += rdlength as usize;
        }

        Ok((resource_records, start))
    }

    /// Serialize the DNS resource records into a DNS protocol conformant, network ready buffer.
    pub fn serialize(
        &self,
        start: usize,
        domain_name_offsets: &mut HashMap<String, u16>,
    ) -> Result<(Vec<u8>, usize), String> {
        let mut buf = Vec::new();

        DnsPacket::serialize_domain_name(&self.name, &mut buf, start, domain_name_offsets)?;

        buf.push(((self.rrtype >> 8) & 0xFF) as u8);
        buf.push((self.rrtype & 0xFF) as u8);

        buf.push(((self.class >> 8) & 0xFF) as u8);
        buf.push((self.class & 0xFF) as u8);

        buf.push(((self.ttl >> 24) & 0xFF) as u8);
        buf.push(((self.ttl >> 16) & 0xFF) as u8);
        buf.push(((self.ttl >> 8) & 0xFF) as u8);
        buf.push((self.ttl & 0xFF) as u8);

        buf.push(((self.rdlength >> 8) & 0xFF) as u8);
        buf.push((self.rdlength & 0xFF) as u8);

        buf.append(&mut self.rdata.clone());

        let start = start + buf.len();
        Ok((buf, start))
    }
}

/// DNS Packet.
#[derive(Debug)]
pub struct DnsPacket {
    /// DNS Header for the DNS packet.
    pub header: DnsHeader,
    /// DNS Question section for the DNS packet.
    pub question: Vec<DnsQuestion>,
    /// DNS Answer section for the DNS packet.
    pub answer: Vec<DnsResourceRecord>,
    /// DNS Authority section for the DNS packet.
    pub authority: Vec<DnsResourceRecord>,
    /// DNS Additonal section for the DNS packet.
    pub additional: Vec<DnsResourceRecord>,
}

impl DnsPacket {
    /// Parse a DNS packet from a raw DNS packet.
    pub fn parse_dns_packet(dns_packet_buf: &Vec<u8>) -> Result<DnsPacket, String> {
        let header: DnsHeader = DnsHeader::parse_dns_header(dns_packet_buf)?;

        let start = DNS_HEADER_SIZE;
        let (questions, start) = DnsQuestion::parse_questions(dns_packet_buf, &header, start)?;
        let (answers, start) =
            DnsResourceRecord::parse_resource_records(dns_packet_buf, start, header.ancount)?;
        let (authorities, start) =
            DnsResourceRecord::parse_resource_records(dns_packet_buf, start, header.nscount)?;
        let (additionals, _) =
            DnsResourceRecord::parse_resource_records(dns_packet_buf, start, header.arcount)?;

        let dns_packet: DnsPacket = DnsPacket {
            header,
            question: questions,
            answer: answers,
            authority: authorities,
            additional: additionals,
        };

        Ok(dns_packet)
    }

    /// Serialize the DNS packet into a DNS protocol conformant, network ready buffer.
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        let mut domain_name_offsets = HashMap::new();

        buf.append(&mut self.header.serialize());

        let mut curr_index = DNS_HEADER_SIZE;

        for question in &self.question {
            let (mut question_buf, end) =
                question.serialize(curr_index, &mut domain_name_offsets)?;
            buf.append(&mut question_buf);
            curr_index = end;
        }

        for resource_record in &self.answer {
            let (mut record_buf, end) =
                resource_record.serialize(curr_index, &mut domain_name_offsets)?;
            buf.append(&mut record_buf);
            curr_index = end;
        }

        for resource_record in &self.authority {
            let (mut record_buf, end) =
                resource_record.serialize(curr_index, &mut domain_name_offsets)?;
            buf.append(&mut record_buf);
            curr_index = end;
        }

        for resource_record in &self.additional {
            let (mut record_buf, end) =
                resource_record.serialize(curr_index, &mut domain_name_offsets)?;
            buf.append(&mut record_buf);
            curr_index = end;
        }

        Ok(buf)
    }

    /// Parse a DNS domain name from a raw DNS packet, taking into account DNS message compression.
    pub fn parse_domain_name(
        buf: &Vec<u8>,
        start: usize,
        limit: usize,
    ) -> Result<(String, usize), String> {
        if buf.is_empty() {
            return Err("buf is empty".into());
        } else if start >= buf.len() || start >= limit {
            return Err("start is past buf's end or limit".into());
        }

        let mut domain_name = String::new();
        let mut curr = start;

        while (curr as usize) < buf.len() {
            let label_length = buf[curr] as usize;

            if label_length == 0
            //null label = root zone
            {
                curr = curr + 1;
                break;
            } else if (label_length & 0xC0usize) == 0xC0usize
            //message compression pointer
            {
                if curr + 1 >= buf.len() {
                    return Err("domain name pointer appears at end of buf".into());
                }

                let offset = (label_length & 0x3Fusize) << 8 | buf[curr + 1] as usize & 0xFFusize;
                let res = DnsPacket::parse_domain_name(buf, offset, curr);

                match res {
                    Ok((domain_name_suffix, _)) => {
                        domain_name.push_str(domain_name_suffix.as_str());
                    }
                    Err(error) => {
                        return Err(format!("error parsing domain name pointer: {}", error).into());
                    }
                };

                curr += 2;

                break;
            } else if (label_length + curr) >= buf.len() {
                return Err("domain name label length octet too large".into());
            } else {
                let mut label = String::new();
                for ch in buf[curr + 1..curr + label_length + 1].iter() {
                    label.push(*ch as char);
                }
                domain_name.push_str(label.as_str());
                domain_name.push('.');

                curr += label_length + 1;
            }
        }

        if !DnsPacket::is_domain_name_valid(&domain_name) {
            return Err(format!("invalid domain name: {}", domain_name));
        }

        Ok((domain_name, curr))
    }

    /// Returns true if domain_name represents a valid DNS domain name.
    pub fn is_domain_name_valid(domain_name: &String) -> bool {
        if domain_name == "." {
            return true;
        } else if domain_name.is_empty() || domain_name.starts_with(".") {
            return false;
        }

        /*
         IDNA was proposed in RFC 3490, but it only applies to application code. We are not that.
         We won't handle punycode, but instead just ensure that the domain names are valid per
         RFC 1035.

         Each label must:
          1. start with a letter
          2. End with a letter or digit
          3. Have as interior characters only letters, digits, and hyphen.
          4. Must be 63 characters or less. (This means first two bits of all labels are always 0).
        */
        for label in domain_name.split_terminator('.') {
            if label.len() > 63
                || !label.starts_with(|c: char| c.is_ascii_alphabetic())
                || !label.ends_with(|c: char| c.is_ascii_alphanumeric())
                || label.contains(|c: char| c != '-' && !c.is_ascii_alphanumeric())
            {
                return false;
            }
        }

        domain_name.ends_with('.')
    }

    // Will attempt to massage a given domain name into a valid one
    // Remove leading '.' and whitespace, append '.' to end
    // TODO Should this be extended to be more aggressive/convert to IDNA?
    // Should this remove whitespace at all? Maybe just dns specific things like dots
    fn normalize_domain_name(domain_name: &String) -> String {
        if domain_name.is_empty() || domain_name == "." {
            return domain_name.clone();
        }

        let mut domain_name: String = domain_name
            .strip_prefix(".")
            .or(Some(domain_name))
            .unwrap()
            .into();

        if !domain_name.ends_with('.') {
            domain_name.push('.');
        }

        domain_name
    }

    /// Serialize domain_name into a DNS protocol conformant, network ready buffer, using message compression.
    pub fn serialize_domain_name(
        domain_name: &String,
        buf: &mut Vec<u8>,
        start: usize,
        domain_name_offsets: &mut HashMap<String, u16>,
    ) -> Result<(), String> {
        if !DnsPacket::is_domain_name_valid(domain_name) {
            return Err(format!("invalid domain name: {}", domain_name));
        }
        let mut subdomain = &domain_name[0..domain_name.len()];

        loop {
            if subdomain.is_empty() || subdomain == "." {
                buf.push(0);
                break;
            }

            match domain_name_offsets.get(subdomain) {
                Some(offset) => {
                    buf.push(((offset >> 8) & 0x3F) as u8 | 0xC0);
                    buf.push((offset & 0xFF) as u8);
                    break;
                }
                None => {
                    let label =
                        &subdomain[0..subdomain.find('.').ok_or("subdomain had no \'.\'")?];

                    // Max offset is 0x3FFF, since the two high order bits are always set.
                    // If we go past the possible offset value, no point in storing pointer.
                    if (start + buf.len()) <= 0x3FFFusize {
                        domain_name_offsets.insert(subdomain.into(), (start + buf.len()) as u16);
                    }

                    buf.push(label.len() as u8);

                    for ch in label.chars() {
                        buf.push(ch as u8);
                    }

                    subdomain = &subdomain
                        [subdomain.find('.').ok_or("subdomain had no \'.\'")? + 1..subdomain.len()];
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{*, opcodes::*, rcodes::*, types::*, classes::*};

    const BASIC_QUERY: &'static [u8] = &[
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

    const BASIC_QUERY_RESPONSE: &'static [u8] = &[
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

    const NAME_COMPRESSION_QUERY: &'static [u8] = &[
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

    #[test]
    fn test_dns_header_new() -> Result<(), String> {
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

    #[test]
    fn test_parse_domain_name() -> Result<(), String> {
        let query = &Vec::from(BASIC_QUERY);
        let correct_domain_name = String::from("www.google.com.");

        let (domain_name, end) = DnsPacket::parse_domain_name(query, DNS_HEADER_SIZE, query.len())?;

        assert_eq!(domain_name, correct_domain_name);
        assert_eq!(end, 28);

        let correct_domain_name = String::from("pointer.www.google.com.");
        let query = &Vec::from(NAME_COMPRESSION_QUERY);

        let (domain_name, end) = DnsPacket::parse_domain_name(query, 32, query.len())?;

        assert_eq!(domain_name, correct_domain_name);
        assert_eq!(end, 42);

        Ok(())
    }

    #[test]
    fn test_parse_questions() -> Result<(), String> {
        let correct_domain_name = String::from("www.google.com.");

        let query = &Vec::from(BASIC_QUERY);

        let header = DnsHeader::parse_dns_header(query)?;
        let (questions, end) = DnsQuestion::parse_questions(query, &header, DNS_HEADER_SIZE)?;

        assert_eq!(questions.len(), 1);
        assert_eq!(end, 32);

        let question = &questions[0];
        assert_eq!(question.qname, correct_domain_name);
        assert_eq!(question.qtype, DNS_TYPE_A);
        assert_eq!(question.qclass, DNS_CLASS_IN);

        let query = &Vec::from(NAME_COMPRESSION_QUERY);

        let header = DnsHeader::parse_dns_header(query)?;
        let (questions, end) = DnsQuestion::parse_questions(query, &header, DNS_HEADER_SIZE)?;

        assert_eq!(questions.len(), 2);
        assert_eq!(end, query.len());

        let question = &questions[0];
        assert_eq!(question.qname, correct_domain_name);
        assert_eq!(question.qtype, DNS_TYPE_A);
        assert_eq!(question.qclass, DNS_CLASS_IN);

        let correct_domain_name = String::from("pointer.www.google.com.");

        let question = &questions[1];
        assert_eq!(question.qname, correct_domain_name);
        assert_eq!(question.qtype, DNS_TYPE_NS);
        assert_eq!(question.qclass, DNS_CLASS_CH);

        Ok(())
    }

    #[test]
    fn test_parse_dns_resource_records() -> Result<(), String> {
        let query = &Vec::from(BASIC_QUERY_RESPONSE);
        let header = &DnsHeader::parse_dns_header(query)?;
        let (resource_records, _) =
            DnsResourceRecord::parse_resource_records(query, 32, header.ancount)?;

        assert_eq!(resource_records.len(), 1);

        let resource_record = &resource_records[0];
        let correct_resource_record_name = String::from("www.google.com.");

        assert_eq!(resource_record.name, correct_resource_record_name);
        assert_eq!(resource_record.rrtype, DNS_TYPE_A);
        assert_eq!(resource_record.class, DNS_CLASS_IN);
        assert_eq!(resource_record.ttl, 600);
        assert_eq!(resource_record.rdlength, 4);

        let rdata = &resource_record.rdata;
        let a_address = std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);

        assert_eq!(Ok(a_address), "216.58.217.36".parse());

        Ok(())
    }

    #[test]
    fn test_serialize() -> Result<(), String> {
        let query = Vec::from(NAME_COMPRESSION_QUERY);

        let dns_packet = DnsPacket::parse_dns_packet(&query)?;

        let res = dns_packet.serialize()?;

        assert_eq!(query, res, "\nquery: {:02X?}\nres:   {:02X?}", query, res);

        Ok(())
    }

    #[test]
    fn test_is_domain_name_valid() -> Result<(), String> {
        let domain_name = String::from("www.google.com.");

        assert!(DnsPacket::is_domain_name_valid(&domain_name));

        let domain_name = String::from(
            "reallylongdomainnamelabelistoolongreallylongdomainnamelabelistoolong.google.com.",
        );
        assert!(!DnsPacket::is_domain_name_valid(&domain_name));

        let domain_name = String::from("www.space inlabel.google.com.");
        assert!(!DnsPacket::is_domain_name_valid(&domain_name));

        let domain_name = String::from(".beginswith.");
        assert!(!DnsPacket::is_domain_name_valid(&domain_name));

        let domain_name = String::from("hasnoending.dot");
        assert!(!DnsPacket::is_domain_name_valid(&domain_name));

        let domain_name = String::from("");
        assert!(!DnsPacket::is_domain_name_valid(&domain_name));

        let domain_name = String::from(".");
        assert!(DnsPacket::is_domain_name_valid(&domain_name));

        Ok(())
    }

    #[test]
    fn test_normalize_domain_name() -> Result<(), String> {
        Ok(())
    }
}
