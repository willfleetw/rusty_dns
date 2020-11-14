/// DNS Packet Header.
pub mod dns_header;

/// DNS Packet Question.
pub mod dns_question;

/// DNS Resource Record.
pub mod dns_resource_record;

use crate::domain_name::*;
use crate::{classes::*, *};
use dns_header::*;
use dns_question::*;
use dns_resource_record::*;

use std::collections::HashMap;

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
    pub fn new(domain_name: &String, resource_record_type: u16) -> Result<DnsPacket, String> {
        let mut header = DnsHeader::new()?;

        let domain_name = normalize_domain_name(domain_name);
        if !is_domain_name_valid(&domain_name) {
            return Err(format!("invalid domain name: {}", domain_name));
        }

        let question = vec![DnsQuestion {
            qname: domain_name,
            qtype: resource_record_type,
            qclass: DNS_CLASS_IN,
        }];

        header.qdcount = 1;

        let dns_packet = DnsPacket {
            header,
            question,
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };

        Ok(dns_packet)
    }

    /// Parse a DNS packet from a raw DNS packet.
    pub fn parse_dns_packet(dns_packet_buf: &Vec<u8>) -> Result<DnsPacket, String> {
        let header = DnsHeader::parse_dns_header(dns_packet_buf)?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_examples::*;

    #[test]
    fn test_serialize() -> Result<(), String> {
        let query = Vec::from(NAME_COMPRESSION_QUERY);

        let dns_packet = DnsPacket::parse_dns_packet(&query)?;

        let res = dns_packet.serialize()?;

        assert_eq!(query, res, "\nquery: {:02X?}\nres:   {:02X?}", query, res);

        Ok(())
    }
}
