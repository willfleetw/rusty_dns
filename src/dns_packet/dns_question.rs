use super::{dns_header::*, domain_name::*};
use std::collections::HashMap;

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
        let (qname, end) = parse_domain_name(dns_packet_buf, start, dns_packet_buf.len())?;

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

        serialize_domain_name(&self.qname, &mut buf, start, domain_name_offsets)?;

        buf.push(((self.qtype >> 8) & 0xFF) as u8);
        buf.push((self.qtype & 0xFF) as u8);

        buf.push(((self.qclass >> 8) & 0xFF) as u8);
        buf.push((self.qclass & 0xFF) as u8);

        let start = start + buf.len();
        Ok((buf, start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classes::*, query_examples::*, types::*, DNS_HEADER_SIZE};

    #[test]
    fn test_parse_questions() -> Result<(), String> {
        let correct_domain_name = String::from("www.google.com.");

        let query = &Vec::from(BASIC_QUERY);

        let header = DnsHeader::parse(query)?;
        let (questions, end) = DnsQuestion::parse_questions(query, &header, DNS_HEADER_SIZE)?;

        assert_eq!(questions.len(), 1);
        assert_eq!(end, 32);

        let question = &questions[0];
        assert_eq!(question.qname, correct_domain_name);
        assert_eq!(question.qtype, DNS_TYPE_A);
        assert_eq!(question.qclass, DNS_CLASS_IN);

        let query = &Vec::from(NAME_COMPRESSION_QUERY);

        let header = DnsHeader::parse(query)?;
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
}
