use super::domain_name::*;
use std::collections::HashMap;

//TODO Create resource record structure to handle individual rr types (A, AAAA, SOA, etc.)

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
            let (name, end) = parse_domain_name(buf, start, buf.len())?;

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

        serialize_domain_name(&self.name, &mut buf, start, domain_name_offsets)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classes::*, dns_packet::dns_header::*, query_examples::*, types::*};

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
}
