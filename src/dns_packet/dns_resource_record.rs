use super::domain_name::*;
use crate::types::*;
use std::collections::HashMap;

//TODO Create resource record structure to handle individual rr types (A, AAAA, SOA, etc.)

/// Represents the data stored in DNS resource records
#[derive(Debug)]
pub enum DnsResourceRecordData {
    /// An IPv4 host address.
    A(std::net::Ipv4Addr),
    /// An authoritative name server.
    NS(String),
    /// A mail destination (Obsolete - replaced by MX).
    MD(String),
    /// A mail forwarder (Obsolete - replaced by MX).
    MF(String),
    /// The canonical name for an alias.
    CNAME(String),
    /// Marks the start of a zone of authority.
    SOA((String, String, u32, u32, u32, u32, u32)),
    /// A mailbox domain name.
    MB(String),
    /// A mail group member.
    MG(String),
    /// A mail rename domain name.
    MR(String),
    /// An experimental RR containing any possible data.
    NULL(Vec<u8>),
    /// A well known service description.
    WKS((u32, u8, Vec<u8>)),
    /// A domain name pointer.
    PTR(String),
    /// Host information.
    HINFO((String, String)),
    /// Mailbox or mail list information.
    MINFO((String, String)),
    /// Mail exchange.
    MX((u16, String)),
    /// Text strings.
    TXT(String),
    /// An IPv6 host address.
    AAAA(std::net::Ipv6Addr),
    /// Specifies location of a service for a specific protocol.
    SRV((u16, u16, u16, String)),
}

impl DnsResourceRecordData {
    /// Parse the data for a resource record from buf
    pub fn parse(
        rrtype: u16,
        buf: &Vec<u8>,
        start: usize,
        rdlength: u16,
    ) -> Result<(DnsResourceRecordData, usize), String> {
        let data: DnsResourceRecordData;
        match rrtype {
            DNS_TYPE_A => {
                if buf.len() != 4 {
                    return Err("rdata length incorrect for A record".into());
                }

                data = Self::A(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
            }
            DNS_TYPE_AAAA => {
                if rdlength != 16 {
                    return Err("rdata length incorrect for A record".into());
                }

                data = Self::AAAA(std::net::Ipv6Addr::new(
                    (buf[0] as u16) << 8 | buf[1] as u16,
                    (buf[2] as u16) << 8 | buf[3] as u16,
                    (buf[4] as u16) << 8 | buf[5] as u16,
                    (buf[6] as u16) << 8 | buf[7] as u16,
                    (buf[8] as u16) << 8 | buf[9] as u16,
                    (buf[10] as u16) << 8 | buf[11] as u16,
                    (buf[12] as u16) << 8 | buf[13] as u16,
                    (buf[14] as u16) << 8 | buf[15] as u16,
                ));
            }

            DNS_TYPE_CNAME => {
                let (cname, end) = parse_domain_name(buf, start, buf.len())?;
                start = end;
                data = Self::CNAME(cname);
            }

            DNS_TYPE_HINFO => {
                let (cpu, end) = parse_character_string(buf, start)?;
                start = end;
                let (os, end) = parse_character_string(buf, start)?;
                start = end;
                data = Self::HINFO((cpu, os));
            }
            _ => {
                return Err(format!("not supported resource record type {}", rrtype));
            }
        }

        Ok((data, start))
    }

    /// Serialize the resource record data into a DNS protocol network ready format
    pub fn serialize(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Pretty printing for the specific resource record data type
    pub fn to_string(&self) -> String {
        match self {
            DnsResourceRecordData::A(a) => return a.to_string(),
            _ => return String::from(""),
        }
    }
}

/// DNS Resource Record.
#[derive(Debug)]
pub struct DnsResourceRecord {
    /// Name of the resource record.
    pub name: String,
    /// Type of the resource record.
    pub rrtype: u16,
    /// Class of the resource record.
    pub class: u16,
    /// TTL (Time to Live) of the resource record.
    pub ttl: u32,
    /// Length in bytes of the resource record data.
    pub rdlength: u16,
    /// The actual data for the resource record.
    pub rdata: DnsResourceRecordData,
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
        rdata: DnsResourceRecordData,
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
            let rdata = DnsResourceRecordData::parse(rrtype, buf, start, rdlength)?;

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

        buf.append(&mut self.rdata.serialize());

        let start = start + buf.len();
        Ok((buf, start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classes::*, dns_packet::dns_header::*, query_examples::*};

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

        match resource_record.rdata {
            DnsResourceRecordData::A(address) => {
                assert_eq!(Ok(address), "216.58.217.36".parse());
            }
            _ => {
                return Err("Parsed resource record data was not A record data".into());
            }
        }

        Ok(())
    }
}
