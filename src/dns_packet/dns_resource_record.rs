use super::domain_name::*;
use crate::types::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse character string from buf
pub fn parse_character_string(
    buf: &Vec<u8>,
    start: usize,
    limit: usize,
) -> Result<(String, usize), String> {
    if start >= buf.len() {
        return Err(format!("start={} is past buf.len()={}", start, buf.len()));
    }

    let mut curr = start;

    let string_length = buf[curr] as usize;
    curr += 1;
    let end = string_length + curr;
    if end > buf.len() {
        return Err(format!(
            "character-string length {} is past buf.len()={}",
            string_length,
            buf.len()
        ));
    } else if end > limit {
        return Err(format!(
            "character-string length {} is past buf.len()={}",
            string_length,
            buf.len()
        ));
    }

    let mut character_string = String::from("");
    for ch in &buf[curr..end] {
        character_string.push(*ch as char);
    }

    Ok((character_string, end))
}

pub fn serialize_character_string(
    character_string: &String,
    buf: &mut Vec<u8>,
) -> Result<(), String> {
    // max length of character_string is 255 characters, plus the length octet
    if character_string.len() >= 256 {
        return Err(format!(
            "character_string length {} >= 256",
            character_string.len()
        ));
    }

    buf.push(character_string.len() as u8);
    for ch in character_string.chars() {
        buf.push(ch as u8);
    }

    Ok(())
}

/// Represents the data stored in DNS resource records
#[derive(Debug)]
pub enum DnsResourceRecordData {
    /// An IPv4 host address.
    A(Ipv4Addr),
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
    WKS((Ipv4Addr, u8, Vec<u8>)),
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
    AAAA(Ipv6Addr),
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
    ) -> Result<DnsResourceRecordData, String> {
        let limit = start + rdlength as usize;

        let data: DnsResourceRecordData;

        match rrtype {
            DNS_TYPE_A => {
                if rdlength != 4 {
                    return Err("rdata length incorrect for A record".into());
                }

                data = Self::A(Ipv4Addr::new(
                    buf[start],
                    buf[start + 1],
                    buf[start + 2],
                    buf[start + 3],
                ));
            }
            DNS_TYPE_AAAA => {
                if rdlength != 16 {
                    return Err("rdata length incorrect for A record".into());
                }
                data = Self::AAAA(Ipv6Addr::new(
                    (buf[start + 0] as u16) << 8 | buf[1] as u16,
                    (buf[start + 2] as u16) << 8 | buf[start + 3] as u16,
                    (buf[start + 4] as u16) << 8 | buf[start + 5] as u16,
                    (buf[start + 6] as u16) << 8 | buf[start + 7] as u16,
                    (buf[start + 8] as u16) << 8 | buf[start + 9] as u16,
                    (buf[start + 10] as u16) << 8 | buf[start + 11] as u16,
                    (buf[start + 12] as u16) << 8 | buf[start + 13] as u16,
                    (buf[start + 14] as u16) << 8 | buf[start + 15] as u16,
                ));
            }
            DNS_TYPE_CNAME => {
                let (cname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::CNAME(cname);
            }
            DNS_TYPE_MX => {
                if rdlength <= 2 {
                    return Err(format!("{} is too short an rdlength for type MX", rdlength));
                }

                let preference = (buf[start] as u16) << 8 | buf[start + 1] as u16;
                let (exchange, _) = parse_domain_name(buf, start + 2, limit)?;

                data = Self::MX((preference, exchange));
            }
            DNS_TYPE_NS => {
                let (nsdname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::NS(nsdname);
            }
            DNS_TYPE_PTR => {
                let (ptrdname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::PTR(ptrdname);
            }
            DNS_TYPE_SOA => {
                let (mname, end) = parse_domain_name(buf, start, limit)?;
                let (rname, end) = parse_domain_name(buf, end, limit)?;

                if (rdlength - (end - start) as u16) < 20 {
                    // not enough to parse remaining fields
                    return Err(format!(
                        "{} is too short an rdlength for given SOA record",
                        rdlength
                    ));
                }

                let serial = (buf[end] as u32) << 24
                    | (buf[end + 1] as u32) << 16
                    | (buf[end + 2] as u32) << 8
                    | buf[end + 3] as u32;
                let refresh = (buf[end + 4] as u32) << 24
                    | (buf[end + 5] as u32) << 16
                    | (buf[end + 6] as u32) << 8
                    | buf[end + 7] as u32;
                let retry = (buf[end + 8] as u32) << 24
                    | (buf[end + 9] as u32) << 16
                    | (buf[end + 10] as u32) << 8
                    | buf[end + 11] as u32;
                let expire = (buf[end + 12] as u32) << 24
                    | (buf[end + 13] as u32) << 16
                    | (buf[end + 14] as u32) << 8
                    | buf[end + 15] as u32;
                let minimum = (buf[end + 16] as u32) << 24
                    | (buf[end + 17] as u32) << 16
                    | (buf[end + 18] as u32) << 8
                    | buf[end + 19] as u32;

                data = Self::SOA((mname, rname, serial, refresh, retry, expire, minimum));
            }
            DNS_TYPE_TXT => {
                let (txtdata, _) = parse_character_string(buf, start, limit)?;

                data = Self::TXT(txtdata);
            }
            DNS_TYPE_SRV => {
                if rdlength < 7 {
                    return Err(format!(
                        "{} is too short an rdlength for an SRV record",
                        rdlength
                    ));
                }

                let priority = (buf[start] as u16) << 8 | buf[start + 1] as u16;
                let weight = (buf[start + 2] as u16) << 8 | buf[start + 3] as u16;
                let port = (buf[start + 4] as u16) << 8 | buf[start + 5] as u16;
                let (target, _) = parse_domain_name(buf, start, limit)?;

                data = Self::SRV((priority, weight, port, target));
            }
            DNS_TYPE_NULL => {
                data = Self::NULL(Vec::from(&buf[start..limit]));
            }
            DNS_TYPE_WKS => {
                if rdlength < 5 {
                    return Err(format!(
                        "{} is too short an rdlength for a WKS record",
                        rdlength
                    ));
                }

                let address =
                    Ipv4Addr::new(buf[start], buf[start + 1], buf[start + 2], buf[start + 3]);

                let protocol = buf[start + 4];
                let bitmap = Vec::from(&buf[start + 5..limit]);

                data = Self::WKS((address, protocol, bitmap));
            }
            DNS_TYPE_HINFO => {
                let (cpu, end) = parse_character_string(buf, start, limit)?;
                let (os, _) = parse_character_string(buf, end, limit)?;
                data = Self::HINFO((cpu, os));
            }
            DNS_TYPE_MB => {
                let (madname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::MB(madname);
            }
            DNS_TYPE_MD => {
                let (madname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::MD(madname);
            }
            DNS_TYPE_MF => {
                let (madname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::MF(madname);
            }
            DNS_TYPE_MG => {
                let (madname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::MG(madname);
            }
            DNS_TYPE_MR => {
                let (newname, _) = parse_domain_name(buf, start, limit)?;

                data = Self::MR(newname);
            }
            DNS_TYPE_MINFO => {
                let (rmailbx, end) = parse_domain_name(buf, start, limit)?;
                let (emailbx, _) = parse_domain_name(buf, end, limit)?;
                data = Self::MINFO((rmailbx, emailbx));
            }
            _ => {
                return Err(format!("not supported resource record type {}", rrtype));
            }
        }

        Ok(data)
    }

    /// Serialize the resource record data into a DNS protocol network ready format
    pub fn serialize(
        &self,
        buf: &mut Vec<u8>,
        domain_name_offsets: &mut HashMap<String, u16>,
    ) -> Result<(), String> {
        match self {
            Self::A(address) => {
                buf.append(&mut Vec::from(address.octets()));
            }
            Self::AAAA(address) => {
                buf.append(&mut Vec::from(address.octets()));
            }
            Self::CNAME(cname) => {
                serialize_domain_name(cname, buf, &mut HashMap::new())?;
            }
            Self::NS(nsdname) => {
                serialize_domain_name(nsdname, buf, &mut HashMap::new())?;
            }
            Self::MX((preference, exchange)) => {
                buf.push(((preference & 0xFF00) >> 8) as u8);
                buf.push((preference & 0xFF) as u8);
                serialize_domain_name(exchange, buf, &mut HashMap::new())?;
            }
            Self::PTR(ptrdname) => {
                serialize_domain_name(ptrdname, buf, &mut HashMap::new())?;
            }
            Self::SOA((mname, rname, serial, refresh, retry, expire, minimum)) => {
                serialize_domain_name(mname, buf, domain_name_offsets)?;
                serialize_domain_name(rname, buf, domain_name_offsets)?;
                buf.push(((serial & 0xFF000000) >> 24) as u8);
                buf.push(((serial & 0xFF0000) >> 16) as u8);
                buf.push(((serial & 0xFF00) >> 8) as u8);
                buf.push((serial & 0xFF) as u8);
                buf.push(((refresh & 0xFF000000) >> 24) as u8);
                buf.push(((refresh & 0xFF0000) >> 16) as u8);
                buf.push(((refresh & 0xFF00) >> 8) as u8);
                buf.push((refresh & 0xFF) as u8);
                buf.push(((retry & 0xFF000000) >> 24) as u8);
                buf.push(((retry & 0xFF0000) >> 16) as u8);
                buf.push(((retry & 0xFF00) >> 8) as u8);
                buf.push((retry & 0xFF) as u8);
                buf.push(((expire & 0xFF000000) >> 24) as u8);
                buf.push(((expire & 0xFF0000) >> 16) as u8);
                buf.push(((expire & 0xFF00) >> 8) as u8);
                buf.push((expire & 0xFF) as u8);
                buf.push(((minimum & 0xFF000000) >> 24) as u8);
                buf.push(((minimum & 0xFF0000) >> 16) as u8);
                buf.push(((minimum & 0xFF00) >> 8) as u8);
                buf.push((minimum & 0xFF) as u8);
            }
            Self::NULL(data) => {
                buf.append(&mut data.clone());
            }
            Self::TXT(txt_data) => {
                serialize_character_string(txt_data, buf)?;
            }
            Self::SRV((priority, weight, port, target)) => {
                buf.push(((priority & 0xFF00) >> 8) as u8);
                buf.push((priority & 0xFF) as u8);
                buf.push(((weight & 0xFF00) >> 8) as u8);
                buf.push((weight & 0xFF) as u8);
                buf.push(((port & 0xFF00) >> 8) as u8);
                buf.push((port & 0xFF) as u8);
                serialize_domain_name(target, buf, domain_name_offsets)?;
            }
            Self::WKS((address, protocol, bit_map)) => {
                buf.append(&mut Vec::from(address.octets()));
                buf.push(*protocol);
                buf.append(&mut bit_map.clone());
            }
            Self::MD(madname) => {
                serialize_domain_name(madname, buf, domain_name_offsets)?;
            }
            Self::MB(madname) => {
                serialize_domain_name(madname, buf, domain_name_offsets)?;
            }
            Self::MF(madname) => {
                serialize_domain_name(madname, buf, domain_name_offsets)?;
            }
            Self::MR(madname) => {
                serialize_domain_name(madname, buf, domain_name_offsets)?;
            }
            Self::MG(madname) => {
                serialize_domain_name(madname, buf, domain_name_offsets)?;
            }
            Self::HINFO((cpu, os)) => {
                serialize_character_string(cpu, buf)?;
                serialize_character_string(os, buf)?;
            }
            Self::MINFO((rmailbx, emailbx)) => {
                serialize_domain_name(rmailbx, buf, domain_name_offsets)?;
                serialize_domain_name(emailbx, buf, domain_name_offsets)?;
            }
        }

        Ok(())
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
        buf: &mut Vec<u8>,
        domain_name_offsets: &mut HashMap<String, u16>,
    ) -> Result<usize, String> {
        serialize_domain_name(&self.name, buf, domain_name_offsets)?;

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

        let computed_rdlength = buf.len();
        self.rdata.serialize(buf, domain_name_offsets)?;
        let computed_rdlength = buf.len() - computed_rdlength;
        if computed_rdlength != self.rdlength as usize {
            return Err(format!(
                "rdlength {} does not match computed rdlength {}",
                self.rdlength, computed_rdlength
            ));
        }

        let start = start + buf.len();
        Ok(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classes::*, dns_packet::dns_header::*, query_examples::*};

    mod example_rrtypes {
        pub const A: &'static [u8] = &[0x7F, 0x00, 0x00, 0x01]; // 127.0.0.1

        pub const CNAME: &'static [u8] = &[
            0x03, 0x77, 0x77, 0x77, // www
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com
            0x00, // root
        ];

        pub const MX: &'static [u8] = &[
            0x01, 0xA4, // PREFERENCE = 420
            0x03, 0x77, 0x77, 0x77, // www
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com
            0x00, // root
        ];

        pub const SOA: &'static [u8] = &[
            0x03, 0x77, 0x77, 0x77, // www
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com
            0x00, // root
            0xC0, 0x04, // domain name pointer to "google.com."
            0x00, 0x00, 0x00, 0x01, // 1
            0x00, 0x00, 0x00, 0x10, // 16
            0x00, 0x00, 0x01, 0x00, // 256
            0x00, 0x00, 0x10, 0x00, // 4096
            0x00, 0x01, 0x00, 0x00, // 65,536
        ];

        pub const TXT: &'static [u8] = &[
            0x0B, // length=11
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, // "Hello World"
        ];
    }
    use example_rrtypes::*;

    #[test]
    fn test_parse_dns_resource_records() -> Result<(), String> {
        let query = &Vec::from(BASIC_QUERY_RESPONSE);
        let header = &DnsHeader::parse(query)?;
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

    #[test]
    fn test_parse_dns_resource_record_data() -> Result<(), String> {
        let record_data_buf = Vec::from(A);
        let record_data = DnsResourceRecordData::parse(
            DNS_TYPE_A,
            &record_data_buf,
            0,
            record_data_buf.len() as u16,
        )?;
        assert!(match record_data {
            DnsResourceRecordData::A(data) => {
                data == Ipv4Addr::new(127, 0, 0, 1)
            }
            _ => {
                false
            }
        });

        let record_data_buf = Vec::from(CNAME);
        let record_data = DnsResourceRecordData::parse(
            DNS_TYPE_CNAME,
            &record_data_buf,
            0,
            record_data_buf.len() as u16,
        )?;
        assert!(match record_data {
            DnsResourceRecordData::CNAME(data) => {
                data == "www.google.com."
            }
            _ => {
                false
            }
        });

        let record_data_buf = Vec::from(MX);
        let record_data = DnsResourceRecordData::parse(
            DNS_TYPE_MX,
            &record_data_buf,
            0,
            record_data_buf.len() as u16,
        )?;
        assert!(match record_data {
            DnsResourceRecordData::MX(data) => {
                data == (420, "www.google.com.".into())
            }
            _ => {
                false
            }
        });

        let record_data_buf = Vec::from(SOA);
        let record_data = DnsResourceRecordData::parse(
            DNS_TYPE_SOA,
            &record_data_buf,
            0,
            record_data_buf.len() as u16,
        )?;
        assert!(match record_data {
            DnsResourceRecordData::SOA(data) => {
                data == (
                    "www.google.com.".into(),
                    "google.com.".into(),
                    1,
                    16,
                    256,
                    4096,
                    65536,
                )
            }
            _ => {
                false
            }
        });

        Ok(())
    }

    #[test]
    fn test_serialize_dns_resource_record_data() -> Result<(), String> {
        let record_data_buf = Vec::from(A);
        let record_data =
            DnsResourceRecordData::parse(DNS_TYPE_A, &record_data_buf, 0, A.len() as u16)?;
        let record_data_serialized = &mut Vec::new();
        record_data.serialize(record_data_serialized, &mut HashMap::new())?;

        assert_eq!(A, *record_data_serialized);

        let record_data_buf = Vec::from(CNAME);
        let record_data =
            DnsResourceRecordData::parse(DNS_TYPE_CNAME, &record_data_buf, 0, CNAME.len() as u16)?;
        let record_data_serialized = &mut Vec::new();
        record_data.serialize(record_data_serialized, &mut HashMap::new())?;

        assert_eq!(CNAME, *record_data_serialized);

        let record_data_buf = Vec::from(SOA);
        let record_data =
            DnsResourceRecordData::parse(DNS_TYPE_SOA, &record_data_buf, 0, SOA.len() as u16)?;
        let record_data_serialized = &mut Vec::new();
        record_data.serialize(record_data_serialized, &mut HashMap::new())?;

        assert_eq!(SOA, *record_data_serialized);

        let record_data_buf = Vec::from(TXT);
        let record_data =
            DnsResourceRecordData::parse(DNS_TYPE_TXT, &record_data_buf, 0, TXT.len() as u16)?;
        let record_data_serialized = &mut Vec::new();
        record_data.serialize(record_data_serialized, &mut HashMap::new())?;

        assert_eq!(TXT, *record_data_serialized);

        let record_data_buf = Vec::from(MX);
        let record_data =
            DnsResourceRecordData::parse(DNS_TYPE_MX, &record_data_buf, 0, MX.len() as u16)?;
        let record_data_serialized = &mut Vec::new();
        record_data.serialize(record_data_serialized, &mut HashMap::new())?;

        assert_eq!(MX, *record_data_serialized);

        Ok(())
    }

    #[test]
    fn test_parse_character_string() -> Result<(), String> {
        let buf = Vec::from(TXT);

        let (character_string, end) = parse_character_string(&buf, 0, buf.len())?;

        assert_eq!(character_string, String::from("Hello World"));
        assert_eq!(end, buf.len());

        Ok(())
    }
}
