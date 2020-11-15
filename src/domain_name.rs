use std::collections::HashMap;

// Should we use a seperate struct to represent domain names? Makes easier to not f up

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
            let res = parse_domain_name(buf, offset, curr);

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

    if !is_domain_name_valid(&domain_name) {
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

/// Will attempt to massage a given domain name into a valid one by removing leading '.' and append '.' to end
// TODO Should this be extended to be more aggressive/convert to IDNA?
// Should this remove whitespace at all? Maybe just dns specific things like dots
pub fn normalize_domain_name(domain_name: &String) -> String {
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
    domain_name_offsets: &mut HashMap<String, u16>,
) -> Result<(), String> {
    if !is_domain_name_valid(domain_name) {
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
                let label = &subdomain[0..subdomain.find('.').ok_or("subdomain had no \'.\'")?];

                // Max offset is 0x3FFF, since the two high order bits are always set.
                // If we go past the possible offset value, no point in storing pointer.
                if (buf.len()) <= 0x3FFFusize {
                    domain_name_offsets.insert(subdomain.into(), buf.len() as u16);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{query_examples::*, DNS_HEADER_SIZE};

    #[test]
    fn test_parse_domain_name() -> Result<(), String> {
        let query = &Vec::from(BASIC_QUERY);
        let correct_domain_name = String::from("www.google.com.");

        let (domain_name, end) = parse_domain_name(query, DNS_HEADER_SIZE, query.len())?;

        assert_eq!(domain_name, correct_domain_name);
        assert_eq!(end, 28);

        let correct_domain_name = String::from("pointer.www.google.com.");
        let query = &Vec::from(NAME_COMPRESSION_QUERY);

        let (domain_name, end) = parse_domain_name(query, 32, query.len())?;

        assert_eq!(domain_name, correct_domain_name);
        assert_eq!(end, 42);

        Ok(())
    }

    #[test]
    fn test_is_domain_name_valid() -> Result<(), String> {
        let domain_name = String::from("www.google.com.");

        assert!(is_domain_name_valid(&domain_name));

        let domain_name = String::from(
            "reallylongdomainnamelabelistoolongreallylongdomainnamelabelistoolong.google.com.",
        );
        assert!(!is_domain_name_valid(&domain_name));

        let domain_name = String::from("www.space inlabel.google.com.");
        assert!(!is_domain_name_valid(&domain_name));

        let domain_name = String::from(".beginswith.");
        assert!(!is_domain_name_valid(&domain_name));

        let domain_name = String::from("hasnoending.dot");
        assert!(!is_domain_name_valid(&domain_name));

        let domain_name = String::from("");
        assert!(!is_domain_name_valid(&domain_name));

        let domain_name = String::from(".");
        assert!(is_domain_name_valid(&domain_name));

        Ok(())
    }

    #[test]
    fn test_normalize_domain_name() -> Result<(), String> {
        Ok(())
    }
}
