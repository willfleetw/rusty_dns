use rusty_dns::{dns_packet::*, rcodes::*, types::*};

#[test]
fn test_basic_dns_resolution() -> Result<(), String> {
    let dns_packet = DnsPacket::new(&String::from("www.google.com."), DNS_TYPE_A)?;
    println!("dns_packet:\n{:#?}", dns_packet);

    let dns_response = rusty_dns::send_dns_query_to(&dns_packet, &String::from("8.8.8.8:53"))?;

    assert_eq!(dns_response.header.rcode, DNS_RCODE_NO_ERROR);
    assert_eq!(
        dns_response
            .answer
            .first()
            .ok_or("dns_response had no answers")?
            .rrtype,
        DNS_TYPE_A
    );

    Ok(())
}
