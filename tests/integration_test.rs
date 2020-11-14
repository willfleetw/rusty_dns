use rusty_dns::{dns_packet::*, rcodes::*, types::*};
use std::net::UdpSocket;

#[test]
fn test_basic_dns_resolution() -> Result<(), String> {
    let dns_packet = DnsPacket::new(&String::from("www.google.com."), DNS_TYPE_A)?;
    println!("dns_packet:\n{:#?}", dns_packet);

    let client_socket = UdpSocket::bind("0.0.0.0:0").expect("Client could not bind");

    let serialized_dns_packet = dns_packet.serialize()?;

    client_socket
        .send_to(&serialized_dns_packet, "8.8.8.8:53")
        .expect("Client could not send data");

    let mut buf: [u8; 65535] = [0; 65535];
    let (amt, _) = client_socket
        .recv_from(&mut buf)
        .expect("Client could not recieve data from google dns");
    let buf = &buf[..amt];

    let dns_response = DnsPacket::parse_dns_packet(&buf.into()).expect("Could not parse response");
    println!("dns_response:\n{:#?}", dns_response);

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
