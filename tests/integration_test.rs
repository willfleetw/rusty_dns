use dns::{dns_packet::*, rcodes::*};
use std::net::UdpSocket;

#[test]
fn test_basic_dns_resolution() -> Result<(), String> {
    let dns_packet = DnsPacket::parse_dns_packet(&vec![
        0x84, 0xB1, //ID
        0x01, 0x00, //QR=0,OPCODE=0,AA=0,TC=0,RD=1,RA=0,Z=0,RCODE=0
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
    ])?;
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
        1
    );

    Ok(())
}
