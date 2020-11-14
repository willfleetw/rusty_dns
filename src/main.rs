#![allow(dead_code)]
#![allow(unused_variables)]

use rusty_dns::{dns_packet::*, types::*};
use std::net::UdpSocket;

fn main() -> Result<(), String> {
    let dns_packet = DnsPacket::new(&String::from("www.google.com."), DNS_TYPE_A)?;

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

    Ok(())
}
