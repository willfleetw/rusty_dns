fn main() -> Result<(), String> {
    let address = rusty_dns::resolve_domain_name(&String::from("www.google.com"))?;

    println!("Returned IPv4 address: {}", address.to_string());

    Ok(())
}
