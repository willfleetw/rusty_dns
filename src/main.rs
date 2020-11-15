use std::env;

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("Not given a domain name to search for".into());
    }

    let address = rusty_dns::resolve_domain_name(&args[1])?;

    println!("Returned IPv4 address: {}", address.to_string());

    Ok(())
}
