use crate::config::Config;
use crate::dhcp::DhcpCache;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_new_ip(cache: &DhcpCache, config: &Config) -> Ipv4Addr {
    let start_ip: Ipv4Addr = config.subnet.start_ip.parse().unwrap();
    let end_ip: Ipv4Addr = config.subnet.end_ip.parse().unwrap();

    for i in (u32::from(start_ip)..=u32::from(end_ip)).map(|x| Ipv4Addr::from(x)) {
        let ip_str = i.to_string();
        if !cache.leases.values().any(|lease| lease.ip_address == ip_str) {
            return i;
        }
    }

    panic!("No available IP addresses in the range");
}

pub fn get_current_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
