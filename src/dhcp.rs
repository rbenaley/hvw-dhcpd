use crate::config::Config;
use crate::utils::{generate_new_ip, get_current_time};
use anyhow::Result;
use log::{info, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr};
use tokio::net::UdpSocket;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DhcpCache {
    pub leases: HashMap<String, DhcpLease>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DhcpLease {
    pub client_id: String,
    pub ip_address: String,
    pub lease_time: u64,
    pub lease_start: u64,
}

pub async fn handle_dhcp_packet(buf: &[u8], socket: &UdpSocket, cache: &mut DhcpCache, config: &Config) -> Result<()> {
    // Parse DHCP packet
    let dhcp_message_type = buf[242]; // DHCP Message Type Option

    match dhcp_message_type {
        1 => {
            info!("DHCPDISCOVER received");
            handle_discover(buf, socket, cache, config).await?
        },
        3 => {
            info!("DHCPREQUEST received");
            handle_request(buf, socket, cache, config).await?
        },
        _ => info!("Received unsupported DHCP packet: {}", dhcp_message_type),
    }

    Ok(())
}

async fn handle_discover(buf: &[u8], socket: &UdpSocket, cache: &mut DhcpCache, config: &Config) -> Result<()> {
    let client_hardware_address = &buf[28..34]; // MAC address
    let client_id = format!("{:x?}", client_hardware_address);

    if let Some(lease) = cache.leases.get(&client_id) {
        info!("Found existing lease for client: {:?}", lease);
        send_dhcp_offer(socket, buf, lease, config).await?;
    } else {
        info!("Creating new lease for client: {:?}", client_id);
        let new_ip = generate_new_ip(cache, config);
        let new_lease = DhcpLease {
            client_id: client_id.clone(),
            ip_address: new_ip.to_string(),
            lease_time: config.lease.time,
            lease_start: get_current_time(),
        };
        cache.leases.insert(client_id.clone(), new_lease.clone());
        send_dhcp_offer(socket, buf, &new_lease, config).await?;
    }

    Ok(())
}

async fn send_dhcp_offer(socket: &UdpSocket, request_packet: &[u8], lease: &DhcpLease, config: &Config) -> Result<()> {
    let mut offer_packet = [0u8; 300];
    offer_packet[..240].copy_from_slice(&request_packet[..240]); // Copy DHCP header

    // Set the yiaddr (IP address) field
    offer_packet[16..20].copy_from_slice(&lease.ip_address.parse::<Ipv4Addr>().unwrap().octets());

    // Set DHCP options
    let dns_servers = config.dns.servers.iter()
        .flat_map(|s| s.parse::<Ipv4Addr>().unwrap().octets())
        .collect::<Vec<_>>();

    let options = [
        vec![
            53, 1, 2, // DHCP Message Type: DHCPOFFER
            1, 4, 255, 255, 255, 0, // Subnet Mask
            3, 4, 192, 168, 1, 1, // Router
            51, 4, (config.lease.time >> 24) as u8, (config.lease.time >> 16) as u8, (config.lease.time >> 8) as u8, config.lease.time as u8, // Lease Time
            54, 4, 192, 168, 1, 1, // Server Identifier
            6, dns_servers.len() as u8,
        ],
        dns_servers,
        vec![255], // End Option
    ].concat();

    offer_packet[240..240 + options.len()].copy_from_slice(&options);

    info!("Sending DHCPOFFER to client: {:?}", lease.client_id);
    let bytes_sent = match socket.send_to(&offer_packet, "255.255.255.255:68").await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to send DHCPOFFER: {}", e);
            return Err(e.into());
        }
    };
    info!("DHCPOFFER sent ({} bytes)", bytes_sent);
    Ok(())
}

async fn handle_request(buf: &[u8], socket: &UdpSocket, cache: &mut DhcpCache, config: &Config) -> Result<()> {
    let client_hardware_address = &buf[28..34]; // MAC address
    let client_id = format!("{:x?}", client_hardware_address);

    if let Some(lease) = cache.leases.get_mut(&client_id) {
        info!("Found existing lease for client: {:?}", lease);
        lease.lease_start = get_current_time();
        send_dhcp_ack(socket, buf, lease, config).await?;
    } else {
        info!("Creating new lease for client: {:?}", client_id);
        let new_ip = generate_new_ip(cache, config);
        let new_lease = DhcpLease {
            client_id: client_id.clone(),
            ip_address: new_ip.to_string(),
            lease_time: config.lease.time,
            lease_start: get_current_time(),
        };
        cache.leases.insert(client_id.clone(), new_lease.clone());
        send_dhcp_ack(socket, buf, &new_lease, config).await?;
    }

    Ok(())
}

async fn send_dhcp_ack(socket: &UdpSocket, request_packet: &[u8], lease: &DhcpLease, config: &Config) -> Result<()> {
    let mut ack_packet = [0u8; 300];
    ack_packet[..240].copy_from_slice(&request_packet[..240]); // Copy DHCP header

    // Set the yiaddr (your IP address) field
    ack_packet[16..20].copy_from_slice(&lease.ip_address.parse::<Ipv4Addr>().unwrap().octets());

    // Set DHCP options
    let dns_servers = config.dns.servers.iter()
        .flat_map(|s| s.parse::<Ipv4Addr>().unwrap().octets())
        .collect::<Vec<_>>();

    let options = [
        vec![
            53, 1, 5, // DHCP Message Type: DHCPACK
            1, 4, 255, 255, 255, 0, // Subnet Mask
            3, 4, 192, 168, 1, 1, // Router
            51, 4, (config.lease.time >> 24) as u8, (config.lease.time >> 16) as u8, (config.lease.time >> 8) as u8, config.lease.time as u8, // Lease Time
            54, 4, 192, 168, 1, 1, // Server Identifier
            6, dns_servers.len() as u8,
        ],
        dns_servers,
        vec![255], // End Option
    ].concat();

    ack_packet[240..240 + options.len()].copy_from_slice(&options);

    info!("Sending DHCPACK to client: {:?}", lease.client_id);
    let bytes_sent = match socket.send_to(&ack_packet, "255.255.255.255:68").await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to send DHCPACK: {}", e);
            return Err(e.into());
        }
    };
    info!("DHCPACK sent ({} bytes)", bytes_sent);
    Ok(())
}
