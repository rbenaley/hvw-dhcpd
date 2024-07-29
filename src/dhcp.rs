use crate::config::Config;
use crate::utils::{get_current_time, get_new_ip};
use anyhow::Result;
use log::{info, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

pub async fn handle_dhcp_packet(
    buf: &[u8],
    client_socket: &UdpSocket,
    _server_socket: &UdpSocket, // Prefix with an underscore to suppress the warning
    cache: &mut DhcpCache,
    config: &Config
) -> Result<()> {
    // Parse DHCP packet
    let dhcp_message_type = buf[242]; // DHCP Message Type Option

    match dhcp_message_type {
        1 => {
            info!("DHCPDISCOVER received");
            handle_discover(buf, client_socket, cache, config).await?
        },
        3 => {
            info!("DHCPREQUEST received");
            handle_request(buf, client_socket, cache, config).await?
        },
        _ => info!("Received unsupported DHCP packet: {}", dhcp_message_type),
    }

    Ok(())
}

async fn handle_discover(
    buf: &[u8],
    client_socket: &UdpSocket,
    cache: &mut DhcpCache,
    config: &Config
) -> Result<()> {
    let client_hardware_address = &buf[28..34]; // MAC address
    let client_id = format!("{:x?}", client_hardware_address);

    if let Some(lease) = cache.leases.get(&client_id) {
        info!("Found existing lease for client: {:?}", lease);
        send_dhcp_offer(client_socket, buf, lease).await?;
    } else {
        info!("Requesting new lease for client: {:?}", client_id);
        let new_ip = get_new_ip(client_hardware_address, &config.dhcp.server_addr, &config.dhcp.local_addr).await?;
        let new_lease = DhcpLease {
            client_id: client_id.clone(),
            ip_address: new_ip.to_string(),
            lease_time: 86400, // Default lease time (24 hours)
            lease_start: get_current_time(),
        };
        cache.leases.insert(client_id.clone(), new_lease.clone());
        send_dhcp_offer(client_socket, buf, &new_lease).await?;
    }

    Ok(())
}

async fn handle_request(
    buf: &[u8],
    client_socket: &UdpSocket,
    cache: &mut DhcpCache,
    config: &Config
) -> Result<()> {
    let client_hardware_address = &buf[28..34]; // MAC address
    let client_id = format!("{:x?}", client_hardware_address);

    if let Some(lease) = cache.leases.get_mut(&client_id) {
        info!("Found existing lease for client: {:?}", lease);
        lease.lease_start = get_current_time(); // Update lease start time
        send_dhcp_ack(client_socket, buf, lease).await?;
    } else {
        info!("Requesting new lease for client: {:?}", client_id);
        let new_ip = get_new_ip(client_hardware_address, &config.dhcp.server_addr, &config.dhcp.local_addr).await?;
        let new_lease = DhcpLease {
            client_id: client_id.clone(),
            ip_address: new_ip.to_string(),
            lease_time: 86400, // Default lease time (24 hours)
            lease_start: get_current_time(),
        };
        cache.leases.insert(client_id.clone(), new_lease.clone());
        send_dhcp_ack(client_socket, buf, &new_lease).await?;
    }

    Ok(())
}

async fn send_dhcp_offer(socket: &UdpSocket, request_packet: &[u8], lease: &DhcpLease) -> Result<()> {
    let mut offer_packet = [0u8; 300];
    offer_packet[..240].copy_from_slice(&request_packet[..240]); // Copy DHCP header

    // Set the yiaddr (your IP address) field
    offer_packet[16..20].copy_from_slice(&lease.ip_address.parse::<std::net::Ipv4Addr>().unwrap().octets());

    // Set DHCP options
    let options = [
        53, 1, 2, // DHCP Message Type: DHCPOFFER
        1, 4, 255, 255, 255, 0, // Subnet Mask
        3, 4, 192, 168, 1, 1, // Router
        51, 4, 0, 1, 81, 128, // Lease Time (86400 seconds)
        54, 4, 192, 168, 1, 1, // Server Identifier
        255, // End Option
    ];

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

async fn send_dhcp_ack(socket: &UdpSocket, request_packet: &[u8], lease: &DhcpLease) -> Result<()> {
    let mut ack_packet = [0u8; 300];
    ack_packet[..240].copy_from_slice(&request_packet[..240]); // Copy DHCP header

    // Set the yiaddr (your IP address) field
    ack_packet[16..20].copy_from_slice(&lease.ip_address.parse::<std::net::Ipv4Addr>().unwrap().octets());

    // Set DHCP options
    let options = [
        53, 1, 5, // DHCP Message Type: DHCPACK
        1, 4, 255, 255, 255, 0, // Subnet Mask
        3, 4, 192, 168, 1, 1, // Router
        51, 4, 0, 1, 81, 128, // Lease Time (86400 seconds)
        54, 4, 192, 168, 1, 1, // Server Identifier
        255, // End Option
    ];

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

pub async fn forward_dhcp_response(buf: &[u8], client_socket: &UdpSocket, cache: &DhcpCache) -> Result<()> {
    // Extract the transaction ID from the received DHCP packet
    let _transaction_id = &buf[4..8]; // Use _transaction_id to avoid the unused variable warning

    // Extract the client MAC address from the packet
    let client_hardware_address = &buf[28..34];
    let client_id = format!("{:x?}", client_hardware_address);

    // Look up the lease in the cache
    if let Some(lease) = cache.leases.get(&client_id) {
        // Build a new packet to forward to the client
        let mut forward_packet = [0u8; 300];
        forward_packet[..240].copy_from_slice(&buf[..240]); // Copy DHCP header

        // Set the yiaddr (your IP address) field
        forward_packet[16..20].copy_from_slice(&lease.ip_address.parse::<std::net::Ipv4Addr>().unwrap().octets());

        // Set DHCP options
        let options = [
            53, 1, 5, // DHCP Message Type: DHCPACK
            1, 4, 255, 255, 255, 0, // Subnet Mask
            3, 4, 192, 168, 1, 1, // Router
            51, 4, 0, 1, 81, 128, // Lease Time (86400 seconds)
            54, 4, 192, 168, 1, 1, // Server Identifier
            255, // End Option
        ];

        forward_packet[240..240 + options.len()].copy_from_slice(&options);

        info!("Forwarding DHCP response to client: {:?}", lease.client_id);
        let bytes_sent = match client_socket.send_to(&forward_packet, "255.255.255.255:68").await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to forward DHCP response: {}", e);
                return Err(e.into());
            }
        };
        info!("Forwarded DHCP response ({} bytes)", bytes_sent);
    } else {
        error!("No lease found for client: {:?}", client_id);
    }

    Ok(())
}
