use anyhow::Result;
use std::net::{Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

pub fn get_current_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub async fn get_new_ip(client_hardware_address: &[u8], server_addr: &str, local_addr: &str) -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind(local_addr).await?;
    socket.set_broadcast(true)?;

    let mut request_packet = [0u8; 300];
    
    // Build the DHCP REQUEST packet
    // Fill in the necessary DHCP fields
    request_packet[0] = 1; // Message type: Boot Request (1)
    request_packet[1] = 1; // Hardware type: Ethernet
    request_packet[2] = 6; // Hardware address length: 6
    request_packet[3] = 0; // Hops
    // Transaction ID, etc.
    request_packet[4..8].copy_from_slice(&[0x39, 0x03, 0xF3, 0x26]); // Transaction ID
    request_packet[28..34].copy_from_slice(client_hardware_address); // Client MAC address
    // DHCP options
    request_packet[240] = 53; // DHCP option: DHCP Message Type
    request_packet[241] = 1;  // Length: 1
    request_packet[242] = 3;  // DHCPREQUEST

    socket.send_to(&request_packet, server_addr).await?;

    let mut buf = [0u8; 1500];
    let (_size, _) = socket.recv_from(&mut buf).await?;
    // Parse the received DHCPACK packet to extract the assigned IP address
    // Assuming the IP address is at the yiaddr field in the DHCP packet
    let assigned_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    
    Ok(assigned_ip)
}
