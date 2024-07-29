mod config;
mod dhcp;
mod utils;

use crate::config::Config;
use crate::dhcp::{DhcpCache, handle_dhcp_packet, forward_dhcp_response};
use anyhow::Result;
use log::info;
use pnet::datalink;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // Load configuration
    let config: Config = config::load_config("config.toml")?;
    info!("Loaded configuration: {:?}", config);

    let interfaces = datalink::interfaces();
    let _interface = interfaces.into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No suitable network interface found");

    let local_addr = &config.dhcp.local_addr;
    let response_addr = &config.dhcp.response_addr;

    let client_socket = UdpSocket::bind(local_addr).await?;
    client_socket.set_broadcast(true)?;

    let server_socket = UdpSocket::bind(response_addr).await?;
    server_socket.set_broadcast(true)?;

    info!("Listening for clients on {}", local_addr);
    info!("Listening for server responses on {}", response_addr);

    let mut client_buf = [0u8; 1500];
    let mut server_buf = [0u8; 1500];
    let mut cache = DhcpCache::default();

    loop {
        tokio::select! {
            Ok((size, src)) = client_socket.recv_from(&mut client_buf) => {
                info!("Received packet from client {}: {:?}", src, &client_buf[..size]);
                // Handle DHCP packets manually
                handle_dhcp_packet(&client_buf[..size], &client_socket, &server_socket, &mut cache, &config).await?;
            }
            Ok((size, src)) = server_socket.recv_from(&mut server_buf) => {
                info!("Received packet from server {}: {:?}", src, &server_buf[..size]);
                // Handle responses from the DHCP server
                forward_dhcp_response(&server_buf[..size], &client_socket, &cache).await?;
            }
        }
    }
}
