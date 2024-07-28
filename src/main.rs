mod config;
mod dhcp;
mod utils;

use crate::config::Config;
use crate::dhcp::{DhcpCache, handle_dhcp_packet};
use anyhow::Result;
use log::info;
use pnet::datalink;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config: Config = config::load_config("config.toml")?;
    info!("Loaded configuration: {:?}", config);

    let interfaces = datalink::interfaces();
    let _interface = interfaces.into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No suitable network interface found");

    let local_addr = "0.0.0.0:67".to_string();
    let socket = UdpSocket::bind(&local_addr).await?;
    socket.set_broadcast(true)?;

    info!("Listening on {}", local_addr);

    let mut buf = [0u8; 1500];
    let mut cache = DhcpCache::default();

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        info!("Received packet from {}: {:?}", src, &buf[..size]);
        handle_dhcp_packet(&buf[..size], &socket, &mut cache, &config).await?;
    }
}
