use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub dhcp: DhcpConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DhcpConfig {
    pub server_addr: String,
    pub local_addr: String,
    pub response_addr: String, // Add this field
}

pub fn load_config(path: &str) -> Result<Config> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}
