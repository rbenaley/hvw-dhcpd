use anyhow::Result;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub subnet: Subnet,
    pub router: Router,
    pub dns: Dns,
    pub lease: Lease,
}

#[derive(Deserialize, Debug)]
pub struct Subnet {
    pub start_ip: String,
    pub end_ip: String,
    pub mask: String,
}

#[derive(Deserialize, Debug)]
pub struct Router {
    pub ip: String,
}

#[derive(Deserialize, Debug)]
pub struct Dns {
    pub servers: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct Lease {
    pub time: u64,
}

pub fn load_config(file: &str) -> Result<Config> {
    let contents = fs::read_to_string(file)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
