pub mod core;
pub mod features;
pub use valayam_network::network;
pub use valayam_network::stealth;
pub mod template;

pub mod rpc {
    tonic::include_proto!("valayam");
}

pub mod plugin_rpc {
    tonic::include_proto!("valayam.plugin");
}
