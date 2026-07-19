pub mod core;
pub mod features;
pub mod network;
pub mod stealth;
pub mod template;

pub mod rpc {
    tonic::include_proto!("valayam");
}

pub mod plugin_rpc {
    tonic::include_proto!("valayam.plugin");
}
