//! Finalized traffic relay with shared evidence and independent receipt observation.

pub mod config;
pub mod evidence;
pub mod observe;
pub mod profile;
pub mod relay;
pub mod service;
pub mod source;
pub mod state;
pub mod store;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
