use std::time::Instant;

mod manager;
mod pool;
mod worker;

pub use manager::ResourceManager;

#[derive(Copy, Clone, Debug)]
pub struct ResourceInfo {
    created: Instant,
    use_count: usize,
    last_used: Option<Instant>,
    last_verified: Option<Instant>,
}
