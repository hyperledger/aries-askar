use std::future::Future;
use std::time::Duration;

pub use async_global_executor::block_on;

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    async_global_executor::spawn(fut).detach();
}

pub async fn sleep_ms(dur: u64) {
    async_io::Timer::after(Duration::from_millis(dur)).await;
}
