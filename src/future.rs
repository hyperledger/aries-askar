use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub use async_global_executor::block_on;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[inline]
pub async fn blocking<F, T>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    blocking::unblock(f).await
}

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    async_global_executor::spawn(fut).detach();
}

pub async fn sleep_ms(dur: u64) {
    async_io::Timer::after(Duration::from_millis(dur)).await;
}
