use std::future::Future;
use std::mem::transmute;
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
pub async fn blocking_scoped<'f, F, T>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'f,
{
    // FIXME: this is currently unsound
    // need to ensure that the function does not outlive this future by
    // adding a drop sentinel
    let g = Box::new(f) as Box<dyn FnOnce() -> T + Send + 'f>;
    blocking::unblock(unsafe { transmute::<_, Box<dyn FnOnce() -> T + Send + 'static>>(g) }).await
}

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    async_global_executor::spawn(fut).detach();
}

pub async fn sleep_ms(dur: u64) {
    async_io::Timer::after(Duration::from_millis(dur)).await;
}
