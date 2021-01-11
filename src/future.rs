use std::future::Future;
use std::pin::Pin;

pub use async_global_executor::block_on;
// use once_cell::sync::Lazy;
// use suspend_exec::ThreadPool;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// pub static THREAD_POOL: Lazy<ThreadPool> = Lazy::new(ThreadPool::default);

#[inline]
pub async fn unblock<F, T>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    // THREAD_POOL.run(f).await.unwrap()
    blocking::unblock(f).await
}

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    async_global_executor::spawn(fut).detach();
}
