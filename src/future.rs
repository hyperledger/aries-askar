use std::{future::Future, pin::Pin, time::Duration};

use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Error creating tokio runtime"));

pub fn block_on<R>(f: impl Future<Output = R>) -> R {
    RUNTIME.block_on(f)
}

#[inline]
pub async fn unblock<F, T>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    RUNTIME
        .spawn_blocking(f)
        .await
        .expect("Error running blocking task")
}

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    RUNTIME.spawn(fut);
}

pub async fn sleep(dur: Duration) {
    let _rt = RUNTIME.enter();
    tokio::time::sleep(dur).await
}

pub async fn timeout<R>(dur: Duration, f: impl Future<Output = R>) -> Option<R> {
    let _rt = RUNTIME.enter();
    tokio::time::timeout(dur, f).await.ok()
}
