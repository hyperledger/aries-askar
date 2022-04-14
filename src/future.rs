use std::{future::Future, pin::Pin, time::Duration};

use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Error creating tokio runtime"));

/// Block the current thread on an async task, when not running inside the scheduler.
pub fn block_on<R>(f: impl Future<Output = R>) -> R {
    RUNTIME.block_on(f)
}

/// Run a blocking task without interrupting the async scheduler.
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

/// Spawn an async task into the runtime.
#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    RUNTIME.spawn(fut);
}

/// Wait until a specific duration has passed (used in tests).
#[doc(hidden)]
pub async fn sleep(dur: Duration) {
    let _rt = RUNTIME.enter();
    tokio::time::sleep(dur).await
}

/// Cancel an async task if it does not complete after a timeout (used in tests).
#[doc(hidden)]
pub async fn timeout<R>(dur: Duration, f: impl Future<Output = R>) -> Option<R> {
    let _rt = RUNTIME.enter();
    tokio::time::timeout(dur, f).await.ok()
}
