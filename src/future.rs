use std::future::Future;
use std::marker::PhantomData;
use std::mem::transmute;
use std::pin::Pin;
use std::thread;
use std::time::Duration;

use option_lock::OptionLock;

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
    let blk = Blocking::boxed(f);
    let sentinel = blk.sentinel();
    let mut blk = unsafe {
        transmute::<_, Box<dyn CallBlocking<T> + 'static>>(blk as Box<dyn CallBlocking<T> + 'f>)
    };
    let result = blocking::unblock(move || blk.call()).await;
    std::mem::forget(sentinel);
    result
}

enum BlockingState {
    Thread(thread::Thread),
    Done,
}

struct BlockingSentinel {
    ptr: *const OptionLock<BlockingState>,
}

unsafe impl Send for BlockingSentinel {}

impl Drop for BlockingSentinel {
    fn drop(&mut self) {
        let lock = unsafe { &*self.ptr };
        if let Some(mut guard) = lock.try_lock() {
            if guard.is_none() {
                guard.replace(BlockingState::Thread(thread::current()));
                drop(guard);
                thread::park();
            }
        }
    }
}

trait CallBlocking<T>: Send {
    fn call(&mut self) -> T;
}

struct Blocking<F, T> {
    state: OptionLock<BlockingState>,
    f: Option<F>,
    _pd: PhantomData<T>,
}

impl<F: FnOnce() -> T + Send, T: Send> Blocking<F, T> {
    fn boxed(f: F) -> Box<Self> {
        Box::new(Self {
            state: OptionLock::empty(),
            f: Some(f),
            _pd: PhantomData,
        })
    }
}

impl<F, T> Blocking<F, T> {
    fn sentinel(self: &Box<Self>) -> BlockingSentinel {
        BlockingSentinel { ptr: &self.state }
    }
}

impl<F, T> CallBlocking<T> for Blocking<F, T>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    fn call(&mut self) -> T {
        let result = (self.f.take().unwrap())();
        let mut guard = self.state.spin_lock();
        match guard.take() {
            Some(BlockingState::Thread(th)) => {
                guard.replace(BlockingState::Done);
                drop(guard);
                th.unpark()
            }
            _ => (),
        }
        result
    }
}

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    async_global_executor::spawn(fut).detach();
}

pub async fn sleep_ms(dur: u64) {
    async_io::Timer::after(Duration::from_millis(dur)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::poll_once;
    use std::sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc,
    };
    use std::time::Duration;

    #[test]
    fn blocking_scoped_drop() {
        let called = Arc::new(AtomicBool::new(false));
        let fut = blocking_scoped({
            let called = called.clone();
            move || {
                thread::sleep(Duration::from_millis(50));
                called.store(true, SeqCst);
            }
        });
        // poll once to queue the fn, then drop the future
        // this should block until the closure completes
        assert_eq!(block_on(poll_once(fut)), None);
        assert_eq!(called.load(SeqCst), true);
    }
}
