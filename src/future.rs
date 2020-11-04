use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::PhantomData;
use std::mem::{transmute, MaybeUninit};
use std::pin::Pin;
use std::sync::atomic::{fence, AtomicU8, Ordering};
use std::thread;
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
    let blk = Blocking::boxed(f);
    let sentinel = blk.sentinel();
    let mut blk = unsafe {
        transmute::<_, Box<dyn CallBlocking<T> + 'static>>(blk as Box<dyn CallBlocking<T> + 'f>)
    };
    let result = blocking::unblock(move || blk.call()).await;
    std::mem::forget(sentinel);
    result
}

const COMPLETE_INIT: u8 = 0;
const COMPLETE_WAKE: u8 = 1;
const COMPLETE_DONE: u8 = 2;

struct Completion {
    state: AtomicU8,
    thread: UnsafeCell<MaybeUninit<thread::Thread>>,
}

impl Completion {
    #[inline]
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(COMPLETE_INIT),
            thread: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    pub fn wait(&self) {
        match self.state.load(Ordering::Relaxed) {
            COMPLETE_DONE => {
                // synchronize with the blocking thread
                fence(Ordering::Acquire);
            }
            COMPLETE_INIT => {
                unsafe { self.thread.get().write(MaybeUninit::new(thread::current())) };
                match self.state.compare_exchange(
                    COMPLETE_INIT,
                    COMPLETE_WAKE,
                    Ordering::Acquire,
                    Ordering::Acquire,
                ) {
                    Ok(_) => thread::park(),
                    Err(COMPLETE_DONE) => (),
                    Err(s) => panic!("Unexpected state for Completion: {}", s),
                }
            }
            s => panic!("Unexpected state for Completion: {}", s),
        }
    }

    #[inline]
    pub fn done(&self) {
        match self.state.swap(COMPLETE_DONE, Ordering::Release) {
            COMPLETE_INIT => (),
            COMPLETE_WAKE => unsafe { self.thread.get().read().assume_init() }.unpark(),
            s => panic!("Unexpected state for Completion: {}", s),
        }
    }
}

struct BlockingSentinel {
    ptr: *const Completion,
}

unsafe impl Send for BlockingSentinel {}

impl Drop for BlockingSentinel {
    fn drop(&mut self) {
        let completion = unsafe { &*self.ptr };
        completion.wait();
    }
}

trait CallBlocking<T>: Send {
    fn call(&mut self) -> T;
}

struct Blocking<F, T> {
    completion: Completion,
    f: Option<F>,
    _pd: PhantomData<T>,
}

impl<F: FnOnce() -> T + Send, T: Send> Blocking<F, T> {
    #[inline]
    fn boxed(f: F) -> Box<Self> {
        Box::new(Self {
            completion: Completion::new(),
            f: Some(f),
            _pd: PhantomData,
        })
    }
}

impl<F, T> Blocking<F, T> {
    #[inline]
    fn sentinel(self: &Box<Self>) -> BlockingSentinel {
        BlockingSentinel {
            ptr: &self.completion,
        }
    }
}

impl<F, T> CallBlocking<T> for Blocking<F, T>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    #[inline]
    fn call(&mut self) -> T {
        let result = (self.f.take().unwrap())();
        self.completion.done();
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
        // poll once to queue the fn, then drop the future.
        // this should block until the closure completes
        assert_eq!(block_on(poll_once(fut)), None);
        assert_eq!(called.load(SeqCst), true);
    }
}
