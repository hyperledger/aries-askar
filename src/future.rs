use std::future::Future;
use std::pin::Pin;

pub use async_global_executor::block_on;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[inline]
pub async fn unblock<F, T>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    blocking::unblock(f).await
}

pub use self::scoped_impl::unblock_scoped;

mod scoped_impl {
    use std::cell::UnsafeCell;
    use std::marker::PhantomData;
    use std::mem::{transmute, MaybeUninit};
    use std::ops::{Deref, DerefMut};
    use std::pin::Pin;
    use std::sync::atomic::{fence, AtomicU8, Ordering};
    use std::thread;

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

    pub struct Checker {
        complete: *const Completion,
    }

    unsafe impl Send for Checker {}

    impl Drop for Checker {
        #[inline]
        fn drop(&mut self) {
            unsafe { &*self.complete }.wait();
        }
    }

    pub struct Sentinel<T: 'static> {
        blocking: &'static mut dyn CallBlocking<T>,
        complete: *const Completion,
    }

    unsafe impl<T: 'static> Send for Sentinel<T> {}

    impl<T: 'static> Deref for Sentinel<T> {
        type Target = dyn CallBlocking<T>;

        fn deref(&self) -> &Self::Target {
            self.blocking
        }
    }

    impl<T: 'static> DerefMut for Sentinel<T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.blocking
        }
    }

    impl<T: 'static> Drop for Sentinel<T> {
        #[inline]
        fn drop(&mut self) {
            unsafe { &*self.complete }.done();
        }
    }

    pub trait CallBlocking<T>: Send {
        fn call(&mut self) -> T;
    }

    pub struct Blocking<F, T> {
        completion: Completion,
        f: Option<F>,
        _pd: PhantomData<T>,
    }

    impl<F, T> Blocking<F, T>
    where
        F: FnOnce() -> T + Send,
        T: Send,
    {
        #[inline]
        pub fn new(f: F) -> Self {
            Self {
                completion: Completion::new(),
                f: Some(f),
                _pd: PhantomData,
            }
        }

        #[inline]
        pub fn make_static(self: Pin<&mut Self>) -> (Sentinel<T>, Checker) {
            let complete = &self.completion as *const Completion;
            (
                Sentinel {
                    blocking: unsafe {
                        transmute(self.get_unchecked_mut() as &mut dyn CallBlocking<T>)
                    },
                    complete,
                },
                Checker { complete },
            )
        }
    }

    impl<F, T> CallBlocking<T> for Blocking<F, T>
    where
        F: FnOnce() -> T + Send,
        T: Send,
    {
        #[inline]
        fn call(&mut self) -> T {
            (self.f.take().unwrap())()
        }
    }

    #[inline]
    pub async fn unblock_scoped<'f, F, T>(f: F) -> T
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'f,
    {
        let mut blk = Blocking::new(f);
        let blk = unsafe { Pin::new_unchecked(&mut blk) };
        let (mut sentinel, checker) = blk.make_static();
        let result = blocking::unblock(move || sentinel.call()).await;
        std::mem::forget(checker);
        result
    }
}

#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    async_global_executor::spawn(fut).detach();
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::{
        future::{block_on, poll_once},
        pin,
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, Barrier,
    };
    use std::thread;
    use std::time::Duration;

    #[test]
    fn unblock_scoped_drop() {
        // simply check that a never-polled unblock_scoped fut does not block on drop
        let fut = unblock_scoped(|| {});
        drop(fut);
    }

    #[test]
    fn unblock_scoped_poll_drop() {
        let barrier = Arc::new(Barrier::new(2));
        let called = Arc::new(AtomicBool::new(false));
        let fut = unblock_scoped({
            let barrier = Arc::clone(&barrier);
            let called = called.clone();
            move || {
                barrier.wait();
                thread::sleep(Duration::from_millis(50));
                called.store(true, SeqCst);
            }
        });
        // poll once to queue the fn, then drop the future.
        // this should block until the closure completes
        {
            pin!(fut);
            assert_eq!(block_on(poll_once(&mut fut)), None);
            // ensure the function is actually executed. otherwise it
            // could be dropped without being run by the worker thread
            // (which is acceptable but not what is being tested)
            barrier.wait();
            // fut will now be dropped
        }
        assert_eq!(called.load(SeqCst), true);
    }
}
