use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task;
use std::thread;
use std::time::Instant;

use futures_channel::oneshot;

use super::manager::ResourceManager;
use super::sentinel::Sentinel;
use super::worker::{BlockingWorker, ResourcePoolWorker};
use super::ResourceInfo;

#[derive(Clone, Copy, Debug, PartialOrd, PartialEq)]
pub enum PoolWorkerFlag {
    Init,
    Ready,
    Busy,
    Shutdown,
    Done,
}

pub struct PoolResource<M: ResourceManager> {
    inner: Option<M::Resource>,
    info: ResourceInfo,
    state: PoolThreadState<M>,
}

impl<M: ResourceManager> Debug for PoolResource<M>
where
    M::Resource: Debug,
{
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("PoolResource")
            .field("inner", &self.inner.as_ref().unwrap())
            .field("info", &self.info)
            .finish()
    }
}

impl<M: ResourceManager> Display for PoolResource<M>
where
    M::Resource: Display,
{
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.inner.as_ref().unwrap(), fmt)
    }
}

impl<M: ResourceManager> PoolResource<M> {
    fn new(res: M::Resource, info: Option<ResourceInfo>, state: PoolThreadState<M>) -> Self {
        let info = info.unwrap_or_else(|| ResourceInfo {
            created: Instant::now(),
            use_count: 0,
            last_used: None,
            last_verified: None,
        });
        Self {
            inner: Some(res),
            info,
            state,
        }
    }

    fn unwrap(mut self) -> (M::Resource, ResourceInfo) {
        (self.inner.take().unwrap(), self.info)
    }
}

impl<M: ResourceManager> std::ops::Deref for PoolResource<M> {
    type Target = M::Resource;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<M: ResourceManager> std::ops::DerefMut for PoolResource<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl<M: ResourceManager> Drop for PoolResource<M> {
    fn drop(&mut self) {
        self.info.use_count += 1;
        self.info.last_used = Some(Instant::now());

        // if manager is running, take value and send it back
        // otherwise leave it to be dropped on this thread
        // manager should wait for all resources unless it panics
        if let Ok(mut inner) = self.state.inner.lock() {
            if inner.flag != PoolWorkerFlag::Done {
                inner.queue.push_back(WorkerMessage::Release(
                    self.inner.take().unwrap(),
                    self.info,
                ));
            }
            // state.cvar is notified automatically
        }
    }
}

#[derive(Debug)]
pub enum AcquireError<E: Debug + Send> {
    Init,
    Busy,
    Stopped,
    ResourceError(E),
}

#[derive(Debug)]
pub struct InitError();

enum WorkerMessage<M: ResourceManager> {
    Acquire(oneshot::Sender<Result<PoolResource<M>, AcquireError<M::Error>>>),
    Release(M::Resource, ResourceInfo),
}

struct PoolSharedState<M: ResourceManager> {
    inner: Mutex<PoolInnerState<M>>,
    resources: Mutex<VecDeque<(M::Resource, ResourceInfo)>>,
    cvar: Condvar,
}

struct PoolInnerState<M: ResourceManager> {
    flag: PoolWorkerFlag,
    queue: VecDeque<WorkerMessage<M>>,
    waiters: VecDeque<oneshot::Sender<Result<PoolResource<M>, AcquireError<M::Error>>>>,
    pending_count: usize,
    min_count: usize,
    max_count: Option<usize>,
    max_waiters: Option<usize>,
    ready_wakers: Vec<task::Waker>,
    done_wakers: Vec<task::Waker>,
}

type PoolThreadState<M> = Sentinel<PoolSharedState<M>>;

pub struct ResourcePool<M: ResourceManager> {
    state: Sentinel<PoolSharedState<M>>,
}

impl<M: ResourceManager> ResourcePool<M> {
    pub fn new(manager: M) -> Self {
        let min_count = manager.min_count();
        let max_count = manager.max_count();
        let max_waiters = manager.max_waiters();

        let state = Arc::new(PoolSharedState {
            inner: Mutex::new(PoolInnerState {
                flag: PoolWorkerFlag::Init,
                queue: VecDeque::new(),
                waiters: VecDeque::new(),
                pending_count: 0,
                min_count,
                max_count,
                max_waiters,
                ready_wakers: Vec::new(),
                done_wakers: Vec::new(),
            }),
            resources: Mutex::new(VecDeque::<(M::Resource, ResourceInfo)>::new()),
            cvar: Condvar::new(),
        });
        let scopy = state.clone();
        thread::spawn(move || Self::run(manager, scopy));
        Self {
            state: Sentinel::new(state, |state, remain| {
                if remain == 0 {
                    if let Ok(mut inner) = state.inner.lock() {
                        if inner.flag != PoolWorkerFlag::Done {
                            inner.flag = PoolWorkerFlag::Shutdown;
                            state.cvar.notify_all();
                        }
                    }
                }
            }),
        }
    }

    fn run(mut manager: M, state: Arc<PoolSharedState<M>>) -> Result<(), M::Error> {
        // detect thread panic and change state to Done
        let state = PoolThreadState::new(state, |state, remain| {
            // FIXME check thread::is_panicking and enable logging
            // this would indicate either a worker or the pool main thread is panicking
            // cache the main thread ID to compare

            if remain == 0 {
                // this is the last copy
                if let Ok(mut inner) = state.inner.lock() {
                    inner.flag = PoolWorkerFlag::Done;
                    for waker in inner.ready_wakers.drain(..) {
                        // alert ready waiter so it can receive an InitError
                        waker.wake();
                    }
                    for waker in inner.done_wakers.drain(..) {
                        // alert done waiter
                        waker.wake();
                    }
                }
            } else {
                // notify main thread every time a reference is dropped
                // this avoids a deadlock during the shutdown procedure
                state.cvar.notify_all();
            }
        });

        // run initializer in this thread, queueing requests until finished
        manager.init()?;

        // worker is now responsible for the manager
        let mut worker = Box::new(BlockingWorker::new(manager)) as Box<dyn ResourcePoolWorker<M>>;

        let mut inner = state.inner.lock().unwrap();
        if inner.flag == PoolWorkerFlag::Init {
            inner.flag = PoolWorkerFlag::Ready;
        }
        for waker in inner.ready_wakers.drain(..) {
            waker.wake();
        }

        loop {
            if inner.flag == PoolWorkerFlag::Shutdown {
                break;
            }

            if let Some(message) = inner.queue.pop_front() {
                // release lock
                drop(inner);

                match message {
                    WorkerMessage::Acquire(sender) => {
                        let mut reslock = state.resources.lock().unwrap();

                        if let Some((res, info)) = reslock.pop_front() {
                            // send back an existing resource
                            if let Err(err) = sender.send(Ok(PoolResource {
                                inner: Some(res),
                                info,
                                state: state.clone(),
                            })) {
                                // recipient disappeared, put resource back into collection
                                let handle = err.unwrap();
                                reslock.push_front(handle.unwrap());
                            }
                        } else {
                            drop(reslock);

                            let state = state.clone();
                            worker.create(Box::new(move |res| {
                                let res = res
                                    .map_err(|e| AcquireError::ResourceError(e))
                                    .map(|r| PoolResource::new(r, None, state.clone()));

                                if res.is_err() {
                                    // resource is no longer pending - it failed
                                    state.inner.lock().unwrap().pending_count -= 1;
                                }

                                if let Err(err) = sender.send(res) {
                                    // recipient disappeared, put resource back into collection
                                    let handle = err.unwrap();
                                    state.resources.lock().unwrap().push_front(handle.unwrap());
                                }
                                // cvar is notified when closure is dropped
                            }));
                        }
                    }
                    WorkerMessage::Release(res, mut resinfo) => {
                        let state = state.clone();
                        worker.verify(
                            res,
                            resinfo,
                            Box::new(move |res| {
                                // resource no longer pending
                                state.inner.lock().unwrap().pending_count -= 1;

                                if let Some(res) = res {
                                    // resource verified, put back into service
                                    resinfo.last_verified = Some(Instant::now());
                                    let mut reslock = state.resources.lock().unwrap();
                                    reslock.push_front((res, resinfo));
                                }
                                // cvar is notified when closure is dropped
                            }),
                        );
                    }
                }
                inner = state.inner.lock().unwrap();
            }

            if !inner.waiters.is_empty() {
                // move waiters onto the queue if there's room for more
                // FIXME check logic - need to check total count?
                while inner.pending_count < inner.max_count.clone().unwrap() {
                    if let Some(sender) = inner.waiters.pop_front() {
                        inner.pending_count += 1;
                        inner.queue.push_back(WorkerMessage::Acquire(sender));
                    }
                }
            }
            if inner.flag == PoolWorkerFlag::Busy {
                let max_wait = inner.max_waiters.clone().unwrap();
                if inner.pending_count < inner.max_count.clone().unwrap()
                    || inner.waiters.len() < max_wait
                {
                    inner.flag = PoolWorkerFlag::Ready;
                }
            }

            // FIXME need to clean up idle workers
            // FIXME create workers up to min_count while accepting new requests
            // with small delay in between?

            if inner.queue.is_empty() && inner.flag != PoolWorkerFlag::Shutdown {
                // FIXME max wait until next keepalive timeout
                inner = state.cvar.wait(inner).unwrap();
            }
        }

        // entered shutdown state

        // drop any senders in wait queue
        inner.waiters.clear();

        loop {
            // dispose of resources while waiting for any other threads
            while let Some(message) = inner.queue.pop_front() {
                // allow callers to determine we are shutting down
                drop(inner);

                match message {
                    WorkerMessage::Acquire(_) => {
                        // just drop sender to indicate we are stopped
                    }
                    WorkerMessage::Release(res, info) => {
                        worker.dispose(res, info);
                    }
                }

                inner = state.inner.lock().unwrap();
            }

            // count is increased for each PoolResource given out
            // as well as each create() and verify() callback.
            // wait for them to send back their results and complete
            if state.ref_count() == 1 {
                break;
            }
            // wait for next child to shut down
            inner = state.cvar.wait(inner).unwrap();
        }

        // lock no longer needed
        drop(inner);

        let mut reslock = state.resources.lock().unwrap();
        for (res, info) in reslock.drain(..) {
            worker.dispose(res, info);
        }

        Ok(())
    }

    pub async fn acquire<'a>(&self) -> Result<PoolResource<M>, AcquireError<M::Error>> {
        let (send, recv) = oneshot::channel();

        if let Ok(mut inner) = self.state.inner.lock() {
            match inner.flag {
                PoolWorkerFlag::Busy => {
                    return Err(AcquireError::Busy);
                }
                PoolWorkerFlag::Shutdown | PoolWorkerFlag::Done => {
                    return Err(AcquireError::Stopped);
                }
                _ => (),
            }

            if inner.max_count.is_none() || inner.pending_count < inner.max_count.clone().unwrap() {
                inner.pending_count += 1;
                inner.queue.push_back(WorkerMessage::Acquire(send));
                self.state.cvar.notify_all();
            } else if inner.max_waiters.is_none()
                || inner.waiters.len() < inner.max_waiters.clone().unwrap()
            {
                inner.waiters.push_back(send);
            } else {
                inner.flag = PoolWorkerFlag::Busy;
                return Err(AcquireError::Busy);
            }
        } else {
            return Err(AcquireError::Stopped);
        }

        if let Ok(result) = recv.await {
            result
        } else {
            Err(AcquireError::Stopped)
        }
    }

    // note: will block until all clones are dropped
    pub fn shutdown(self) -> PoolShutdown<M> {
        PoolShutdown {
            state: self.state.unwrap(),
        }
    }
}

impl<M: ResourceManager> Clone for ResourcePool<M> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

// wait for init to complete
impl<M: ResourceManager> Future for ResourcePool<M> {
    type Output = Result<Self, InitError>;
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        if let Ok(mut inner) = self.state.inner.lock() {
            match inner.flag {
                PoolWorkerFlag::Init => {
                    let waker = cx.waker().clone();
                    inner.ready_wakers.retain(|w| !waker.will_wake(w));
                    inner.ready_wakers.push(waker);
                    task::Poll::Pending
                }
                PoolWorkerFlag::Ready | PoolWorkerFlag::Busy => task::Poll::Ready(Ok(self.clone())),
                _ => {
                    if inner.flag == PoolWorkerFlag::Done {}
                    task::Poll::Ready(Err(InitError {}))
                }
            }
        } else {
            task::Poll::Ready(Err(InitError {}))
        }
    }
}

pub struct PoolShutdown<M: ResourceManager> {
    state: Arc<PoolSharedState<M>>,
}

impl<M: ResourceManager> Future for PoolShutdown<M> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        // note: will panic if the mutex was poisoned by another thread
        let mut inner = self.state.inner.lock().unwrap();
        match inner.flag {
            PoolWorkerFlag::Done => task::Poll::Ready(()),
            _ => {
                let waker = cx.waker().clone();
                inner.done_wakers.retain(|w| !waker.will_wake(w));
                inner.done_wakers.push(waker);
                task::Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smol::{block_on, blocking};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::sleep;
    use std::time::Duration;

    #[derive(Default)]
    struct TestResourceManager {
        idx: AtomicUsize,
    }

    impl ResourceManager for TestResourceManager {
        type Resource = String;
        type Error = String;

        fn init(&mut self) -> Result<(), String> {
            println!("init");
            sleep(Duration::from_millis(10));
            Ok(())
        }

        fn create(&self) -> Result<String, String> {
            let idx = self.idx.fetch_add(1, Ordering::SeqCst);
            Ok(idx.to_string())
        }
    }

    // test that two ready wakers on separate clones of the pool are supported
    #[test]
    fn pool_ready_wakers() {
        let p1 = ResourcePool::new(TestResourceManager::default());
        let p2 = p1.clone();
        let th = thread::spawn(move || {
            block_on(async move {
                let result = p2.await;
                println!("done thread 2");
                result
            })
        });
        block_on(async move {
            let result = p1.await;
            println!("done thread 1");
            result
        })
        .unwrap();
        th.join().unwrap().unwrap();
    }

    // test pool shutdown waiter
    #[test]
    fn pool_done_waker() {
        let p1 = ResourcePool::new(TestResourceManager::default());
        let p2 = p1.clone();
        let th = thread::spawn(move || {
            block_on(async move {
                p2.shutdown().await;
                println!("done shutdown");
            })
        });
        block_on(async move {
            println!("val: {}", p1.acquire().await.unwrap());
            println!("done p1");
        });
        th.join().unwrap();
    }
}
