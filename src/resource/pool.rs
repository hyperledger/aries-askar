use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use futures_channel::oneshot;

use super::manager::ResourceManager;
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
    state: PoolSentinel<M>,
}

impl<M: ResourceManager> PoolResource<M> {
    fn new(res: M::Resource, info: Option<ResourceInfo>, state: PoolSentinel<M>) -> Self {
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
pub enum AcquireError<E: std::fmt::Debug + Send> {
    Init,
    Busy,
    Stopped,
    ResourceError(E),
}

enum WorkerMessage<M: ResourceManager> {
    Acquire(oneshot::Sender<Result<PoolResource<M>, AcquireError<M::Error>>>),
    Release(M::Resource, ResourceInfo),
}

struct PoolState<M: ResourceManager> {
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
}

struct PoolSentinel<M: ResourceManager>(Arc<PoolState<M>>);

impl<M: ResourceManager> PoolSentinel<M> {
    fn ref_count(&self) -> usize {
        Arc::strong_count(&self.0)
    }
}

impl<M: ResourceManager> Clone for PoolSentinel<M> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<M: ResourceManager> std::ops::Deref for PoolSentinel<M> {
    type Target = PoolState<M>;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<M: ResourceManager> Drop for PoolSentinel<M> {
    fn drop(&mut self) {
        // FIXME check thread::is_panicking and enable logging
        // this would indicate either a worker or the pool main thread is panicking

        if Arc::strong_count(&self.0) == 1 {
            // this is the last copy
            if let Ok(mut inner) = self.0.inner.lock() {
                inner.flag = PoolWorkerFlag::Done;
            }
        } else {
            // notify main thread every time a reference is dropped
            // this avoids a deadlock during the shutdown procedure
            self.0.cvar.notify_all();
        }
    }
}

#[derive(Clone)]
pub struct ResourcePool<M: ResourceManager> {
    state: Arc<PoolState<M>>,
}

impl<M: ResourceManager> ResourcePool<M> {
    pub fn new(manager: M) -> Self {
        let min_count = manager.min_count();
        let max_count = manager.max_count();
        let max_waiters = manager.max_waiters();

        let state = Arc::new(PoolState {
            inner: Mutex::new(PoolInnerState {
                flag: PoolWorkerFlag::Init,
                queue: VecDeque::new(),
                waiters: VecDeque::new(),
                pending_count: 0,
                min_count,
                max_count,
                max_waiters,
            }),
            resources: Mutex::new(VecDeque::<(M::Resource, ResourceInfo)>::new()),
            cvar: Condvar::new(),
        });
        let scopy = state.clone();
        thread::spawn(move || Self::run(manager, scopy));
        Self { state }
    }

    fn run(mut manager: M, state: Arc<PoolState<M>>) -> Result<(), M::Error> {
        // detect thread panic and change state to Done
        let state = PoolSentinel(state);

        // run initializer in this thread, queueing requests until finished
        manager.init()?;

        // worker is now responsible for the manager
        let mut worker = Box::new(BlockingWorker::new(manager)) as Box<dyn ResourcePoolWorker<M>>;

        let mut inner = state.inner.lock().unwrap();
        inner.flag = PoolWorkerFlag::Ready;
        state.cvar.notify_all();

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

            if inner.queue.is_empty() {
                // FIXME max wait until next keepalive timeout
                inner = state.cvar.wait(inner).unwrap();
            }
        }

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

    // FIXME add method to wait for init, giving clients the choice
    // to avoid AcquireError::Init
}

impl<M: ResourceManager> Drop for ResourcePool<M> {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.state.inner.lock() {
            inner.flag = PoolWorkerFlag::Shutdown;
            self.state.cvar.notify_all();
        }
    }
}
