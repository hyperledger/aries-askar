use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::{atomic::Ordering, Arc};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use super::manager::Manager;
use super::queue::Queue;
use super::resource::{Managed, ResourceFuture, ResourceInfo};
use super::util::Timer;

pub enum AcquireError<E> {
    Busy,
    ResourceError(E),
    Stopped,
    Timeout,
}

impl<E: Debug> Debug for AcquireError<E> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Busy => write!(fmt, "AcquireError::Busy"),
            Self::ResourceError(err) => write!(fmt, "AcquireError::ResourceError({:?})", err),
            Self::Stopped => write!(fmt, "AcquireError::Stopped"),
            Self::Timeout => write!(fmt, "AcquireError::Timeout"),
        }
    }
}

pub enum TryAcquire<R: Send, E: Send> {
    Busy,
    Resource(Managed<R>),
    Stopped,
    Future(ResourceFuture<R, E>, Option<Arc<Timer>>),
    Wait(Arc<Timer>),
}

enum AcquireState<R: Send, E: Send> {
    Init(Queue<R>, Manager<R, E>),
    Active(ResourceFuture<R, E>, Option<Arc<Timer>>),
    Wait(Arc<Timer>),
}

impl<R: Send, E: Send> Unpin for AcquireState<R, E> {}

pub struct Acquire<R: Send, E: Send> {
    inner: Option<AcquireState<R, E>>,
}

impl<R: Send, E: Send> Acquire<R, E> {
    pub(crate) fn new(queue: Queue<R>, mgr: Manager<R, E>) -> Self {
        Self {
            inner: Some(AcquireState::Init(queue, mgr)),
        }
    }
}

impl<R: Send, E: Send> Future for Acquire<R, E> {
    type Output = Result<Managed<R>, AcquireError<E>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = match self.inner.take() {
            Some(state) => state,
            None => {
                // future already completed
                return Poll::Ready(Err(AcquireError::Stopped));
            }
        };

        loop {
            state = match state {
                AcquireState::Init(queue, mgr) => {
                    match try_acquire(&queue, &mgr, Some(cx.waker())) {
                        TryAcquire::Busy => {
                            return Poll::Ready(Err(AcquireError::Busy));
                        }
                        TryAcquire::Future(fut, timer) => AcquireState::Active(fut, timer),
                        TryAcquire::Resource(res) => {
                            return Poll::Ready(Ok(res));
                        }
                        TryAcquire::Stopped => {
                            return Poll::Ready(Err(AcquireError::Stopped));
                        }
                        TryAcquire::Wait(timer) => AcquireState::Wait(timer),
                    }
                }
                AcquireState::Active(mut fut, timer) => {
                    if timer
                        .as_ref()
                        .map(|t| t.completed.load(Ordering::Acquire))
                        .unwrap_or(false)
                    {
                        return Poll::Ready(Err(AcquireError::Timeout));
                    }
                    match Pin::new(&mut fut).poll(cx) {
                        Poll::Pending => {
                            timer.as_ref().map(|t| t.update(Some(cx.waker())));
                            self.inner.replace(AcquireState::Active(fut, timer));
                            return Poll::Pending;
                        }
                        Poll::Ready(result) => {
                            return Poll::Ready(
                                result
                                    .map(|r| r.to_managed())
                                    .map_err(AcquireError::ResourceError),
                            );
                        }
                    }
                }
                AcquireState::Wait(timer) => {
                    if timer.completed.load(Ordering::Acquire) {
                        return Poll::Ready(Err(AcquireError::Timeout));
                    }
                    timer.update(Some(cx.waker()));
                    self.inner.replace(AcquireState::Wait(timer));
                    return Poll::Pending;
                }
            };
        }
    }
}

pub fn try_acquire<R: Send, E: Send>(
    queue: &Queue<R>,
    mgr: &Manager<R, E>,
    waker: Option<&Waker>,
) -> TryAcquire<R, E> {
    let time_start = Instant::now();

    let mut guard = match queue.lock() {
        Ok(guard) if guard.status.is_running() => guard,
        _ => {
            // stopped or mutex poisoned
            return TryAcquire::Stopped;
        }
    };

    // fetch from idle queue
    if guard.wait_count == 0 {
        if let Some(((res, mut info), idle_start)) = guard.idle.pop_back() {
            let res = Managed::new(res, info, queue.clone());
            drop(guard);
            queue.notify();

            // FIXME verify on checkout - create verify task and return that
            info.borrow_count += 1;
            info.last_borrow.replace(Instant::now());
            return TryAcquire::Resource(res);
        }
    }

    // check for too many waiters
    if queue
        .config
        .max_waiters
        .as_ref()
        .map(|max| *max <= guard.wait_count)
        .unwrap_or(false)
    {
        return TryAcquire::Busy;
    }

    // try to create a new resource
    if queue
        .config
        .max_count
        .map(|c| c > guard.total_count)
        .unwrap_or(true)
    {
        // increase total resource count
        // note: if `fut` is dropped before being run to completion or the operation
        // produces an error, then queue.total_count will be reduced on drop
        guard.total_count += 1;
        let fut = ResourceFuture::new(None, ResourceInfo::default(), queue.clone(), None);

        let timer = if queue.config.acquire_timeout.is_some() {
            let timer = Arc::new(Timer::new(true));
            guard.timers.push_timed(timer.clone(), Some(time_start));
            Some(timer)
        } else {
            None
        };
        drop(guard);
        queue.notify();

        let result = mgr.create(fut);
        return TryAcquire::Future(
            result,
            timer.map(|t| {
                t.update(waker);
                t
            }),
        );
    }

    // register idle waiter
    let timer = Arc::new(Timer::new(false));
    guard.timers.push_timed(timer.clone(), Some(time_start));
    guard.wait_count += 1;
    drop(guard);
    queue.notify();

    return TryAcquire::Wait(timer);
}
