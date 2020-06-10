use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::task::{self, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use futures_util::future::{BoxFuture, FutureExt};
use futures_util::task::AtomicWaker;

use super::acquire::Acquire;
use super::executor::Executor;
use super::queue::Queue;
use super::resource::{
    resource_create, resource_dispose, ApplyUpdate, ResourceFuture, ResourceInfo,
};
use super::util::{TimedDeque, TimedMap};

pub struct PoolConfig<R, E: Debug> {
    acquire_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    min_count: usize,
    max_count: Option<usize>,
    max_waiters: Option<usize>,
    create: Box<dyn ApplyUpdate<R, E> + Send + Sync>,
    dispose: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
}

impl<R: Send + 'static, E: Debug + Send + 'static> PoolConfig<R, E> {
    pub fn new<F, O>(create: F) -> Self
    where
        F: Fn() -> O + Send + Sync + 'static,
        O: Future<Output = Result<R, E>> + Send + 'static,
    {
        Self {
            acquire_timeout: None,
            idle_timeout: None,
            min_count: 0,
            max_count: None,
            max_waiters: None,
            create: Box::new(resource_create(create)),
            dispose: None,
        }
    }

    pub fn dispose<F, O>(mut self, dispose: F) -> Self
    where
        F: Fn(R, ResourceInfo) -> O + Send + Sync + 'static,
        O: Future<Output = Result<(), E>> + Send + 'static,
    {
        self.dispose.replace(Box::new(resource_dispose(dispose)));
        self
    }

    pub fn build(self) -> Pool<R, E> {
        let queue = Queue::default();
        let exec = Executor::new(self.create, self.dispose);
        Pool::new(queue, exec)
    }
}

pub struct Pool<R, E> {
    queue: Queue<R>,
    exec: Executor<R, E>,
}

impl<R: Send + 'static, E: Send + 'static> Pool<R, E> {
    pub(crate) fn new<'e>(queue: Queue<R>, exec: Executor<R, E>) -> Self {
        let pool = Self { queue, exec };
        let runner = pool.clone();
        thread::spawn(move || runner.run());
        pool
    }

    fn run(self) {
        let exec = self.exec;
        let config = &self.queue.config;
        let queue = &self.queue;
        let mut next_check;
        let mut process_idle;
        let mut process_release;
        let mut process_timers = TimedMap::new();
        let mut prev_count;
        let mut prev_update_count;
        let mut waiters_removed;
        let mut updated;
        let idle_timeout = config.idle_timeout.as_ref().copied().unwrap_or_default();
        let can_idle = idle_timeout.as_millis() > 0;

        let mut guard = queue.lock().unwrap();
        guard.running = true;

        while guard.running {
            next_check = None;
            prev_count = guard.total_count;
            prev_update_count = guard.update_count;
            process_idle = TimedDeque::new();
            process_release = TimedDeque::new();
            waiters_removed = 0usize;
            updated = false;

            // remove expired resources
            let expired = if can_idle {
                let min_time = Instant::now() - idle_timeout;
                Some(guard.idle.remove_before(min_time))
            } else {
                None
            };

            // swap timer queue and release queue while processing
            // FIXME if there are no timers and no expired, we can skip all of this
            mem::swap(&mut process_timers, &mut guard.timers);
            mem::swap(&mut process_release, &mut guard.release);

            // release lock to allow idle resource return and timer registration
            drop(guard);

            // move expired idle resources to verify or dispose queues
            if let Some((expired_res, next_time)) = expired {
                // FIXME if neither keepalive or dispose are defined, just drop resource
                // define perform_keepalive on config

                let mut keepalive_count = config
                    .min_count
                    .saturating_sub(prev_count - expired_res.len());
                for ((res, info), _) in expired_res {
                    let fut =
                        ResourceFuture::<R, E>::new(Some(res), info, self.queue.clone(), None);
                    if keepalive_count > 0 {
                        // exec.keepalive(fut);
                        keepalive_count -= 1;
                    } else {
                        exec.dispose(fut);
                    }
                }

                if let Some(next_time) = next_time {
                    next_check =
                        Some(next_check.map_or(next_time, |c| std::cmp::min(c, next_time)));
                }
            }

            // process release queue
            for (res, idle_start) in process_release {
                // if we don't have an idle timeout, call dispose
                process_idle.push_timed(res, Some(idle_start));
                // FIXME send to executor if dispose is given or verify is needed
                // need to check count
                // otherwise drop here
                // for (res, _) in expired_res {
                //     let (res, info) = res.unwrap();
                //     state.resmgr.lock().unwrap().dispose(res, info);
                // }
            }

            // remove expired waiters
            if let Some(acquire_timeout) = config.acquire_timeout.as_ref() {
                let min_time = Instant::now() - *acquire_timeout;
                let (removed, next_time) = process_timers.remove_before(min_time);
                for (_, timer) in removed {
                    if !timer.busy.load(Ordering::Acquire) {
                        waiters_removed += 1;
                    }
                    timer.completed.store(true, Ordering::SeqCst);
                    timer.waker.wake();
                }
                if let Some(next_time) = next_time {
                    next_check =
                        Some(next_check.map_or(next_time, |c| std::cmp::min(c, next_time)));
                }
            }

            // wake timers awaiting acquire
            // only if we have max_count
            let mut extra_count = 0; // max_count - count;
            if extra_count > 0 {
                let wake = process_timers
                    .iter()
                    .flat_map(|(key, timer)| {
                        if !timer.busy.load(Ordering::Relaxed) {
                            Some(*key)
                        } else {
                            None
                        }
                    })
                    .take(extra_count)
                    .collect::<Vec<_>>();
                for key in wake {
                    waiters_removed += 1;
                    if config.acquire_timeout.is_none() {
                        if let Some(timer) = process_timers.remove(&key) {
                            // timer no longer required
                            timer.completed.store(true, Ordering::SeqCst);
                            timer.waker.wake();
                        }
                    } else {
                        if let Some(timer) = process_timers.get_mut(&key) {
                            // timer transitions to a busy timer
                            timer.busy.store(true, Ordering::Relaxed);
                            timer.waker.wake();
                        }
                    }
                }
            }

            // reacquire lock
            guard = queue.lock().unwrap();

            // subtract idle waiters that were removed, allowing more waiters
            guard.wait_count -= waiters_removed;

            // merge any timers registered during processing
            if !guard.timers.is_empty() {
                updated = true;
                if let Some((next_time, _)) = guard.timers.keys().next().copied() {
                    next_check =
                        Some(next_check.map_or(next_time, |c| std::cmp::min(c, next_time)));
                }
                process_timers.append(&mut guard.timers);
            }
            mem::swap(&mut process_timers, &mut guard.timers);

            if guard.update_count != prev_update_count {
                updated = true;
            }

            // abort if queue was dropped
            if !guard.running {
                break;
            }

            // FIXME create up to min resources - can register one with mutex locked
            // only if there are no updates?
            // check actual count while mutex is locked, cannot change
            // add auto delay

            // if no additional timers were registered, and no resources were updated, then wait
            if !updated {
                if let Some(check) =
                    next_check.and_then(|c| c.checked_duration_since(Instant::now()))
                {
                    let (q, _) = queue.wait_timeout(guard, check).unwrap();
                    guard = q;
                } else {
                    guard = queue.wait(guard).unwrap();
                }
            }
        }

        guard.running = false;

        // FIXME remove idle resources and run dispose
        // set all timers to completed and wake
    }

    pub fn acquire(&self) -> Acquire<R, E> {
        Acquire::new(self.queue.clone(), self.exec.clone())
    }
}

impl<R, E> Clone for Pool<R, E> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            exec: self.exec.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::util::AtomicCounter;
    use super::*;
    use smol::block_on;
    use std::cell::Cell;

    fn counter_pool() -> PoolConfig<usize, ()> {
        let source = Arc::new(AtomicCounter::default());
        PoolConfig::<usize, ()>::new(move || {
            let s = source.clone();
            async move { Ok(s.increment()) }
        })
    }

    #[test]
    fn test_pool_acquire_order() {
        let pool = counter_pool().build();
        let next = || pool.acquire();
        block_on(async move {
            let fst = next().await.unwrap();
            let snd = next().await.unwrap();
            assert_eq!(*fst, 1);
            assert_eq!(*snd, 2);
            drop(snd);
            assert_eq!(*next().await.unwrap(), 2);
            drop(fst);
            assert_eq!(*next().await.unwrap(), 1);
        })
    }

    #[test]
    fn test_pool_dispose() {
        let disposed = Arc::new(AtomicCounter::default());
        let dcopy = disposed.clone();
        let pool = counter_pool()
            .dispose(move |res, _| {
                let d = dcopy.clone();
                println!("dispose!");
                async move {
                    d.increment();
                    Ok(())
                }
            })
            .build();
        block_on(async move {
            pool.acquire().await.unwrap();
        });
        assert_eq!(disposed.value(), 1);
    }

    #[test]
    // demonstrate a resource type that is Send but !Sync
    fn test_not_sync() {
        let source = Arc::new(AtomicCounter::default());
        let pool = PoolConfig::<Cell<usize>, ()>::new(move || {
            let s = source.clone();
            async move { Ok(Cell::new(s.increment())) }
        })
        .build();
        block_on(async move {
            assert_eq!(pool.acquire().await.unwrap().get(), 1);
        });
    }
}
