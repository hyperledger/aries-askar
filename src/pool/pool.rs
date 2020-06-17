use std::fmt::Debug;
use std::future::Future;
use std::mem;
use std::sync::{atomic::Ordering, Arc};
use std::thread;
use std::time::{Duration, Instant};

use futures_channel::oneshot;

use super::acquire::Acquire;
use super::executor::Executor;
use super::manager::Manager;
use super::queue::{Queue, QueueInner, QueueStatus};
use super::resource::{
    resource_create, resource_dispose, ApplyUpdate, ResourceFuture, ResourceInfo,
};
use super::sentinel::Sentinel;
use super::util::{TimedDeque, TimedMap};

pub struct PoolConfig<R, E: Debug> {
    acquire_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    min_count: usize,
    max_count: Option<usize>,
    max_waiters: Option<usize>,
    thread_count: Option<usize>,
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
            thread_count: None,
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

    pub fn min_count(mut self, val: usize) -> Self {
        self.min_count = val;
        self
    }

    pub fn max_count(mut self, val: usize) -> Self {
        self.max_count.replace(val);
        self
    }

    pub fn build(self) -> Pool<R, E> {
        let queue = Queue::default();
        let mgr = Manager::new(self.create, self.dispose, None);
        let exec = Executor::new(self.thread_count.unwrap_or(1));
        Pool::new(queue, mgr, exec)
    }
}

pub struct Pool<R: Send, E> {
    queue: Queue<R>,
    mgr: Manager<R, E>,
    exec: Executor,
}

impl<R: Send, E> Clone for Pool<R, E> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            mgr: self.mgr.clone(),
            exec: self.exec.clone(),
        }
    }
}

impl<R: Send + 'static, E: Send + 'static> Pool<R, E> {
    pub(crate) fn new<'e>(queue: Queue<R>, mgr: Manager<R, E>, exec: Executor) -> Self {
        let (qcopy, mcopy, ecopy) = (queue.clone(), mgr.clone(), exec.clone());
        let pool = Self { queue, mgr, exec };
        thread::spawn(move || Self::run(qcopy, mcopy, ecopy));
        pool
    }

    fn run(queue: Queue<R>, mgr: Manager<R, E>, exec: Executor) {
        let cleanup = Sentinel::new(Arc::new(queue.clone()), |queue, _| {
            if let Ok(mut guard) = queue.lock() {
                guard.status = QueueStatus::Stopped;
                let mut timers = TimedMap::new();
                mem::swap(&mut timers, &mut guard.timers);
                drop(guard);
                // notify any waiters of the new status
                queue.notify();

                // ensure all wakers are called when the run loop has ended
                for (_, timer) in timers {
                    timer.completed.store(true, Ordering::SeqCst);
                    timer.waker.wake();
                }
            }
        });

        let config = &queue.config;
        let mut next_check;
        let mut process_idle;
        let mut process_expired;
        let mut process_release;
        let mut process_timers = TimedMap::new();
        let mut prev_count;
        let mut prev_update_count;
        let mut waiters_removed;
        let mut updated;
        let mut disposed_count;
        let idle_timeout = config.idle_timeout.as_ref().copied().unwrap_or_default();
        let can_idle = idle_timeout.as_millis() > 0;

        let mut guard = queue.lock().unwrap();
        if guard.status != QueueStatus::Init {
            return;
        }
        guard.status = QueueStatus::Running;
        queue.notify();

        loop {
            next_check = None;
            prev_count = guard.total_count;
            prev_update_count = guard.update_count;
            // FIXME avoid this allocation while mutex is held
            process_idle = TimedDeque::new();
            process_release = TimedDeque::new();
            waiters_removed = 0usize;
            disposed_count = 0;
            updated = false;

            let drain = guard.status == QueueStatus::Draining;

            // remove expired resources
            let expired = if guard.idle.is_empty() || !can_idle {
                None
            } else if drain {
                Some((guard.idle.remove_all(), None))
            } else {
                let min_time = Instant::now() - idle_timeout;
                Some(guard.idle.remove_before(min_time))
            };

            if expired.is_some() || !guard.timers.is_empty() || !guard.release.is_empty() {
                // swap timer queue and release queue while processing
                mem::swap(&mut process_timers, &mut guard.timers);
                mem::swap(&mut process_release, &mut guard.release);

                // release lock to allow idle resource return and timer registration
                drop(guard);

                // move expired idle resources to verify or dispose queues
                if let Some((expired_res, next_time)) = expired {
                    process_expired = expired_res;
                    if let Some(next_time) = next_time {
                        next_check =
                            Some(next_check.map_or(next_time, |c| std::cmp::min(c, next_time)));
                    }
                } else {
                    process_expired = TimedDeque::new();
                }

                // current resource count, at least until the lock was released
                let total_count =
                    prev_count.saturating_sub(process_expired.len() + process_release.len());
                let mut keepalive_count = if drain {
                    0
                } else {
                    config.min_count.saturating_sub(total_count)
                };

                // process release queue
                for (res, idle_start) in process_release {
                    if !drain
                        && can_idle
                        && Instant::now().saturating_duration_since(idle_start) < idle_timeout
                    {
                        process_idle.push_timed(res, Some(idle_start));
                    } else {
                        process_expired.push_timed(res, Some(idle_start));
                    }
                }

                // process expired queue
                for ((res, info), _) in process_expired {
                    let fut = ResourceFuture::<R, E>::new(Some(res), info, queue.clone(), None);
                    if !drain && can_idle && keepalive_count > 0 {
                        if !spawn_or_cancel(mgr.keepalive(fut), &mgr, &exec) {
                            disposed_count += 1;
                        }
                        keepalive_count -= 1;
                    } else {
                        if !spawn_or_cancel(mgr.dispose(fut), &mgr, &exec) {
                            disposed_count += 1;
                        }
                    }
                }

                // remove and process expired waiters
                let clear_timers = if drain {
                    Some(process_timers.remove_all())
                } else if let Some(acquire_timeout) = config.acquire_timeout.as_ref() {
                    let min_time = Instant::now() - *acquire_timeout;
                    let (removed, next_time) = process_timers.remove_before(min_time);
                    if let Some(next_time) = next_time {
                        next_check =
                            Some(next_check.map_or(next_time, |c| std::cmp::min(c, next_time)));
                    }
                    Some(removed)
                } else {
                    None
                };
                if let Some(clear_timers) = clear_timers {
                    for (_, timer) in clear_timers {
                        if !timer.busy.load(Ordering::Acquire) {
                            waiters_removed += 1;
                        }
                        timer.completed.store(true, Ordering::SeqCst);
                        timer.waker.wake();
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

                // subtract disposed resources
                guard.total_count -= disposed_count;

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

                // merge new idle resources
                if !process_idle.is_empty() {
                    guard.idle.append(&mut process_idle);
                }

                if guard.update_count != prev_update_count {
                    updated = true;
                }

                // FIXME re-check queue status
            }

            println!(
                "count: {} {:?} {} {}",
                guard.total_count, guard.status, drain, updated
            );

            if guard.status == QueueStatus::Draining && guard.total_count == 0 {
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

        guard.status = QueueStatus::Shutdown;
        drop(guard);
        queue.notify();
    }

    pub fn acquire(&self) -> Acquire<R, E> {
        Acquire::new(self.queue.clone(), self.mgr.clone())
    }

    pub async fn clear(&self) {}

    pub async fn drain(self) -> Self {
        let queue = self.queue.clone();
        let (send, recv) = oneshot::channel();
        self.exec.spawn_ok(async move {
            drain_blocking(&queue);
            send.send(()).unwrap_or(());
        });
        recv.await.unwrap_or(());
        self
    }
}

impl<R: Send, E> Drop for Pool<R, E> {
    fn drop(&mut self) {
        // FIXME how best to detect when there's only one pool instance
        drain_blocking(&self.queue);
    }
}

fn drain_blocking<R: Send>(queue: &Queue<R>) {
    if let Ok(mut guard) = queue.lock() {
        if guard.status == QueueStatus::Running {
            guard.status = QueueStatus::Draining;
            queue.notify();
            loop {
                guard = queue.wait(guard).unwrap();
                if guard.status == QueueStatus::Stopped {
                    break;
                }
            }
        }
    }
}

fn spawn_or_cancel<R: Send + 'static, E: Send + 'static>(
    fut: ResourceFuture<R, E>,
    mgr: &Manager<R, E>,
    exec: &Executor,
) -> bool {
    if !fut.is_complete() {
        let mgr = mgr.clone();
        exec.spawn_ok(fut.to_task(move |err| mgr.handle_error(err)));
        true
    } else {
        fut.cancel();
        false
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
        thread::spawn(|| smol::run(futures_util::future::pending::<()>()));
        block_on(async move {
            pool.acquire().await.unwrap();
            //pool.drain().await;
        });
        assert_eq!(disposed.value(), 1);
    }

    #[test]
    // demonstrate a resource type that is Send but !Sync
    fn test_pool_not_sync() {
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
