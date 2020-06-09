use std::sync::{Arc, Condvar, LockResult, Mutex, MutexGuard, WaitTimeoutResult};
use std::task::Waker;
use std::time::{Duration, Instant};

use super::resource::{Managed, ResourceFuture, ResourceInfo};
use super::util::{TimedDeque, TimedMap, Timer};

type Guard<'a, R> = MutexGuard<'a, QueueInner<R>>;

pub struct QueueConfig {
    pub acquire_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub max_waiters: Option<usize>,
    pub min_count: usize,
    pub max_count: Option<usize>,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            acquire_timeout: None,
            idle_timeout: None,
            max_waiters: None,
            min_count: 0,
            max_count: None,
        }
    }
}

pub struct QueueInner<R> {
    pub idle: TimedDeque<(R, ResourceInfo)>,
    pub release: TimedDeque<(R, ResourceInfo)>,
    pub running: bool,
    pub timers: TimedMap<Arc<Timer>>,
    pub total_count: usize,
    pub update_count: usize,
    pub verify: TimedDeque<(R, ResourceInfo)>,
    pub wait_count: usize,
}

pub struct Queue<R> {
    pub(super) config: Arc<QueueConfig>,
    cvar: Arc<Condvar>,
    inner: Arc<Mutex<QueueInner<R>>>,
}

impl<R> Clone for Queue<R> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            inner: self.inner.clone(),
            cvar: self.cvar.clone(),
        }
    }
}

impl<R: Send> Default for Queue<R> {
    fn default() -> Self {
        Self::new(QueueConfig::default())
    }
}

impl<R: Send> Queue<R> {
    pub fn new(config: QueueConfig) -> Self {
        let queue = Self {
            config: Arc::new(config),
            inner: Arc::new(Mutex::new(QueueInner {
                idle: TimedDeque::default(),
                release: TimedDeque::default(),
                running: false,
                timers: TimedMap::default(),
                total_count: 0,
                update_count: 0,
                verify: TimedDeque::default(),
                wait_count: 0,
            })),
            cvar: Arc::new(Condvar::new()),
        };
        queue
    }

    pub fn lock(&self) -> LockResult<Guard<R>> {
        self.inner.lock()
    }

    pub fn notify(&self) {
        self.cvar.notify_all()
    }

    pub fn release(&self, res: Option<R>, info: ResourceInfo) -> Option<R> {
        if let Ok(mut queue) = self.inner.lock() {
            if let Some(res) = res {
                queue.release.push_timed((res, info), None);
            } else {
                queue.total_count -= 1;
            }
            queue.update_count += 1;
            drop(queue);
            self.cvar.notify_all();
            None
        } else {
            res
        }
    }

    pub fn wait<'a>(&'a self, guard: Guard<'a, R>) -> LockResult<Guard<R>> {
        self.cvar.wait(guard)
    }

    pub fn wait_timeout<'a>(
        &'a self,
        guard: Guard<'a, R>,
        timeout: Duration,
    ) -> LockResult<(Guard<R>, WaitTimeoutResult)> {
        self.cvar.wait_timeout(guard, timeout)
    }
}
