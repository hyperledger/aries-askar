use std::sync::{Arc, Condvar, LockResult, Mutex, MutexGuard, WaitTimeoutResult};
use std::time::Duration;

use super::resource::ResourceInfo;
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

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum QueueStatus {
    Init,
    Running,
    Draining,
    Shutdown,
    Stopped,
}

impl QueueStatus {
    pub fn is_running(&self) -> bool {
        *self == Self::Init || *self == Self::Running
    }

    pub fn is_shutdown(&self) -> bool {
        *self == Self::Shutdown || *self == Self::Stopped
    }
}

pub struct QueueInner<R> {
    pub idle: TimedDeque<(R, ResourceInfo)>,
    pub release: TimedDeque<(R, ResourceInfo)>,
    pub status: QueueStatus,
    pub timers: TimedMap<Arc<Timer>>,
    pub total_count: usize,
    pub update_count: usize,
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
                status: QueueStatus::Init,
                timers: TimedMap::default(),
                total_count: 0,
                update_count: 0,
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
        // FIXME use atomic for counts
        // if value is none, mutex is not needed
        if let Ok(mut guard) = self.inner.lock() {
            if !guard.status.is_shutdown() {
                if let Some(res) = res {
                    guard.release.push_timed((res, info), None);
                } else {
                    guard.total_count -= 1;
                }
                guard.update_count += 1;
                drop(guard);
                self.notify();
                return None;
            }
        }
        res
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
