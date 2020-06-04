use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use super::ResourceInfo;

pub struct QueueState<R: Send> {
    idle: VecDeque<(R, ResourceInfo)>,
}

pub struct QueueInternal<R: Send> {
    state: Mutex<QueueState<R>>,
    cvar: Condvar,
}

pub struct Queue<R: Send> {
    inner: Arc<QueueInternal<R>>,
}

impl<R: Send> Clone for Queue<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub enum QueueError {
    Empty,
    Poisoned,
}

impl<R: Send> Queue<R> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(QueueInternal {
                state: Mutex::new(QueueState {
                    idle: VecDeque::new(),
                }),
                cvar: Condvar::new(),
            }),
        }
    }

    #[inline]
    pub fn lock(&self) -> Result<MutexGuard<QueueState<R>>, QueueError> {
        self.inner.state.lock().map_err(|_| QueueError::Poisoned)
    }

    #[inline]
    pub fn notify(&self) {
        self.inner.cvar.notify_all()
    }

    pub fn wait<'a>(
        &'a self,
        guard: MutexGuard<'a, QueueState<R>>,
    ) -> Result<MutexGuard<QueueState<R>>, QueueError> {
        self.inner
            .cvar
            .wait(guard)
            .map_err(|_| QueueError::Poisoned)
    }

    pub fn acquire(mut state: MutexGuard<QueueState<R>>) -> Result<(R, ResourceInfo), QueueError> {
        if let Some(resinfo) = state.idle.pop_front() {
            Ok(resinfo)
        } else {
            Err(QueueError::Empty)
        }
    }

    pub fn release(&self, res: R, info: ResourceInfo) -> Result<(), (R, ResourceInfo, QueueError)> {
        match self.lock() {
            Ok(mut inner) => {
                inner.idle.push_front((res, info));
                self.notify();
                Ok(())
            }
            Err(e) => Err((res, info, e)),
        }
    }
}
