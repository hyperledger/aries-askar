use std::fmt::{Debug, Display, Formatter};
use std::time::Instant;

use super::manager::ResourceManager;
use super::{PoolThreadState, WorkerFlag, WorkerMessage};

#[derive(Copy, Clone, Debug)]
pub struct ResourceInfo {
    pub created: Instant,
    pub use_count: usize,
    pub last_used: Option<Instant>,
    pub last_verified: Option<Instant>,
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
        if fmt.alternate() {
            fmt.debug_struct("PoolResource")
                .field("inner", &self.inner.as_ref().unwrap())
                .field("info", &self.info)
                .finish()
        } else {
            Debug::fmt(&self.inner.as_ref().unwrap(), fmt)
        }
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
    pub(crate) fn new(
        res: M::Resource,
        info: Option<ResourceInfo>,
        state: PoolThreadState<M>,
    ) -> Self {
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

    pub(crate) fn unwrap(mut self) -> (M::Resource, ResourceInfo) {
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
            if inner.flag != WorkerFlag::Done {
                inner.queue.push_back(WorkerMessage::Release(
                    self.inner.take().unwrap(),
                    self.info,
                ));
            }
            // state.cvar is notified automatically
        }
    }
}
