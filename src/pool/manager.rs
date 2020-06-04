use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use super::queue::Queue;
use super::ResourceInfo;

pub trait ResourceManager: Send + 'static {
    type Resource: Send;
    type Error: std::fmt::Debug + Send;

    fn init(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    // fn init_timeout(&self) -> Option<Duration> {
    //     None
    // }

    fn create(&self) -> Result<Self::Resource, Self::Error>;

    // fn create_timeout(&self) -> Option<Duration> {
    //     None
    // }

    // after idle timeout:
    // connections under min_count are re-verified
    // connections beyond min_count are dropped
    fn idle_timeout(&self) -> Option<Duration> {
        None
    }

    // should perform keepalive if needed
    fn verify(&self, res: Self::Resource, _info: ResourceInfo) -> Option<Self::Resource> {
        Some(res)
    }

    fn dispose(&self, _res: Self::Resource, _info: ResourceInfo) {}

    fn max_count(&self) -> Option<usize> {
        None
    }

    fn min_count(&self) -> usize {
        0
    }

    fn max_waiters(&self) -> Option<usize> {
        None
    }
}

pub trait ManageResource: Send {
    type Resource: Send;
    type Error: std::fmt::Debug + Send;

    fn create(&self) -> Result<Self::Resource, Self::Error>;

    // should perform keepalive if needed
    fn verify(&self, res: Self::Resource, _info: ResourceInfo) -> Option<Self::Resource> {
        Some(res)
    }

    fn dispose(&self, _res: Self::Resource, _info: ResourceInfo) {}
}

pub trait Manager<R>: Clone + Send {
    fn create(&self, max_count: Option<usize>) -> Result<usize, usize>;

    fn release(&self, res: R, _info: ResourceInfo);

    fn dispose(&self, _res: R, _info: ResourceInfo);
}

pub struct AtomicCounter {
    count: AtomicUsize,
}

impl AtomicCounter {
    pub fn new(val: usize) -> Self {
        Self {
            count: AtomicUsize::new(val),
        }
    }

    pub fn increment(&self) -> usize {
        self.count.fetch_add(1, Ordering::SeqCst)
    }

    pub fn decrement(&self) -> usize {
        self.count.fetch_sub(1, Ordering::SeqCst)
    }

    pub fn value(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    pub fn try_increment(&self, max: usize) -> Result<usize, usize> {
        let mut count = self.count.load(Ordering::SeqCst);
        if count < max {
            count = self.increment();
            if count > max {
                self.decrement();
                Err(count)
            } else {
                Ok(count)
            }
        } else {
            Err(count)
        }
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

pub struct BlockingManager<M: ManageResource> {
    resmgr: Arc<Mutex<M>>,
    queue: Queue<M::Resource>,
    count: Arc<AtomicCounter>,
}

impl<M: ManageResource> BlockingManager<M> {
    pub fn new(resmgr: M, queue: Queue<M::Resource>, max_count: Option<usize>) -> Self {
        Self {
            resmgr: Arc::new(Mutex::new(resmgr)),
            queue,
            count: Arc::new(AtomicCounter::default()),
        }
    }

    pub fn count(&self) -> usize {
        self.count.value()
    }
}

impl<M: ManageResource> Clone for BlockingManager<M> {
    fn clone(&self) -> Self {
        Self {
            resmgr: self.resmgr.clone(),
            queue: self.queue.clone(),
            count: self.count.clone(),
        }
    }
}

impl<R: Send, M> Manager<R> for BlockingManager<M>
where
    M: ManageResource<Resource = R>,
{
    fn create(&self, max_count: Option<usize>) -> Result<usize, usize> {
        let mut count;
        if let Some(max_count) = max_count {
            count = self.count.try_increment(max_count)?;
        } else {
            count = self.count.increment();
        }
        match self.resmgr.lock().unwrap().create() {
            Ok(res) => {
                if let Err((res, info, _)) = self.queue.release(res, ResourceInfo::default()) {
                    self.dispose(res, info);
                    self.count.decrement();
                }
            }
            // FIXME add error handler
            Err(e) => {
                eprintln!("Error creating resource: {:?}", e);
                self.count.decrement();
            }
        }
        Ok(count)
    }

    fn release(&self, res: R, mut info: ResourceInfo) {
        if let Some(res) = self.resmgr.lock().unwrap().verify(res, info) {
            info.last_verified.replace(Instant::now());
            if let Err((res, info, _)) = self.queue.release(res, info) {
                self.dispose(res, info);
                self.count.decrement();
            }
        } else {
            self.count.decrement();
        }
    }

    fn dispose(&self, res: R, info: ResourceInfo) {
        self.resmgr.lock().unwrap().dispose(res, info)
    }
}

// TODO
// multi thread manager (verify and dispose on one thread, pool for creates)
// create on same thread if count is zero
