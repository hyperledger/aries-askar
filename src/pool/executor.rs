use std::sync::Arc;

use super::resource::{ApplyUpdate, ResourceFuture};

pub struct ExecutorInner<R, E> {
    create: Box<dyn ApplyUpdate<R, E> + Send + Sync>,
    dispose: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
    // handle_error
    //keepalive: Option<ResourceVerifyFn<'a, R, E>>,
    // verify: Option<Mutex<Box<dyn VerifyResource<'a, R, E>>>,
    // dispose: Option<Mutex<Box<dyn DisposeResource<'a, R, E>>>,
}

pub struct Executor<R, E> {
    inner: Arc<ExecutorInner<R, E>>,
}

impl<R, E> Clone for Executor<R, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R: Send, E: Send> Executor<R, E> {
    pub fn new(
        create: Box<dyn ApplyUpdate<R, E> + Send + Sync>,
        dispose: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
        // keepalive: Option<ResourceDisposeFn<'e, R, E>>,
    ) -> Self {
        Self {
            inner: Arc::new(ExecutorInner {
                create,
                dispose,
                //keepalive,
            }),
        }
    }

    fn run(self) {}

    // pub fn have_keepalive(&self) -> bool {
    //     self.keepalive.is_some()
    // }

    pub fn create(&self, mut target: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
        self.inner.create.apply(&mut target);
        target
    }

    pub fn handle_error(&self, err: E) {}

    pub fn verify_acquire(&self, fut: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
        fut
    }

    pub fn verify_release(&self, fut: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
        fut
    }

    pub fn dispose(&self, mut target: ResourceFuture<R, E>) {
        println!("dispose");
        if let Some(dispose) = self.inner.dispose.as_ref() {
            dispose.apply(&mut target);
            // self.spawn(target)
        }
    }
}
