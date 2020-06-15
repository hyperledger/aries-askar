use std::sync::Arc;

use super::resource::{ApplyUpdate, ResourceFuture};

pub struct Manager<R, E> {
    inner: Arc<ManagerInner<R, E>>,
}

pub struct ManagerInner<R, E> {
    create: Box<dyn ApplyUpdate<R, E> + Send + Sync>,
    dispose: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
    keepalive: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
    // handle_error
}

impl<R, E> Clone for Manager<R, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R: Send, E: Send> Manager<R, E> {
    pub fn new(
        create: Box<dyn ApplyUpdate<R, E> + Send + Sync>,
        dispose: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
        keepalive: Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
    ) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                create,
                dispose,
                keepalive,
            }),
        }
    }

    pub fn create(&self, mut target: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
        self.inner.create.apply(&mut target);
        target
    }

    pub fn keepalive(&self, mut target: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
        println!("keepalive");
        if let Some(handler) = self.inner.keepalive.as_ref() {
            handler.apply(&mut target);
            target
        } else {
            self.dispose(target)
        }
    }

    pub fn handle_error(&self, err: E) {}

    // pub fn verify_acquire(&self, fut: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
    //     fut
    // }

    // pub fn verify_release(&self, fut: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
    //     fut
    // }

    pub fn dispose(&self, mut target: ResourceFuture<R, E>) -> ResourceFuture<R, E> {
        println!("dispose");
        if let Some(handler) = self.inner.dispose.as_ref() {
            handler.apply(&mut target);
        }
        target
    }

    // #[inline]
    // fn apply(
    //     &self,
    //     handler: &Option<Box<dyn ApplyUpdate<R, E> + Send + Sync>>,
    //     mut target: ResourceFuture<R, E>,
    // ) -> ResourceFuture<R, E> {
    //     if let Some(handler) = handler.as_ref() {
    //         handler.apply(&mut target);
    //     }
    //     target
    // }
}
