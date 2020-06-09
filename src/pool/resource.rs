use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_util::future::{BoxFuture, FutureExt};

use super::queue::Queue;

#[derive(Copy, Clone, Debug)]
pub struct ResourceInfo {
    pub start: Instant,
    pub created_at: Option<Instant>,
    pub borrow_count: usize,
    pub last_borrow: Option<Instant>,
    pub last_idle: Option<Instant>,
    pub last_verified: Option<Instant>,
    pub disposed_at: Option<Instant>,
    pub borrowed: bool,
}

impl Default for ResourceInfo {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            created_at: None,
            borrow_count: 0,
            last_borrow: None,
            last_idle: None,
            last_verified: None,
            disposed_at: None,
            borrowed: false,
        }
    }
}

pub struct Managed<R: Send> {
    value: Option<R>,
    info: ResourceInfo,
    queue: Option<Queue<R>>,
}

impl<R: Send> Managed<R> {
    pub(crate) fn new(value: R, info: ResourceInfo, queue: Queue<R>) -> Self {
        Self {
            value: Some(value),
            info,
            queue: Some(queue),
        }
    }
}

impl<R: Send + Debug> Debug for Managed<R> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        if fmt.alternate() {
            fmt.debug_struct("ManagedResource")
                .field("value", &self.deref())
                .field("info", &self.info)
                .finish()
        } else {
            Debug::fmt(&self.value, fmt)
        }
    }
}

impl<R: Send + Display> Display for Managed<R> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.deref(), fmt)
    }
}

impl<R: Send> Deref for Managed<R> {
    type Target = R;
    fn deref(&self) -> &Self::Target {
        // note: panics after drop when value is taken
        self.value.as_ref().unwrap()
    }
}

impl<R: Send> DerefMut for Managed<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // note: panics after drop when value is taken
        self.value.as_mut().unwrap()
    }
}

impl<R: Send> Drop for Managed<R> {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.take() {
            queue.release(self.value.take(), self.info);
        }
    }
}

pub struct ResourceFuture<R: Send, E> {
    value: Option<R>,
    info: ResourceInfo,
    queue: Option<Queue<R>>,
    update: Option<ResourceUpdate<R, E>>,
}

impl<R: Send, E> Unpin for ResourceFuture<R, E> {}

impl<R: Send, E> ResourceFuture<R, E> {
    pub(crate) fn new(
        value: Option<R>,
        info: ResourceInfo,
        queue: Queue<R>,
        update: Option<ResourceUpdate<R, E>>,
    ) -> Self {
        Self {
            value,
            info,
            queue: Some(queue),
            update,
        }
    }

    pub fn apply(&mut self, update: ResourceUpdate<R, E>) {
        assert!(self.complete());
        self.update.replace(update);
    }

    pub fn complete(&self) -> bool {
        self.update.is_none()
    }

    pub fn info(&mut self) -> &mut ResourceInfo {
        &mut self.info
    }

    pub fn to_managed(mut self) -> Managed<R> {
        let value = self.value.take().unwrap();

        // note: queue is taken here, so now the Managed is responsible
        // for decrementing the count by calling queue.release
        Managed::new(value, self.info, self.queue.take().unwrap())
    }
}

impl<R: Send, E> Deref for ResourceFuture<R, E> {
    type Target = Option<R>;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<R: Send, E> DerefMut for ResourceFuture<R, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<R: Send, E> Drop for ResourceFuture<R, E> {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.take() {
            queue.release(self.value.take(), self.info);
        }
    }
}

impl<R: Send, E: Send> Future for ResourceFuture<R, E> {
    type Output = Result<ResourceFuture<R, E>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.complete() {
            return Poll::Ready(Ok(ResourceFuture::new(
                self.value.take(),
                self.info,
                self.queue.take().unwrap(),
                None,
            )));
        }

        let mut update = self.update.as_mut().unwrap();
        match Pin::new(&mut update).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(
                result.map(|r| ResourceFuture::new(r, self.info, self.queue.take().unwrap(), None)),
            ),
        }
    }
}

pub type ResourceUpdate<R, E> = BoxFuture<'static, Result<Option<R>, E>>;

pub type ResourceUpdateFn<R, E> =
    Box<dyn Fn(Option<R>, ResourceInfo) -> ResourceUpdate<R, E> + Send + Sync>;

pub trait ApplyUpdate<R: Send, E> {
    fn apply(&self, fut: &mut ResourceFuture<R, E>);
}

impl<R: Send, E> ApplyUpdate<R, E> for ResourceUpdateFn<R, E> {
    fn apply(&self, fut: &mut ResourceFuture<R, E>) {
        let upd = (self)(fut.take(), *fut.info());
        fut.apply(upd);
    }
}

pub fn resource_create<C, F, R, E>(ctor: C) -> ResourceUpdateFn<R, E>
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = Result<R, E>> + Send + 'static,
    R: 'static,
    E: 'static,
{
    Box::new(move |_, _| ctor().map(|result| result.map(Option::Some)).boxed())
}

pub fn resource_dispose<D, F, R, E>(dtor: D) -> ResourceUpdateFn<R, E>
where
    D: Fn(R, ResourceInfo) -> F + Send + Sync + 'static,
    F: Future<Output = Result<(), E>> + Send + 'static,
    R: 'static,
    E: 'static,
{
    Box::new(move |r, i| {
        dtor(r.unwrap(), i)
            .map(|result| result.map(|_| None))
            .boxed()
    })
}

// pub fn resource_verify<'f, V, F, R, E>(verify: V) -> ResourceVerifyFn<'f, R, E>
// where
//     V: Fn(R, ResourceInfo) -> F + Send + Sync + 'static,
//     F: Future<Output = Result<Option<R>, E>> + Send + 'f,
//     R: 'f,
//     E: 'f,
// {
//     Box::new(move |r, i| verify(r, i).map(|_| None).boxed())
// }

// }
