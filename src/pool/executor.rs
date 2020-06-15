use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use async_channel::{unbounded, Receiver, Sender};

use futures_util::future::{BoxFuture, FutureExt};

use super::sentinel::Sentinel;

pub struct Executor {
    inner: Option<Arc<ExecutorInner>>,
    panicked: Arc<AtomicBool>,
}

pub struct ExecutorInner {
    sender: Sender<BoxFuture<'static, ()>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Clone for Executor {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            panicked: self.panicked.clone(),
        }
    }
}

impl Executor {
    pub fn new(thread_count: usize) -> Self {
        let mut workers = vec![];
        let (sender, receiver) = unbounded();
        let panicked = Arc::new(AtomicBool::new(false));
        let sentinel = Sentinel::new(panicked.clone(), |state, _| {
            if thread::panicking() {
                state.store(true, Ordering::Relaxed);
            }
        });
        for _ in 0..thread_count {
            let wk_recv = receiver.clone();
            let wk_sentinel = sentinel.clone();
            workers.push(thread::spawn(move || {
                smol::run(Self::work(wk_recv, wk_sentinel))
            }));
        }
        Self {
            inner: Some(Arc::new(ExecutorInner { sender, workers })),
            panicked,
        }
    }

    pub fn spawn_ok(&self, fut: impl Future<Output = ()> + Send + 'static) {
        if self.panicked.load(Ordering::Relaxed) {
            panic!("Worker thread panicked");
        }
        self.inner
            .as_ref()
            .unwrap()
            .sender
            .try_send(fut.boxed())
            .expect("error spawning task into executor")
    }

    pub async fn work(receiver: Receiver<BoxFuture<'static, ()>>, sentinel: Sentinel<AtomicBool>) {
        loop {
            match receiver.recv().await {
                Ok(fut) => {
                    smol::Task::local(fut).await;
                }
                Err(_) => {
                    // exit loop once sender is dropped
                    drop(sentinel);
                    break;
                }
            }
        }
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // block on threads if the last instance of the executor
            if let Ok(ExecutorInner {
                mut workers,
                sender,
            }) = Arc::try_unwrap(inner)
            {
                drop(sender);
                for worker in workers.drain(..) {
                    worker.join().unwrap()
                }
            }
        }
    }
}
