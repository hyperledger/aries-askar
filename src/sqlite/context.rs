use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};
use futures_channel::{mpsc, oneshot};
use futures_util::{stream::Stream, task::AtomicWaker};
use rusqlite::{Connection, Error, OpenFlags, Row, Rows, ToSql};

use crate::error::KvResult;

type Task = Box<dyn FnOnce(&mut Connection) + Send>;

pub struct ConnectionContext {
    handle: Arc<JoinHandle<()>>,
    sender: Sender<Task>,
}

impl ConnectionContext {
    pub fn new(path: String, flags: OpenFlags, vfs: Option<String>) -> Result<Self, Error> {
        let mut conn = if let Some(ref vfs) = vfs {
            Connection::open_with_flags_and_vfs(path, flags, vfs.as_str())
        } else {
            Connection::open_with_flags(path, flags)
        }?;
        let (sender, receiver) = bounded::<Task>(1);
        let handle = thread::spawn(move || {
            for task in receiver {
                task(&mut conn);
            }
        });
        Ok(Self {
            handle: Arc::new(handle),
            sender,
        })
    }

    pub async fn enter<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Connection) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        self.perform(|mut conn| {
            sender.send(f(&mut conn)).ok();
        });
        receiver.await.unwrap()
    }

    pub fn perform<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Connection) + Send + 'static,
    {
        // note: this is not expected to block because the connection
        // is only accessed by the thread that acquired it
        self.sender.send(Box::new(f)).unwrap();
    }

    pub async fn process_query<P, R, T>(
        &mut self,
        sql: String,
        params: P,
        mut proc: R,
    ) -> KvResult<QueryResults<T>>
    where
        P: IntoIterator + Send + 'static,
        P::Item: ToSql,
        R: ResultProcessor<Item = T> + Send + 'static,
        T: Send + 'static,
    {
        let (init_sender, init_receiver) = oneshot::channel();
        self.perform(move |conn| {
            let mut stmt = match conn.prepare(sql.as_str()) {
                Ok(stmt) => stmt,
                Err(err) => {
                    init_sender.send(KvResult::Err(err.into())).ok();
                    return;
                }
            };
            let mut rows = match stmt.query(params) {
                Ok(rows) => rows,
                Err(err) => {
                    init_sender.send(KvResult::Err(err.into())).ok();
                    return;
                }
            };
            let (sender, receiver) = bounded(1);
            let waker = Arc::new(AtomicWaker::default());
            init_sender.send(Ok((receiver, waker.clone()))).ok();
            while !proc.completed() {
                match proc.next(&mut rows, conn) {
                    Some(mut result) => loop {
                        result = match sender.try_send(result) {
                            Ok(_) => break,
                            Err(TrySendError::Full(result)) => {
                                waker.wake();
                                thread::park();
                                result
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                return;
                            }
                        }
                    },
                    None => {
                        break;
                    }
                }
            }
            waker.wake();
        });
        let (receiver, waker) = init_receiver.await.unwrap()?;
        Ok(QueryResults {
            ctx: self.handle.clone(),
            receiver,
            waker,
        })
    }
}

pub struct QueryResults<T> {
    ctx: Arc<JoinHandle<()>>,
    receiver: Receiver<KvResult<T>>,
    waker: Arc<AtomicWaker>,
}

impl<T> Stream for QueryResults<T> {
    type Item = KvResult<T>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.receiver.try_recv() {
            Ok(val) => Poll::Ready(Some(val)),
            Err(TryRecvError::Empty) => {
                self.waker.register(cx.waker());
                self.ctx.thread().unpark();
                Poll::Pending
            }
            Err(TryRecvError::Disconnected) => Poll::Ready(None),
        }
    }
}

pub trait ResultProcessor {
    type Item;
    fn next(&mut self, rows: &mut Rows, conn: &Connection) -> Option<KvResult<Self::Item>>;
    fn completed(&self) -> bool;
}

pub trait BatchProcessor {
    type Row;
    type Result;
    fn process_row(&mut self, row: &Row) -> KvResult<Self::Row>;
    fn process_batch(&mut self, rows: Vec<Self::Row>, conn: &Connection) -> KvResult<Self::Result>;
}

pub struct BatchQuery<P: BatchProcessor> {
    completed: bool,
    batch: usize,
    proc: P,
}

impl<P: BatchProcessor> BatchQuery<P> {
    pub fn new(batch: usize, proc: P) -> Self {
        Self {
            completed: false,
            batch,
            proc,
        }
    }
}

impl<P: BatchProcessor> ResultProcessor for BatchQuery<P> {
    type Item = (P::Result, bool);

    fn completed(&self) -> bool {
        self.completed
    }

    fn next(&mut self, rows: &mut Rows, conn: &Connection) -> Option<KvResult<(P::Result, bool)>> {
        let mut processed_rows = vec![];
        for _ in 0..self.batch {
            match rows.next().transpose().map(|row_result| {
                row_result
                    .map_err(Into::into)
                    .and_then(|row| self.proc.process_row(&row))
            }) {
                Some(Ok(r)) => {
                    processed_rows.push(r);
                }
                Some(Err(err)) => {
                    self.completed = true;
                    return Some(Err(err));
                }
                None => {
                    self.completed = true;
                    break;
                }
            }
        }
        if processed_rows.is_empty() {
            None
        } else {
            Some(
                self.proc
                    .process_batch(processed_rows, conn)
                    .map(|r| (r, self.completed)),
            )
        }
    }
}
