use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_channel::{bounded, Receiver, SendError};
use async_resource::thread::{Task, ThreadResource};
use futures_util::stream::Stream;
use suspend::block_on;

pub use rusqlite::{params, Connection, Error, OpenFlags, Row, Rows, ToSql};

use crate::error::{KvError, KvResult};

#[derive(Debug)]
pub struct ConnectionContext {
    res: ThreadResource<Connection>,
}

impl ConnectionContext {
    pub fn new(path: String, flags: Option<OpenFlags>, vfs: Option<String>) -> Result<Self, Error> {
        let flags = flags.unwrap_or_default();
        let res = ThreadResource::try_create(move || {
            if let Some(ref vfs) = vfs {
                Connection::open_with_flags_and_vfs(path, flags, vfs.as_str())
            } else {
                Connection::open_with_flags(path, flags)
            }
        })?;
        Ok(Self { res })
    }

    // pub fn enter<F, R>(&mut self, f: F) -> Task<R>
    // where
    //     F: FnOnce(&mut Connection) -> R + Send + 'static,
    //     R: Send + 'static,
    // {
    //     self.res.enter(f)
    // }

    pub async fn perform<F, R>(&mut self, f: F) -> KvResult<R>
    where
        F: FnOnce(&mut Connection) -> KvResult<R> + Send + 'static,
        R: Send + 'static,
    {
        match self.res.enter(f).await {
            Err(_) => Err(KvError::Disconnected),
            Ok(val) => val,
        }
    }

    pub fn process_query<'q, P, R, T>(
        &'q mut self,
        sql: String,
        params: P,
        mut proc: R,
    ) -> QueryResults<'q, T>
    where
        P: IntoIterator + Send + 'static,
        P::Item: ToSql,
        R: ResultProcessor<Item = T> + Send + 'static,
        T: Send + 'static,
    {
        let (result_send, receiver) = bounded(20);
        let task = self.res.enter(move |conn| {
            let mut stmt = match conn.prepare(sql.as_str()) {
                Ok(stmt) => stmt,
                Err(err) => {
                    result_send.try_send(KvResult::Err(err.into())).ok();
                    return;
                }
            };
            let mut rows = match stmt.query(params) {
                Ok(rows) => rows,
                Err(err) => {
                    result_send.try_send(KvResult::Err(err.into())).ok();
                    return;
                }
            };
            while !proc.completed() {
                match proc.next(&mut rows, conn) {
                    Some(result) => {
                        match block_on(result_send.send(result)) {
                            Ok(_) => break,
                            Err(SendError(result)) => {
                                // receiver has gone away
                                drop(result);
                                break;
                            }
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        });
        QueryResults { receiver, task }
    }
}

pub struct QueryResults<'q, T> {
    receiver: Receiver<KvResult<T>>,
    task: Task<'q, ()>,
}

impl<'q, T> QueryResults<'q, T> {
    fn pin_receiver(self: Pin<&mut Self>) -> Pin<&mut Receiver<KvResult<T>>> {
        unsafe { Pin::map_unchecked_mut(self, |slf| &mut slf.receiver) }
    }

    fn pin_task(self: Pin<&mut Self>) -> Pin<&mut Task<'q, ()>> {
        unsafe { Pin::map_unchecked_mut(self, |slf| &mut slf.task) }
    }
}

impl<T> Stream for QueryResults<'_, T> {
    type Item = KvResult<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.as_mut().pin_receiver().poll_next(cx) {
            Poll::Ready(None) => (),
            Poll::Ready(val) => return Poll::Ready(val),
            Poll::Pending => return Poll::Pending,
        }
        match self.pin_task().poll(cx) {
            Poll::Ready(_) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
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

pub struct SqlParams<'a> {
    items: Vec<Box<dyn ToSql + Send + 'a>>,
}

impl<'a> SqlParams<'a> {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn from_iter<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToSql + Send + 'a,
    {
        let mut s = Self::new();
        s.extend(items);
        s
    }

    pub fn push<T>(&mut self, item: T)
    where
        T: ToSql + Send + 'a,
    {
        self.items.push(Box::new(item))
    }

    pub fn extend<I, T>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
        T: ToSql + Send + 'a,
    {
        self.items.extend(
            items
                .into_iter()
                .map(|item| Box::new(item) as Box<dyn ToSql + Send>),
        )
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

impl<'a> IntoIterator for SqlParams<'a> {
    type Item = Box<dyn ToSql + Send + 'a>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}
