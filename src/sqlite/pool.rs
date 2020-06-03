use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lazy_static::lazy_static;

use rusqlite::{Connection, Error, OpenFlags};

use crate::pool::{ResourceInfo, ResourceManager};

lazy_static! {
    static ref INMEM_SEQ: AtomicUsize = AtomicUsize::default();
}

type PoolInitFn = dyn FnOnce(&SqlitePoolConfig) -> Result<(), Error> + Send + 'static;
type ConnSetupFn = dyn Fn(&mut Connection) -> Result<(), Error> + Send + 'static;

pub struct SqlitePoolConfig {
    path: Option<String>,
    mem_seq: Option<usize>,
    flags: OpenFlags,
    vfs: Option<String>,
    pool_init: Vec<Box<PoolInitFn>>,
    conn_setup: Vec<Box<ConnSetupFn>>,
}

impl SqlitePoolConfig {
    pub fn file<S: AsRef<str>>(path: S) -> Self {
        Self {
            path: Some(path.as_ref().to_string()),
            mem_seq: None,
            flags: OpenFlags::default(),
            pool_init: vec![],
            conn_setup: vec![],
            vfs: None,
        }
    }

    pub fn in_memory() -> Self {
        Self {
            path: None,
            mem_seq: Some(INMEM_SEQ.load(Ordering::SeqCst)), // FIXME INC
            flags: OpenFlags::default(),
            pool_init: vec![],
            conn_setup: vec![],
            vfs: None,
        }
    }

    pub fn with_flags(mut self, flags: OpenFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_vfs<S: AsRef<str>>(mut self, vfs: S) -> Self {
        self.vfs = Some(vfs.as_ref().to_string());
        self
    }

    pub fn on_init<F>(mut self, init: F) -> Self
    where
        F: FnOnce(&Self) -> Result<(), Error> + Send + 'static,
    {
        self.pool_init.push(Box::new(init) as Box<PoolInitFn>);
        self
    }

    pub fn on_connect<F>(mut self, setup: F) -> Self
    where
        F: Fn(&mut Connection) -> Result<(), Error> + Send + 'static,
    {
        self.conn_setup.push(Box::new(setup));
        self
    }

    // pub fn into_pool(min_size: usize, max_size: usize)
}

impl ResourceManager for SqlitePoolConfig {
    type Resource = Connection;
    type Error = rusqlite::Error;

    fn init(&mut self) -> Result<(), Self::Error> {
        println!("init");
        let cbs = self.pool_init.drain(..).collect::<Vec<Box<PoolInitFn>>>();
        for cb in cbs {
            cb(&self)?;
        }
        Ok(())
    }

    fn create(&self) -> Result<Self::Resource, Self::Error> {
        println!("connect");
        let mut conn = if let Some(ref path) = &self.path {
            if let Some(ref vfs) = &self.vfs {
                Connection::open_with_flags_and_vfs(path, self.flags, vfs)
            } else {
                Connection::open_with_flags(path, self.flags)
            }
        } else {
            if let Some(ref vfs) = &self.vfs {
                Connection::open_in_memory_with_flags_and_vfs(self.flags, vfs)
            } else {
                Connection::open_in_memory_with_flags(self.flags)
            }
        }?;
        for cb in self.conn_setup.iter() {
            cb(&mut conn)?;
        }
        Ok(conn)
    }

    // after idle timeout:
    // connections under min_count are re-verified
    // connections beyond min_count are dropped
    fn idle_timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(30))
    }

    fn verify(&self, res: Self::Resource, _info: ResourceInfo) -> Option<Self::Resource> {
        // detect if connection was manually closed?
        // res.execute_batch("")
        Some(res)
    }

    fn dispose(&self, _res: Self::Resource, _info: ResourceInfo) {
        println!("dispose connection");
    }

    fn max_count(&self) -> Option<usize> {
        None
    }

    fn min_count(&self) -> usize {
        // set on config
        0
    }

    fn max_waiters(&self) -> Option<usize> {
        None
    }
}
