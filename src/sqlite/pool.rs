use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_resource::{Pool, PoolConfig};

use rusqlite::{Connection, Error, OpenFlags};

use super::context::ConnectionContext;
use crate::error::{KvError, KvResult};

static INMEM_SEQ: AtomicUsize = AtomicUsize::new(1);

pub type SqlitePool = Pool<ConnectionContext, KvError>;

type ConnSetupFn = dyn Fn(&mut Connection) -> KvResult<()> + Send + Sync + 'static;

impl From<Error> for KvError {
    fn from(err: Error) -> Self {
        KvError::BackendError(err.to_string())
    }
}

pub struct SqlitePoolConfig {
    path: String,
    flags: OpenFlags,
    vfs: Option<String>,
    conn_setup: Vec<Box<ConnSetupFn>>,
}

impl SqlitePoolConfig {
    pub fn file<S: AsRef<str>>(path: S) -> Self {
        Self {
            path: path.as_ref().to_string(),
            flags: OpenFlags::default(),
            conn_setup: vec![],
            vfs: None,
        }
    }

    pub fn in_memory() -> Self {
        let seq = INMEM_SEQ.fetch_add(1, Ordering::SeqCst);
        Self {
            path: format!("file:in-mem-{}?mode=memory&cache=shared", seq),
            flags: OpenFlags::default(),
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

    pub fn on_connect<F>(mut self, setup: F) -> Self
    where
        F: Fn(&mut Connection) -> Result<(), KvError> + Send + Sync + 'static,
    {
        self.conn_setup.push(Box::new(setup));
        self
    }

    pub fn into_pool(self, min_size: usize, max_size: usize) -> SqlitePool {
        let path = self.path;
        let flags = self.flags;
        let vfs = self.vfs;
        let conn_setup = Arc::new(self.conn_setup);
        PoolConfig::new(move || {
            let (path, flags, vfs, conn_setup) =
                (path.clone(), flags.clone(), vfs.clone(), conn_setup.clone());
            async move {
                let mut conn = ConnectionContext::new(path, flags, vfs)?;
                if !conn_setup.is_empty() {
                    conn.perform(move |mut conn| {
                        for setup in conn_setup.iter() {
                            setup(&mut conn)?;
                        }
                        KvResult::Ok(())
                    })
                    .await?;
                }
                Ok(conn)
            }
        })
        .min_count(min_size)
        .max_count(max_size)
        // FIXME - on release, check that connection thread is idle (perform a task)
        .build()
        .unwrap()
    }
}
