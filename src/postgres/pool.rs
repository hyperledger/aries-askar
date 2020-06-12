use std::net::TcpStream;
use std::sync::Arc;

use smol::Async;

use tokio_postgres::{
    config::{Config, Host},
    // tls::TlsConnect,
    NoTls,
};
pub use tokio_postgres::{Client, Error};

use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::error::{KvError, KvResult};
use crate::pool::{Pool, PoolConfig};

const DEFAULT_PORT: u16 = 5432;

pub type PostgresPool = Pool<Client, KvError>;

type ConnSetupFn = dyn Fn(&mut Client) -> KvResult<()> + Send + Sync + 'static;

impl From<Error> for KvError {
    fn from(err: Error) -> Self {
        KvError::BackendError(err.to_string())
    }
}

pub struct PostgresPoolConfig {
    config: String,
    tls: bool,
    conn_setup: Vec<Box<ConnSetupFn>>,
}

impl PostgresPoolConfig {
    pub fn new<S: AsRef<str>>(config: S) -> Self {
        Self {
            config: config.as_ref().to_string(),
            tls: false,
            conn_setup: vec![],
        }
    }

    pub fn with_tls(mut self) -> Self {
        self.tls = true;
        self
    }

    pub fn on_connect<F>(mut self, setup: F) -> Self
    where
        F: Fn(&mut Client) -> Result<(), KvError> + Send + Sync + 'static,
    {
        self.conn_setup.push(Box::new(setup));
        self
    }

    pub fn into_pool(self, min_size: usize, max_size: usize) -> PostgresPool {
        let config = self.config;
        let tls = self.tls;
        let conn_setup = Arc::new(self.conn_setup);
        PoolConfig::new(move || {
            let (config, conn_setup) = (config.clone(), conn_setup.clone());
            async move {
                let config = config.parse::<Config>()?;
                let mut client = connect(config).await?;
                if !conn_setup.is_empty() {
                    // FIXME run in executor
                    for setup in conn_setup.iter() {
                        setup(&mut client)?;
                    }
                }

                Ok(client)
            }
        })
        // FIXME - on release, check that connection thread is idle (perform a task)
        // FIXME - set min count to 1 for in-memory DB to avoid dropping it
        .build()
    }
}

async fn connect(config: Config) -> KvResult<Client> {
    let mut ports = config.get_ports().iter().cloned();
    for host in config.get_hosts() {
        let port = ports.next().unwrap_or(DEFAULT_PORT);
        let hostname = match host {
            #[cfg(unix)]
            Host::Unix(path) => path.as_os_str().to_str().unwrap_or(""),
            Host::Tcp(tcp) => tcp.as_str(),
        };
        let stream = match Async::<TcpStream>::connect(hostname).await {
            Ok(s) => s,
            Err(err) => {
                println!("failed connect: {}", hostname);
                continue;
            }
        };
        // FIXME continue on error?
        let (client, connection) = config.connect_raw(stream.compat(), NoTls).await?;
        // FIXME add connection to executor
        return Ok(client);
    }
    Err(KvError::Disconnected)
}
