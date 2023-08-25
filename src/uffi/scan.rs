use std::sync::Arc;
use tokio::sync::Mutex;
use crate::{
    uffi::{error::ErrorCode, entry::AskarEntry},
    storage::entry::{Entry, Scan},
};

pub struct AskarScan {
    scan: Mutex<Scan<'static, Entry>>,
}

impl AskarScan {
    pub fn new(scan: Scan<'static, Entry>) -> Self {
        Self { scan: Mutex::new(scan) }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AskarScan {
    pub async fn next(&self) -> Result<Option<Vec<Arc<AskarEntry>>>, ErrorCode> {
        let mut scan = self.scan.lock().await;
        let entries = scan.fetch_next().await?;
        let entries: Vec<Arc<AskarEntry>> = entries
            .unwrap_or(vec![])
            .into_iter()
            .map(|entry| Arc::new(AskarEntry::new(entry)))
            .collect();
        if entries.is_empty() {
            Ok(None)
        } else {
            Ok(Some(entries))
        }
    }

    pub async fn fetch_all(&self) -> Result<Vec<Arc<AskarEntry>>, ErrorCode> {
        let mut scan = self.scan.lock().await;
        let mut entries = vec![];
        while let Some(mut batch) = scan.fetch_next().await? {
            entries.append(&mut batch);
        }
        let entries = entries
            .into_iter()
            .map(|entry| Arc::new(AskarEntry::new(entry)))
            .collect();
        Ok(entries)
    }
}
