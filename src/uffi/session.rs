use std::{
    str::FromStr,
    sync::Arc,
};
use tokio::sync::Mutex;
use crate::{
    ffi::tags::EntryTagSet,
    storage::entry::{EntryOperation, TagFilter},
    store::Session,
    uffi::{error::ErrorCode, entry::AskarEntry, entry::AskarKeyEntry, key::AskarLocalKey},
};

#[derive(uniffi::Enum)]
pub enum AskarEntryOperation {
    Insert,
    Replace,
    Remove,
}

impl Into<EntryOperation> for AskarEntryOperation {
    fn into(self) -> EntryOperation {
        match self {
            AskarEntryOperation::Insert => EntryOperation::Insert,
            AskarEntryOperation::Replace => EntryOperation::Replace,
            AskarEntryOperation::Remove => EntryOperation::Remove,
        }
    }
}

macro_rules! SESSION_CLOSED_ERROR {
    () => {
        ErrorCode::Unexpected { message: String::from("Session is already closed") }
    };
}

pub struct AskarSession {
    session: Mutex<Option<Session>>,
}

impl AskarSession {
    pub fn new(session: Session) -> Self {
        Self { session: Mutex::new(Some(session)) }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AskarSession {
    pub async fn close(&self) -> Result<(), ErrorCode> {
        self.session.lock().await.take();
        Ok(())
    }

    pub async fn count(
        &self,
        category: String,
        tag_filter: Option<String>,
    ) -> Result<i64, ErrorCode> {
        Ok(self.
            session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .count(Some(&category), tag_filter.as_deref().map(TagFilter::from_str).transpose()?)
            .await?)
    }

    pub async fn fetch(
        &self,
        category: String,
        name: String,
        for_update: bool,
    ) -> Result<Option<Arc<AskarEntry>>, ErrorCode> {
        let entry = self
            .session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .fetch(&category, &name, for_update)
            .await?;
        Ok(entry.map(|entry| Arc::new(AskarEntry::new(entry))))
    }

    pub async fn fetch_all(
        &self,
        category: String,
        tag_filter: Option<String>,
        limit: Option<i64>,
        for_update: bool,
    ) -> Result<Vec<Arc<AskarEntry>>, ErrorCode> {
        let entries = self
            .session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .fetch_all(Some(&category), tag_filter.as_deref().map(TagFilter::from_str).transpose()?, limit, for_update)
            .await?;
        Ok(entries
            .into_iter()
            .map(|entry| Arc::new(AskarEntry::new(entry)))
            .collect())
    }

    pub async fn update(
        &self,
        operation: AskarEntryOperation,
        category: String,
        name: String,
        value: Vec<u8>,
        tags: Option<String>,
        expiry_ms: Option<i64>,
    ) -> Result<(), ErrorCode> {
        let tags = if let Some(tags) = tags {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(&tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        self.session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .update(operation.into(), &category, &name, Some(&value), tags.as_deref(), expiry_ms)
            .await?;
        Ok(())
    }

    pub async fn remove_all(
        &self,
        category: String,
        tag_filter: Option<String>,
    ) -> Result<i64, ErrorCode> {
        Ok(self
            .session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .remove_all(Some(&category), tag_filter.as_deref().map(TagFilter::from_str).transpose()?)
            .await?)
    }

    pub async fn insert_key(
        &self,
        name: String,
        key: Arc<AskarLocalKey>,
        metadata: Option<String>,
        tags: Option<String>,
        expiry_ms: Option<i64>,
    ) -> Result<(), ErrorCode> {
        let tags = if let Some(tags) = tags {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(&tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        self.session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .insert_key(&name, &key.key, metadata.as_deref(), tags.as_deref(), expiry_ms)
            .await?;
        Ok(())
    }

    pub async fn fetch_key(
        &self,
        name: String,
        for_update: bool,
    ) -> Result<Option<Arc<AskarKeyEntry>>, ErrorCode> {
        let key = self
            .session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .fetch_key(&name, for_update)
            .await?;
        Ok(key.map(|entry| Arc::new(AskarKeyEntry::new(entry))))
    }

    pub async fn fetch_all_keys(
        &self,
        algorithm: Option<String>,
        thumbprint: Option<String>,
        tag_filter: Option<String>,
        limit: Option<i64>,
        for_update: bool,
    ) -> Result<Vec<Arc<AskarKeyEntry>>, ErrorCode> {
        let tag_filter = tag_filter.as_deref().map(TagFilter::from_str).transpose()?;
        let keys = self
            .session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .fetch_all_keys(algorithm.as_deref(), thumbprint.as_deref(), tag_filter, limit, for_update)
            .await?;
        Ok(keys
            .into_iter()
            .map(|entry| Arc::new(AskarKeyEntry::new(entry)))
            .collect())
    }

    pub async fn remove_key(&self, name: String) -> Result<(), ErrorCode> {
        self
            .session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .remove_key(&name).await?;
        Ok(())
    }

    pub async fn update_key(
        &self,
        name: String,
        metadata: Option<String>,
        tags: Option<String>,
        expiry_ms: Option<i64>,
    ) -> Result<(), ErrorCode> {
        let tags = if let Some(tags) = tags {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(&tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        self.session
            .lock()
            .await
            .as_mut()
            .ok_or(SESSION_CLOSED_ERROR!())?
            .update_key(&name, metadata.as_deref(), tags.as_deref(), expiry_ms)
            .await?;
        Ok(())
    }
}
