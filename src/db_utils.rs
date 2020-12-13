use std::future::Future;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use sqlx::{
    database::HasArguments, pool::PoolConnection, Arguments, Database, Encode, IntoArguments, Pool,
    TransactionManager, Type,
};
use zeroize::Zeroize;

use super::error::Result;
use super::future::unblock;
use super::keys::{
    store::StoreKey,
    wrap::{WrapKey, WrapKeyMethod},
    KeyCache, PassKey,
};
use super::types::{EncEntryTag, Expiry, ProfileId, TagFilter};
use super::wql::{
    sql::TagSqlEncoder,
    tags::{tag_query, TagQueryEncoder},
};

pub const PAGE_SIZE: usize = 32;

pub struct DbSession<'s, DB: Database> {
    profile_key: DbSessionKey,
    state: DbSessionState<DB>,
    transaction: bool,
    _pd: PhantomData<&'s DB>,
}

impl<'s, DB: Database> DbSession<'s, DB> {
    pub(crate) fn new(
        pool: Pool<DB>,
        cache: Arc<KeyCache>,
        profile: String,
        transaction: bool,
    ) -> Self
    where
        DB: Database,
    {
        Self {
            profile_key: DbSessionKey::Pending { cache, profile },
            state: DbSessionState::Pending { pool },
            transaction,
            _pd: PhantomData,
        }
    }

    #[inline]
    fn connection_mut(&mut self) -> Option<&mut PoolConnection<DB>> {
        if let DbSessionState::Active { conn } = &mut self.state {
            Some(conn)
        } else {
            None
        }
    }

    #[inline]
    pub fn is_transaction(&self) -> bool {
        self.transaction
    }

    #[inline]
    fn pool(&self) -> Option<&Pool<DB>> {
        if let DbSessionState::Pending { pool, .. } = &self.state {
            Some(pool)
        } else {
            None
        }
    }

    pub(crate) fn profile_and_key(&mut self) -> Option<(ProfileId, Arc<StoreKey>)> {
        if let DbSessionKey::Active {
            profile_id,
            ref key,
        } = self.profile_key
        {
            Some((profile_id, key.clone()))
        } else {
            None
        }
    }

    pub(crate) async fn make_active<I>(
        &mut self,
        init_key: I,
    ) -> Result<DbSessionActive<'_, 's, DB>>
    where
        I: for<'a> GetProfileKey<'a, DB>,
    {
        if matches!(self.state, DbSessionState::Pending { .. }) {
            info!("Acquire pool connection");
            let mut conn = self.pool().unwrap().acquire().await?;
            if self.transaction {
                info!("Start transaction");
                DB::TransactionManager::begin(&mut conn).await?;
            }
            self.state = DbSessionState::Active { conn };
        }
        let profile_id = match &mut self.profile_key {
            DbSessionKey::Pending { cache, profile } => {
                let cache = cache.clone();
                let mut get_profile = String::new();
                std::mem::swap(profile, &mut get_profile);
                let (profile_id, key) = init_key
                    .call_once(self.connection_mut().unwrap(), cache, get_profile)
                    .await?;
                self.profile_key = DbSessionKey::Active { profile_id, key };
                profile_id
            }
            DbSessionKey::Active { profile_id, .. } => *profile_id,
        };
        let txn_depth = if self.transaction { 1 } else { 0 };
        Ok(DbSessionActive {
            inner: self,
            profile_id,
            txn_depth,
        })
    }

    #[inline]
    pub(crate) fn borrow_mut(&mut self) -> DbSessionRef<'_, 's, DB> {
        DbSessionRef::Borrowed(self)
    }

    #[inline]
    pub(crate) fn owned_ref(self) -> DbSessionRef<'s, 's, DB> {
        DbSessionRef::Owned(self)
    }

    pub(crate) async fn close(mut self, commit: bool) -> Result<()> {
        if self.transaction {
            if let Some(conn) = self.connection_mut() {
                if commit {
                    info!("Commit transaction on close");
                    DB::TransactionManager::commit(conn).await
                } else {
                    info!("Roll-back transaction on close");
                    DB::TransactionManager::rollback(conn).await
                }
                .map_err(err_map!(Backend, "Error closing transaction"))?;
            }
            self.transaction = false;
        }
        Ok(())
    }
}

impl<'q, DB: Database> Drop for DbSession<'q, DB> {
    fn drop(&mut self) {
        if self.transaction {
            if let Some(conn) = self.connection_mut() {
                info!("Dropped transaction: roll-back");
                DB::TransactionManager::start_rollback(conn);
            }
        } else {
            info!("Dropped pool connection")
        }
    }
}

pub(crate) trait GetProfileKey<'a, DB: Database> {
    type Fut: Future<Output = Result<(ProfileId, Arc<StoreKey>)>>;
    fn call_once(
        self,
        pool: &'a mut PoolConnection<DB>,
        cache: Arc<KeyCache>,
        profile: String,
    ) -> Self::Fut;
}

impl<'a, DB: Database, F, Fut> GetProfileKey<'a, DB> for F
where
    F: FnOnce(&'a mut PoolConnection<DB>, Arc<KeyCache>, String) -> Fut,
    Fut: Future<Output = Result<(ProfileId, Arc<StoreKey>)>> + 'a,
{
    type Fut = Fut;
    fn call_once(
        self,
        pool: &'a mut PoolConnection<DB>,
        cache: Arc<KeyCache>,
        profile: String,
    ) -> Self::Fut {
        self(pool, cache, profile)
    }
}

pub(crate) enum DbSessionState<DB: Database> {
    Active { conn: PoolConnection<DB> },
    Pending { pool: Pool<DB> },
}

unsafe impl<DB: Database> Sync for DbSessionState<DB> where DB::Connection: Send {}

pub(crate) enum DbSessionKey {
    Active {
        profile_id: ProfileId,
        key: Arc<StoreKey>,
    },
    Pending {
        cache: Arc<KeyCache>,
        profile: String,
    },
}

pub enum DbSessionRef<'q, 's: 'q, DB: Database> {
    Owned(DbSession<'s, DB>),
    Borrowed(&'q mut DbSession<'s, DB>),
}

impl<'q, 's: 'q, DB: Database> Deref for DbSessionRef<'q, 's, DB> {
    type Target = DbSession<'s, DB>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

impl<'q, 's: 'q, DB: Database> DerefMut for DbSessionRef<'q, 's, DB> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

pub(crate) struct DbSessionActive<'a, 's: 'a, DB: Database> {
    inner: &'a mut DbSession<'s, DB>,
    pub(crate) profile_id: ProfileId,
    txn_depth: usize,
}

impl<'q, 's: 'q, DB: Database> DbSessionActive<'q, 's, DB> {
    #[inline]
    pub fn connection_mut(&mut self) -> &mut PoolConnection<DB> {
        self.inner.connection_mut().unwrap()
    }

    pub async fn commit(mut self) -> Result<()> {
        if self.txn_depth > 0 {
            let conn = self.connection_mut();
            info!("Commit transaction");
            DB::TransactionManager::commit(conn).await?;
            self.txn_depth = 0;
        }
        Ok(())
    }

    #[inline]
    pub fn is_transaction(&self) -> bool {
        self.txn_depth > 0
    }

    pub async fn transaction<'t>(&'t mut self) -> Result<DbSessionActive<'t, 's, DB>>
    where
        's: 't,
    {
        info!("Start nested transaction");
        DB::TransactionManager::begin(self.connection_mut()).await?;
        Ok(DbSessionActive {
            inner: &mut *self.inner,
            profile_id: self.profile_id,
            txn_depth: self.txn_depth + 1,
        })
    }
}

impl<'q, 's: 'q, DB: Database> Drop for DbSessionActive<'q, 's, DB> {
    fn drop(&mut self) {
        if self.txn_depth > 1 {
            info!("Roll-back dropped nested transaction");
            DB::TransactionManager::start_rollback(self.connection_mut());
        }
    }
}

pub struct QueryParams<'q, DB: Database> {
    args: <DB as HasArguments<'q>>::Arguments,
    count: usize,
}

impl<'q, DB: Database> QueryParams<'q, DB> {
    pub fn new() -> Self {
        Self {
            args: Default::default(),
            count: 0,
        }
    }

    pub fn extend<I, T>(&mut self, vals: I)
    where
        I: IntoIterator<Item = T>,
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        for item in vals {
            self.args.add(item);
            self.count += 1;
        }
    }

    pub fn push<T>(&mut self, val: T)
    where
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        self.args.add(val);
        self.count += 1;
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'q, DB> IntoArguments<'q, DB> for QueryParams<'q, DB>
where
    DB: Database,
    <DB as HasArguments<'q>>::Arguments: IntoArguments<'q, DB>,
{
    fn into_arguments(self) -> <DB as HasArguments<'q>>::Arguments {
        self.args.into_arguments()
    }
}

pub trait QueryPrepare {
    type DB: Database;

    fn placeholder(index: i64) -> String {
        format!("?{}", index)
    }

    fn limit_query<'q>(
        mut query: String,
        args: &mut QueryParams<'q, Self::DB>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> String
    where
        i64: for<'e> Encode<'e, Self::DB> + Type<Self::DB>,
    {
        if offset.is_some() || limit.is_some() {
            let last_idx = (args.len() + 1) as i64;
            args.push(offset.unwrap_or(0));
            args.push(limit.unwrap_or(-1));
            let limit = replace_arg_placeholders::<Self>(" LIMIT $$, $$", last_idx);
            query.push_str(&limit);
        }
        query
    }
}

pub fn replace_arg_placeholders<Q: QueryPrepare + ?Sized>(
    filter: &str,
    start_index: i64,
) -> String {
    let mut index = start_index;
    let mut buffer: String = String::with_capacity(filter.len());
    let mut remain = filter;
    while let Some(start_offs) = remain.find('$') {
        let mut iter = remain[(start_offs + 1)..].chars();
        if let Some((end_offs, sub_index)) = iter.next().and_then(|c| match c {
            '$' => Some((start_offs + 2, index)),
            '0'..='9' => {
                let mut end_offs = start_offs + 2;
                while let Some(c) = iter.next() {
                    if ('0'..='9').contains(&c) {
                        end_offs += 1;
                    } else {
                        break;
                    }
                }
                Some((
                    end_offs,
                    remain[(start_offs + 1)..end_offs].parse::<i64>().unwrap() + start_index - 1,
                ))
            }
            _ => None,
        }) {
            buffer.push_str(&remain[..start_offs]);
            buffer.push_str(&Q::placeholder(sub_index));
            remain = &remain[end_offs..];
            index += 1;
        } else {
            buffer.push_str(&remain[..=start_offs]);
            remain = &remain[(start_offs + 1)..];
        }
    }
    buffer.push_str(remain);
    buffer
}

pub(crate) fn decode_tags(tags: &[u8]) -> std::result::Result<Vec<EncEntryTag>, ()> {
    let mut idx = 0;
    let mut plaintext;
    let mut name_start;
    let mut name_end;
    let mut enc_tags = vec![];
    let end = tags.len();
    loop {
        if idx >= end {
            break;
        }
        plaintext = tags[idx] == b'1';
        // assert ':' at idx + 1
        idx += 2;
        name_start = idx;
        name_end = 0;
        loop {
            if idx >= end || tags[idx] == b',' {
                if name_end == 0 {
                    return Err(());
                }
                let name = hex::decode(&tags[(name_start)..(name_end)]).map_err(|_| ())?;
                let value = hex::decode(&tags[(name_end + 1)..(idx)]).map_err(|_| ())?;
                enc_tags.push(EncEntryTag {
                    name,
                    value,
                    plaintext,
                });
                break;
            }
            if tags[idx] == b':' {
                if name_end != 0 {
                    return Err(());
                }
                name_end = idx;
            }
            idx += 1;
        }
        idx += 1;
    }
    Ok(enc_tags)
}

pub fn expiry_timestamp(expire_ms: i64) -> Result<Expiry> {
    chrono::Utc::now()
        .checked_add_signed(chrono::Duration::milliseconds(expire_ms))
        .ok_or_else(|| err_msg!(Unexpected, "Invalid expiry timestamp"))
}

pub async fn encode_tag_filter<Q: QueryPrepare>(
    tag_filter: Option<TagFilter>,
    key: Arc<StoreKey>,
    offset: usize,
) -> Result<Option<(String, Vec<Vec<u8>>)>> {
    if let Some(tag_filter) = tag_filter {
        unblock(move || {
            let tag_query = tag_query(tag_filter.query)?;
            let mut enc = TagSqlEncoder::new(
                |name| Ok(key.encrypt_tag_name(name)?),
                |value| Ok(key.encrypt_tag_value(value)?),
            );
            if let Some(filter) = enc.encode_query(&tag_query)? {
                let filter = replace_arg_placeholders::<Q>(&filter, (offset as i64) + 1);
                Ok(Some((filter, enc.arguments)))
            } else {
                Ok(None)
            }
        })
        .await
    } else {
        Ok(None)
    }
}

pub fn extend_query<'q, Q: QueryPrepare>(
    query: &str,
    args: &mut QueryParams<'q, Q::DB>,
    tag_filter: Option<(String, Vec<Vec<u8>>)>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<String>
where
    i64: for<'e> Encode<'e, Q::DB> + Type<Q::DB>,
    Vec<u8>: for<'e> Encode<'e, Q::DB> + Type<Q::DB>,
{
    let mut query = query.to_string();
    if let Some((filter_clause, filter_args)) = tag_filter {
        args.extend(filter_args);
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter_clause);
    };
    if offset.is_some() || limit.is_some() {
        query = Q::limit_query(query, args, offset, limit);
    };
    Ok(query)
}

pub fn init_keys<'a>(
    method: WrapKeyMethod,
    pass_key: PassKey<'a>,
) -> Result<(StoreKey, Vec<u8>, WrapKey, String)> {
    let (wrap_key, wrap_key_ref) = method.resolve(pass_key)?;
    let store_key = StoreKey::new()?;
    let enc_store_key = encode_store_key(&store_key, &wrap_key)?;
    Ok((store_key, enc_store_key, wrap_key, wrap_key_ref.into_uri()))
}

pub fn encode_store_key(store_key: &StoreKey, wrap_key: &WrapKey) -> Result<Vec<u8>> {
    let mut enc_store_key = store_key.to_string()?;
    let result = wrap_key.wrap_data(enc_store_key.as_bytes())?;
    enc_store_key.zeroize();
    Ok(result)
}

#[inline]
pub fn random_profile_name() -> String {
    uuid::Uuid::new_v4().to_string()
}
