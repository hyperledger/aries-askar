use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use sqlx::{
    database::HasArguments, pool::PoolConnection, Acquire, Arguments, Database, Encode, Executor,
    IntoArguments, Transaction, Type,
};

use super::error::Result;
use super::future::{blocking, BoxFuture};
use super::keys::{store::StoreKey, AsyncEncryptor};
use super::types::{EncEntryTag, Expiry, ProfileId};
use super::wql::{
    self,
    sql::TagSqlEncoder,
    tags::{tag_query, TagQueryEncoder},
};

pub const PAGE_SIZE: usize = 32;

pub struct DbSession<'s, E, DB> {
    pub(crate) exec: E,
    pub(crate) is_txn: bool,
    pub(crate) profile_id: ProfileId,
    pub(crate) key: AsyncEncryptor<StoreKey>,
    _pd: PhantomData<&'s DB>,
}

impl<'s, E, DB> DbSession<'s, E, DB> {
    pub fn new(exec: E, is_txn: bool, profile_id: ProfileId, key: AsyncEncryptor<StoreKey>) -> Self
    where
        DB: Database,
        for<'e> &'e mut E: Executor<'e, Database = DB>,
    {
        Self {
            exec,
            is_txn,
            profile_id,
            key,
            _pd: PhantomData,
        }
    }

    pub async fn transaction<'t>(&'t mut self) -> Result<DbSession<'t, Transaction<'t, DB>, DB>>
    where
        DB: Database,
        for<'e> &'e mut E: Acquire<'e, Database = DB>,
        &'t mut Transaction<'t, DB>: Executor<'t, Database = DB>,
    {

        Ok(DbSession {
            exec: self.exec.begin().await?,
            is_txn: true,
            profile_id: self.profile_id,
            key: self.key.clone(),
            _pd: PhantomData,
        })
    }
}

pub trait CloseDbSession {
    fn close(self, commit: bool) -> BoxFuture<'static, Result<()>>;
}

impl<DB: Database> CloseDbSession for PoolConnection<DB> {
    fn close(self, _commit: bool) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move { Ok(()) })
    }
}

impl<DB: Database> CloseDbSession for Transaction<'static, DB> {
    fn close(self, commit: bool) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            if commit {
                self.commit().await
            } else {
                self.rollback().await
            }
            .map_err(err_map!("Error committing transaction"))
        })
    }
}

pub enum DbSessionRef<'q, 's: 'q, E, DB> {
    Owned(DbSession<'s, E, DB>),
    Borrowed(&'q mut DbSession<'s, E, DB>),
}

impl<'q, 's: 'q, E, DB> Deref for DbSessionRef<'q, 's, E, DB> {
    type Target = DbSession<'s, E, DB>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

impl<'q, 's: 'q, E, DB> DerefMut for DbSessionRef<'q, 's, E, DB> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
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

pub fn decode_tags(tags: &[u8]) -> std::result::Result<Vec<EncEntryTag>, ()> {
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
    tag_filter: Option<wql::Query>,
    key: Option<Arc<StoreKey>>,
    offset: usize,
) -> Result<Option<(String, Vec<Vec<u8>>)>> {
    if let Some(tag_filter) = tag_filter {
        blocking(move || {
            let tag_query = tag_query(tag_filter)?;
            let mut enc = if let Some(key) = key {
                let key2 = key.clone();
                TagSqlEncoder::new(
                    move |name| Ok(key.encrypt_tag_name(name)?),
                    move |value| Ok(key2.encrypt_tag_value(value)?),
                )
            } else {
                TagSqlEncoder::new(
                    |name| Ok(name.as_bytes().to_vec()),
                    |value| Ok(value.as_bytes().to_vec()),
                )
            };
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
