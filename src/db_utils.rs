use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::stream::BoxStream;

use sqlx::{database::HasArguments, Arguments, Database, Encode, IntoArguments, Type};

use super::error::KvResult;
use super::types::KvEntry;
use super::wql::{
    self,
    sql::TagSqlEncoder,
    tags::{tag_query, TagQueryEncoder},
};

pub const PAGE_SIZE: usize = 5;

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

pub trait QueryPrepare: Database {
    fn placeholder(index: i64) -> String {
        format!("?{}", index)
    }
}

pub fn replace_arg_placeholders<DB: QueryPrepare>(filter: &str, start_index: i64) -> (String, i64) {
    let mut index = start_index;
    let mut s: String = filter.to_owned();
    while let Some(pos) = s.find("$$") {
        let arg_str = DB::placeholder(index);
        s.replace_range(pos..(pos + 2), &arg_str);
        index = index + 1;
    }
    (s, index)
}

pub fn extend_query<'q, DB: QueryPrepare>(
    query: &str,
    args: &mut QueryParams<'q, DB>,
    tag_filter: Option<wql::Query>,
    limit: Option<(i64, i64)>,
) -> KvResult<String>
where
    i64: for<'e> Encode<'e, DB> + Type<DB>,
    Vec<u8>: for<'e> Encode<'e, DB> + Type<DB>,
{
    let mut query = query.to_string();
    let mut last_idx = args.len() as i64 + 1;

    if let Some(tag_filter) = tag_filter {
        let tag_query = tag_query(tag_filter)?;
        let mut enc = TagSqlEncoder::new();
        let filter: String = enc.encode_query(&tag_query)?;
        let (filter, next_idx) = replace_arg_placeholders::<DB>(&filter, last_idx);
        last_idx = next_idx;
        args.extend(enc.arguments);
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter);
    };
    if let Some((offs, limit)) = limit {
        args.push(offs);
        args.push(limit);
        let (limit, _next_idx) = replace_arg_placeholders::<DB>(" LIMIT $$, $$", last_idx);
        // last_idx = next_idx;
        query.push_str(&limit);
    };
    Ok(query)
}

pub type Scan = BoxStream<'static, KvResult<Vec<KvEntry>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanToken {
    pub id: usize,
}

impl ScanToken {
    const COUNT: AtomicUsize = AtomicUsize::new(0);

    pub fn next() -> Self {
        Self {
            id: Self::COUNT.fetch_add(1, Ordering::AcqRel),
        }
    }
}

#[derive(Debug)]
pub struct Lock {
    pub entry: KvEntry,
}

// FIXME pool instance will dispose of locks itself
// impl Drop for Lock<'_> {
//     fn drop(&mut self) {
//         // remove the lock
//         let entry = self.entry.clone();
//         self.ctx
//             .enter(move |conn| {
//                 conn.prepare_cached(
//                     "DELETE FROM items_locks WHERE
//                 key_id = ?1 AND category = ?2 AND name = ?3 AND value = ?4",
//                 )
//                 .and_then(|mut del_lock| {
//                     del_lock.execute(params![
//                         &entry.key_id,
//                         &entry.category,
//                         &entry.name,
//                         &entry.value
//                     ])
//                 })
//                 .map_err(|err| eprintln!("Error removing lock: {:?}", err))
//                 .unwrap_or(0);
//             })
//             // FIXME ensure error is logged on failure
//             .wait()
//             .unwrap_or(())
//     }
// }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockToken {
    pub id: usize,
}

impl LockToken {
    const COUNT: AtomicUsize = AtomicUsize::new(0);

    pub fn next() -> Self {
        Self {
            id: Self::COUNT.fetch_add(1, Ordering::AcqRel),
        }
    }
}
