use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_mutex::Mutex;
use async_resource::Executor;
use ffi_support::{rust_string_to_c, FfiStr};
use futures_util::future::FutureExt;
use indy_utils::new_handle_type;
use once_cell::sync::Lazy;

use super::error::set_last_error;
use super::{CallbackId, EnsureCallback, ErrorCode, RUNTIME};
use crate::error::Result as KvResult;
use crate::keys::wrap::{generate_raw_wrap_key, WrapKeyMethod};
use crate::store::{KvProvisionSpec, KvProvisionStore, KvStore, LockToken, ScanToken};
use crate::types::{KvEntry, KvTag, KvUpdateEntry};

new_handle_type!(StoreHandle, FFI_STORE_COUNTER);
new_handle_type!(ScanHandle, FFI_SCAN_COUNTER);

pub type ArcStore = Arc<dyn KvStore + Send + Sync>;

static STORES: Lazy<Mutex<BTreeMap<StoreHandle, ArcStore>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static SCANS: Lazy<Mutex<BTreeMap<ScanHandle, Option<(ArcStore, ScanToken)>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

impl StoreHandle {
    pub async fn load(&self) -> KvResult<ArcStore> {
        STORES
            .lock()
            .await
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn remove(&self) -> KvResult<ArcStore> {
        STORES
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }
}

impl ScanHandle {
    pub async fn load(&self) -> KvResult<Option<(ArcStore, ScanToken)>> {
        SCANS
            .lock()
            .await
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid scan handle"))
    }

    pub async fn update(&self, value: Option<(ArcStore, ScanToken)>) -> KvResult<()> {
        SCANS.lock().await.insert(*self, value);
        Ok(())
    }

    pub async fn remove(&self) -> KvResult<Option<(ArcStore, ScanToken)>> {
        SCANS
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))
    }
}

// FIXME zeroize
struct FfiTagBuf {
    name: CString,
    value: CString,
}

#[repr(C)]
pub struct FfiTag {
    name: *const c_char,
    value: *const c_char,
}

impl FfiTag {
    pub fn decode(&self) -> KvResult<KvTag> {
        let name = unsafe { FfiStr::from_raw(self.name) }
            .as_opt_str()
            .ok_or_else(|| err_msg!("Invalid tag name"))?;
        let value = unsafe { FfiStr::from_raw(self.value) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Invalid tag value"))?;
        Ok(if name.chars().next() == Some('~') {
            KvTag::Plaintext(name[1..].to_owned(), value)
        } else {
            KvTag::Encrypted(name.to_owned(), value)
        })
    }
}

struct FfiEntryBuf {
    category: CString,
    name: CString,
    value: Vec<u8>,
    #[allow(unused)] // referenced by tags_ref
    tags: Vec<FfiTagBuf>,
    tags_ref: Vec<FfiTag>,
}

impl From<KvEntry> for FfiEntryBuf {
    fn from(entry: KvEntry) -> Self {
        let category = CString::new(entry.category.clone()).unwrap();
        let name = CString::new(entry.name.clone()).unwrap();
        let mut tags = vec![];
        let mut tags_ref = vec![];
        let mut tags_idx = 0;
        if let Some(entry_tags) = entry.tags.as_ref() {
            for tag in entry_tags {
                let (name, value) = match tag {
                    KvTag::Encrypted(tag_name, tag_value) => (
                        CString::new(tag_name.as_bytes()).unwrap(),
                        CString::new(tag_value.as_bytes()).unwrap(),
                    ),
                    KvTag::Plaintext(tag_name, tag_value) => {
                        let mut name = "~".to_owned();
                        name.push_str(&tag_name);
                        (
                            CString::new(name.into_bytes()).unwrap(),
                            CString::new(tag_value.as_bytes()).unwrap(),
                        )
                    }
                };
                tags.push(FfiTagBuf { name, value });
                tags_ref.push(FfiTag {
                    name: tags[tags_idx].name.as_c_str().as_ptr(),
                    value: tags[tags_idx].value.as_c_str().as_ptr(),
                });
                tags_idx += 1;
            }
        }
        Self {
            category,
            name,
            value: entry.value.clone(),
            tags,
            tags_ref,
        }
    }
}

pub struct FfiEntrySet {
    pos: AtomicUsize,
    rows: Vec<FfiEntryBuf>,
}

impl FfiEntrySet {
    pub fn next(&self) -> Option<FfiEntry> {
        let pos = self.pos.fetch_add(1, Ordering::Release);
        if pos < self.rows.len() {
            let row = &self.rows[pos];
            Some(FfiEntry {
                category: row.category.as_ptr(),
                name: row.name.as_ptr(),
                value: row.value.as_ptr(),
                value_len: row.value.len(),
                tags: row.tags_ref.as_ptr(),
                tags_len: row.tags_ref.len() * mem::size_of::<FfiTag>(),
            })
        } else {
            None
        }
    }
}

impl From<KvEntry> for FfiEntrySet {
    fn from(entry: KvEntry) -> Self {
        Self {
            pos: AtomicUsize::default(),
            rows: vec![entry.into()],
        }
    }
}

impl From<Vec<KvEntry>> for FfiEntrySet {
    fn from(entries: Vec<KvEntry>) -> Self {
        Self {
            pos: AtomicUsize::default(),
            rows: entries.into_iter().map(Into::into).collect(),
        }
    }
}

#[repr(C)]
pub struct FfiEntry {
    category: *const c_char,
    name: *const c_char,
    value: *const u8,
    value_len: usize,
    tags: *const FfiTag,
    tags_len: usize,
}

impl FfiEntry {
    pub fn decode(&self) -> KvResult<KvEntry> {
        let category = unsafe { FfiStr::from_raw(self.category) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Invalid entry category"))?;
        let name = unsafe { FfiStr::from_raw(self.name) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Invalid entry name"))?;
        let value = unsafe { slice::from_raw_parts(self.value, self.value_len) };
        if self.tags_len % mem::size_of::<FfiTag>() != 0 {
            return Err(err_msg!("Invalid length for entry tags"));
        }
        let tags_count = self.tags_len / mem::size_of::<FfiTag>();
        let tags = unsafe { slice::from_raw_parts(self.tags, tags_count) };
        let entry = KvEntry {
            category,
            name,
            value: value.to_vec(),
            tags: Some(tags.into_iter().try_fold(vec![], |mut acc, tag| {
                acc.push(tag.decode()?);
                KvResult::Ok(acc)
            })?),
        };
        Ok(entry)
    }
}

#[repr(C)]
pub struct FfiUpdateEntry {
    entry: FfiEntry,
    expire_ms: i64,
    profile_id: i64,
}

impl FfiUpdateEntry {
    pub fn decode(&self) -> KvResult<KvUpdateEntry> {
        let entry = self.entry.decode()?;
        Ok(KvUpdateEntry {
            entry,
            expire_ms: if self.expire_ms < 0 {
                None
            } else {
                Some(self.expire_ms)
            },
            profile_id: if self.profile_id == 0 {
                None
            } else {
                Some(self.profile_id)
            },
        })
    }
}

#[no_mangle]
pub extern "C" fn aries_store_provision(
    spec_uri: FfiStr,
    wrap_key_method: FfiStr,
    pass_key: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Provision store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No provision spec URI provided"))?;
        let wrap_key_method = match wrap_key_method.as_opt_str() {
            Some(method) => WrapKeyMethod::parse_uri(method)?,
            None => WrapKeyMethod::default()
        };
        let pass_key = pass_key.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => cb(cb_id, ErrorCode::Success, sid),
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        RUNTIME.spawn_ok(async move {
            let result = async {
                let spec = KvProvisionSpec::create(wrap_key_method, pass_key).await?;
                let store = spec_uri.provision_store(spec).await?;
                let handle = StoreHandle::next();
                let mut stores = STORES.lock().await;
                stores.insert(handle, store);
                Ok(handle)
            }.await;
            cb.resolve(result);
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_generate_raw_key(result_p: *mut *const c_char) -> ErrorCode {
    catch_err! {
        trace!("Create raw key");
        check_useful_c_ptr!(result_p);
        let key = generate_raw_wrap_key()?;
        unsafe { *result_p = rust_string_to_c(key); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_count(
    handle: StoreHandle,
    category: FfiStr,
    tag_filter: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, usize)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Invalid category"))?;
        let tag_filter = tag_filter.as_opt_str().map(serde_json::from_str).transpose().map_err(err_map!("Error parsing tag query"))?;
        let cb = EnsureCallback::new(move |result: KvResult<i64>|
            match result {
                Ok(count) => cb(cb_id, ErrorCode::Success, count as usize),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        RUNTIME.spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.count(None, category.as_str(), tag_filter).await
            }.await;
            cb.resolve(result);
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_fetch(
    handle: StoreHandle,
    category: FfiStr,
    name: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, *const FfiEntrySet)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Invalid category"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Invalid name"))?;
        let cb = EnsureCallback::new(move |result: KvResult<Option<KvEntry>>|
            match result {
                Ok(Some(entry)) => {
                    let results = Box::into_raw(Box::new(FfiEntrySet::from(entry)));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, ptr::null()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        RUNTIME.spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.fetch(None, &category, &name, Default::default()).await
            }.await;
            cb.resolve(result);
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_scan_start(
    handle: StoreHandle,
    category: FfiStr,
    tag_filter: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, ScanHandle)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store start");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Invalid category"))?;
        let tag_filter = tag_filter.as_opt_str().map(serde_json::from_str).transpose().map_err(err_map!("Error parsing tag query"))?;
        let cb = EnsureCallback::new(move |result: KvResult<ScanHandle>|
            match result {
                Ok(handle) => cb(cb_id, ErrorCode::Success, handle),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ScanHandle::invalid()),
            }
        );
        RUNTIME.spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let scan = store.scan_start(None, &category, Default::default(), tag_filter, None, None).await?;
                let handle = ScanHandle::next();
                let mut scans = SCANS.lock().await;
                scans.insert(handle, Some((store, scan)));
                Ok(handle)
            }.await;
            cb.resolve(result);
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_scan_next(
    handle: ScanHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, *const FfiEntrySet)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store next");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: KvResult<Option<Vec<KvEntry>>>|
            match result {
                Ok(Some(entries)) => {
                    let results = Box::into_raw(Box::new(FfiEntrySet::from(entries)));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, ptr::null()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        RUNTIME.spawn_ok(async move {
            let result = async {
                if let Some((store, token)) = handle.load().await? {
                    let (entries, opt_token) = store.scan_next(token).await?;
                    handle.update(opt_token.map(|token| (store, token))).await?;
                    Ok(Some(entries))
                } else {
                    Ok(None)
                }
            }.await;
            cb.resolve(result);
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_scan_free(handle: ScanHandle) -> ErrorCode {
    catch_err! {
        trace!("Close scan");
        RUNTIME.spawn_ok(async move {
            handle.remove().await.unwrap_or_default();
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_results_next(result: *mut FfiEntrySet, entry: *mut FfiEntry) -> bool {
    let results = mem::ManuallyDrop::new(unsafe { Box::from_raw(result) });
    if let Some(found) = results.next() {
        unsafe { *entry = found };
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn aries_store_results_free(result: *mut FfiEntrySet) {
    unsafe { Box::from_raw(result) };
}

#[no_mangle]
pub extern "C" fn aries_store_update(
    handle: StoreHandle,
    updates: *const FfiUpdateEntry,
    updates_len: usize,
    with_lock: usize,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Update store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        if updates_len == 0 || updates_len % mem::size_of::<FfiUpdateEntry>() != 0 {
            return Err(err_msg!("Invalid length for updates"));
        }
        let upd_count = updates_len / mem::size_of::<FfiUpdateEntry>();
        let updates = unsafe { slice::from_raw_parts(updates, upd_count) };
        let entries = updates.into_iter().try_fold(
            Vec::with_capacity(upd_count),
            |mut acc, entry| {
                acc.push(FfiUpdateEntry::decode(entry)?);
                KvResult::Ok(acc)
            }
        )?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        RUNTIME.spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.update(entries, if with_lock == 0 { None } else { Some(LockToken(with_lock))}).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        }.boxed());
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn aries_store_close(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Close store");
        let cb = cb.map(|cb| {
            EnsureCallback::new(move |result|
                match result {
                    Ok(_) => cb(cb_id, ErrorCode::Success),
                    Err(err) => cb(cb_id, set_last_error(Some(err))),
                }
            )
        });
        RUNTIME.spawn_ok(async move {
            let result = async {
                let store = handle.remove().await?;
                store.close().await?;
                Ok(())
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
        }.boxed());
        Ok(ErrorCode::Success)
    }
}
