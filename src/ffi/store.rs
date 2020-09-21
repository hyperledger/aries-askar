use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::os::raw::c_char;
use std::panic::RefUnwindSafe;
use std::ptr;
use std::slice;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_mutex::Mutex;
use ffi_support::{rust_string_to_c, FfiStr};
use indy_utils::new_handle_type;
use once_cell::sync::Lazy;
use zeroize::Zeroize;

use super::error::set_last_error;
use super::{CallbackId, EnsureCallback, ErrorCode};
use crate::error::Result as KvResult;
use crate::future::spawn_ok;
use crate::keys::wrap::{generate_raw_wrap_key, WrapKeyMethod};
use crate::store::{ArcStore, EntryLock, EntryScan, ProvisionStore, ProvisionStoreSpec};
use crate::types::{Entry, EntryTag, UpdateEntry};

new_handle_type!(StoreHandle, FFI_STORE_COUNTER);
new_handle_type!(ScanHandle, FFI_SCAN_COUNTER);

static STORES: Lazy<Mutex<BTreeMap<StoreHandle, ArcStore>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static SCANS: Lazy<Mutex<BTreeMap<ScanHandle, Option<EntryScan>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

impl StoreHandle {
    pub async fn create(value: ArcStore) -> Self {
        let handle = Self::next();
        let mut repo = STORES.lock().await;
        repo.insert(handle, value);
        handle
    }

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
    pub async fn create(value: EntryScan) -> Self {
        let handle = Self::next();
        let mut repo = SCANS.lock().await;
        repo.insert(handle, Some(value));
        handle
    }

    pub async fn borrow(&self) -> KvResult<EntryScan> {
        SCANS
            .lock()
            .await
            .get_mut(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .take()
            .ok_or_else(|| err_msg!(Busy, "Scan handle in use"))
    }

    pub async fn release(&self, value: EntryScan) -> KvResult<()> {
        SCANS
            .lock()
            .await
            .get_mut(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .replace(value);
        Ok(())
    }

    pub async fn remove(&self) -> KvResult<EntryScan> {
        SCANS
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .ok_or_else(|| err_msg!(Busy, "Scan handle in use"))
    }
}

#[repr(transparent)]
pub struct LockHandle(*const FfiEntryLock);

impl LockHandle {
    pub fn new(lock_buf: FfiEntryLock) -> Self {
        Self(Arc::into_raw(Arc::new(lock_buf)))
    }

    pub fn null() -> Self {
        Self(ptr::null_mut())
    }

    pub fn get_entry(&self) -> KvResult<FfiEntry> {
        let el = unsafe { mem::ManuallyDrop::new(Arc::from_raw(self.0)) };
        Ok(el.entry.get_ref())
    }

    pub async fn take(&self) -> KvResult<EntryLock> {
        let el = Arc::clone(&*unsafe { mem::ManuallyDrop::new(Arc::from_raw(self.0)) });
        let result = el
            .lock
            .lock()
            .await
            .take()
            .ok_or_else(|| err_msg!(Busy, "Lock handle in use"))?;
        Ok(result)
    }

    pub fn free(self) {
        unsafe {
            Arc::from_raw(self.0);
        }
    }
}

unsafe impl Send for LockHandle {}
unsafe impl Sync for LockHandle {}

struct FfiTagBuf {
    name: Vec<u8>,
    value: Vec<u8>,
}

#[repr(C)]
pub struct FfiTag {
    name: *const u8,
    value: *const u8,
}

impl FfiTag {
    pub fn decode(&self) -> KvResult<EntryTag> {
        let name = unsafe { FfiStr::from_raw(self.name as *const c_char) }
            .as_opt_str()
            .ok_or_else(|| err_msg!("Invalid tag name"))?;
        let value = unsafe { FfiStr::from_raw(self.value as *const c_char) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Invalid tag value"))?;
        Ok(if name.chars().next() == Some('~') {
            EntryTag::Plaintext(name[1..].to_owned(), value)
        } else {
            EntryTag::Encrypted(name.to_owned(), value)
        })
    }
}

struct FfiEntryBuf {
    category: Vec<u8>,
    name: Vec<u8>,
    value: Vec<u8>,
    #[allow(unused)] // referenced by tags_ref
    tags: Vec<FfiTagBuf>,
    tags_ref: Vec<FfiTag>,
}

unsafe impl Send for FfiEntryBuf {}
unsafe impl Sync for FfiEntryBuf {}

impl FfiEntryBuf {
    pub fn get_ref(&self) -> FfiEntry {
        FfiEntry {
            category: self.category.as_ptr(),
            name: self.name.as_ptr(),
            value: self.value.as_ptr(),
            value_len: self.value.len(),
            tags: self.tags_ref.as_ptr(),
            tags_len: self.tags_ref.len() * mem::size_of::<FfiTag>(),
        }
    }
}

impl From<Entry> for FfiEntryBuf {
    fn from(entry: Entry) -> Self {
        let category = make_c_string(&entry.category);
        let name = make_c_string(&entry.name);
        let tags_count = entry.tags.as_ref().map(Vec::len).unwrap_or_default();
        let mut tags = Vec::with_capacity(tags_count);
        let mut tags_ref = Vec::with_capacity(tags_count);
        let mut tags_idx = 0;
        if let Some(entry_tags) = entry.tags.as_ref() {
            for tag in entry_tags {
                let (name, value) = match tag {
                    EntryTag::Encrypted(tag_name, tag_value) => {
                        (make_c_string(tag_name), make_c_string(tag_value))
                    }
                    EntryTag::Plaintext(tag_name, tag_value) => {
                        let mut name = String::with_capacity(tag_name.len() + 1);
                        name.push('~');
                        name.push_str(&tag_name);
                        (
                            CString::new(name.into_bytes())
                                .unwrap()
                                .into_bytes_with_nul(),
                            make_c_string(tag_value),
                        )
                    }
                };
                tags.push(FfiTagBuf { name, value });
                tags_ref.push(FfiTag {
                    name: tags[tags_idx].name.as_ptr(),
                    value: tags[tags_idx].value.as_ptr(),
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

impl Zeroize for FfiEntryBuf {
    fn zeroize(&mut self) {
        self.value.zeroize();
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
            Some(row.get_ref())
        } else {
            None
        }
    }
}

impl From<Entry> for FfiEntrySet {
    fn from(entry: Entry) -> Self {
        Self {
            pos: AtomicUsize::default(),
            rows: vec![entry.into()],
        }
    }
}

impl From<Vec<Entry>> for FfiEntrySet {
    fn from(entries: Vec<Entry>) -> Self {
        Self {
            pos: AtomicUsize::default(),
            rows: {
                let mut acc = Vec::with_capacity(entries.len());
                acc.extend(entries.into_iter().map(Into::into));
                acc
            },
        }
    }
}

impl Drop for FfiEntrySet {
    fn drop(&mut self) {
        self.rows.zeroize();
    }
}

#[repr(C)]
pub struct FfiEntry {
    category: *const u8,
    name: *const u8,
    value: *const u8,
    value_len: usize,
    tags: *const FfiTag,
    tags_len: usize,
}

impl FfiEntry {
    pub fn decode(&self) -> KvResult<Entry> {
        let category = unsafe { FfiStr::from_raw(self.category as *const c_char) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Invalid entry category"))?;
        let name = unsafe { FfiStr::from_raw(self.name as *const c_char) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Invalid entry name"))?;
        let value = unsafe { slice::from_raw_parts(self.value, self.value_len) };
        if self.tags_len % mem::size_of::<FfiTag>() != 0 {
            return Err(err_msg!("Invalid length for entry tags"));
        }
        let tags_count = self.tags_len / mem::size_of::<FfiTag>();
        let tags = unsafe { slice::from_raw_parts(self.tags, tags_count) };
        let entry = Entry {
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
pub struct FfiEntryLock {
    lock: Mutex<Option<EntryLock>>,
    entry: FfiEntryBuf,
}

impl RefUnwindSafe for FfiEntryLock {}

#[repr(C)]
pub struct FfiUpdateEntry {
    entry: FfiEntry,
    expire_ms: i64,
}

impl FfiUpdateEntry {
    pub fn decode(&self) -> KvResult<UpdateEntry> {
        let entry = self.entry.decode()?;
        Ok(UpdateEntry {
            entry,
            expire_ms: if self.expire_ms < 0 {
                None
            } else {
                Some(self.expire_ms)
            },
        })
    }
}

#[no_mangle]
pub extern "C" fn askar_store_provision(
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
        spawn_ok(async move {
            let result = async {
                let spec = ProvisionStoreSpec::create(wrap_key_method, pass_key).await?;
                let store = spec_uri.provision_store(spec).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_generate_raw_key(result_p: *mut *const c_char) -> ErrorCode {
    catch_err! {
        trace!("Create raw key");
        check_useful_c_ptr!(result_p);
        let key = generate_raw_wrap_key()?;
        unsafe { *result_p = rust_string_to_c(key); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_count(
    handle: StoreHandle,
    category: FfiStr,
    tag_filter: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, count: usize)>,
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
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.count(None, category, tag_filter).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_fetch(
    handle: StoreHandle,
    category: FfiStr,
    name: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: *const FfiEntrySet)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Invalid category"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Invalid name"))?;
        let cb = EnsureCallback::new(move |result: KvResult<Option<Entry>>|
            match result {
                Ok(Some(entry)) => {
                    let results = Box::into_raw(Box::new(FfiEntrySet::from(entry)));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, ptr::null()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.fetch(None, category, name, Default::default()).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_scan_start(
    handle: StoreHandle,
    category: FfiStr,
    tag_filter: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: ScanHandle)>,
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
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let scan = store.scan(None, category, Default::default(), tag_filter, None, None).await?;
                Ok(ScanHandle::create(scan).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_scan_next(
    handle: ScanHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: *const FfiEntrySet)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store next");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: KvResult<Option<Vec<Entry>>>|
            match result {
                Ok(Some(entries)) => {
                    let results = Box::into_raw(Box::new(FfiEntrySet::from(entries)));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, ptr::null()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut scan = handle.borrow().await?;
                let entries = scan.fetch_next().await?;
                handle.release(scan).await?;
                Ok(entries)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_scan_free(handle: ScanHandle) -> ErrorCode {
    catch_err! {
        trace!("Close scan");
        spawn_ok(async move {
            handle.remove().await.ok();
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_results_next(
    result: *mut FfiEntrySet,
    entry: *mut FfiEntry,
    found: *mut bool,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(entry);
        check_useful_c_ptr!(found);
        let results = mem::ManuallyDrop::new(unsafe { Box::from_raw(result) });
        if let Some(next) = results.next() {
            unsafe { *entry = next };
            unsafe { *found = true };
        } else {
            unsafe { *found = false };
        }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_results_free(result: *mut FfiEntrySet) {
    unsafe { Box::from_raw(result) };
}

#[no_mangle]
pub extern "C" fn askar_store_update(
    handle: StoreHandle,
    updates: *const FfiUpdateEntry,
    updates_len: usize,
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
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.update(None, entries).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_create_lock(
    handle: StoreHandle,
    lock_info: *const FfiUpdateEntry,
    acquire_timeout_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, result: LockHandle)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Store create lock");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let update = unsafe { &*lock_info as &FfiUpdateEntry }.decode()?;
        let timeout = if acquire_timeout_ms == -1 { None } else { Some(acquire_timeout_ms)};
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(lock) => cb(cb_id, ErrorCode::Success, lock),
                Err(err) => cb(cb_id, set_last_error(Some(err)), LockHandle::null()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let (entry, lock) = store.create_lock(None, update, timeout).await?;
                let lock_buf = FfiEntryLock {
                    lock: Mutex::new(Some(lock)),
                    entry: entry.into(),
                };
                Ok(LockHandle::new(lock_buf))
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_lock_get_entry(
    handle: LockHandle,
    entry: *mut FfiEntry,
) -> ErrorCode {
    catch_err! {
        trace!("Get store lock entry");
        check_useful_c_ptr!(entry);
        let found = handle.get_entry()?;
        unsafe { *entry = found };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_lock_update(
    handle: LockHandle,
    updates: *const FfiUpdateEntry,
    updates_len: usize,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: usize,
) -> ErrorCode {
    catch_err! {
        trace!("Update store lock");
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
        spawn_ok(async move {
            let result = async {
                let lock = handle.take().await?;
                lock.update(entries).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_lock_free(handle: LockHandle) {
    handle.free()
}

#[no_mangle]
pub extern "C" fn askar_store_close(
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
        spawn_ok(async move {
            let result = async {
                let store = handle.remove().await?;
                store.close().await?;
                Ok(())
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
        });
        Ok(ErrorCode::Success)
    }
}

#[inline]
// note: using a Vec to allow in-place zeroize, which CString does not
fn make_c_string(value: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.len() + 1);
    buf.extend_from_slice(value.as_bytes());
    CString::new(buf).unwrap().into_bytes_with_nul()
}
