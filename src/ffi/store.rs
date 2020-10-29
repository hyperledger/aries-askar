use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::os::raw::c_char;
use std::panic::RefUnwindSafe;
use std::ptr;
use std::slice;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_mutex::Mutex;
use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};
use indy_utils::new_handle_type;
use once_cell::sync::Lazy;
use zeroize::Zeroize;

use super::error::set_last_error;
use super::{CallbackId, EnsureCallback, ErrorCode};
use crate::error::Result as KvResult;
use crate::future::spawn_ok;
use crate::keys::{
    wrap::{generate_raw_wrap_key, WrapKeyMethod},
    KeyAlg, KeyCategory, KeyEntry,
};
use crate::store::{AnyStore, EntryLock, OpenStore, ProvisionStore, ProvisionStoreSpec, Scan};
use crate::types::{Entry, EntryTagSet, UpdateEntry};

new_handle_type!(StoreHandle, FFI_STORE_COUNTER);
new_handle_type!(ScanHandle, FFI_SCAN_COUNTER);

static FFI_STORES: Lazy<Mutex<BTreeMap<StoreHandle, AnyStore>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static FFI_SCANS: Lazy<Mutex<BTreeMap<ScanHandle, Option<Scan<Entry>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

impl StoreHandle {
    pub async fn create(value: AnyStore) -> Self {
        let handle = Self::next();
        let mut repo = FFI_STORES.lock().await;
        repo.insert(handle, value);
        handle
    }

    pub async fn load(&self) -> KvResult<AnyStore> {
        FFI_STORES
            .lock()
            .await
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn remove(&self) -> KvResult<AnyStore> {
        FFI_STORES
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }
}

impl ScanHandle {
    pub async fn create(value: Scan<Entry>) -> Self {
        let handle = Self::next();
        let mut repo = FFI_SCANS.lock().await;
        repo.insert(handle, Some(value));
        handle
    }

    pub async fn borrow(&self) -> KvResult<Scan<Entry>> {
        FFI_SCANS
            .lock()
            .await
            .get_mut(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .take()
            .ok_or_else(|| err_msg!(Busy, "Scan handle in use"))
    }

    pub async fn release(&self, value: Scan<Entry>) -> KvResult<()> {
        FFI_SCANS
            .lock()
            .await
            .get_mut(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .replace(value);
        Ok(())
    }

    pub async fn remove(&self) -> KvResult<Scan<Entry>> {
        FFI_SCANS
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

    pub fn get_result(&self) -> KvResult<(FfiEntry, bool)> {
        let el = unsafe { mem::ManuallyDrop::new(Arc::from_raw(self.0)) };
        Ok((el.entry.clone(), el.new_record))
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

pub struct FfiEntrySet {
    pos: AtomicUsize,
    rows: Vec<FfiEntry>,
}

impl FfiEntrySet {
    pub fn next(&self) -> Option<FfiEntry> {
        let pos = self.pos.fetch_add(1, Ordering::Release);
        if pos < self.rows.len() {
            Some(self.rows[pos].clone())
        } else {
            None
        }
    }
}

impl From<Entry> for FfiEntrySet {
    fn from(entry: Entry) -> Self {
        Self {
            pos: AtomicUsize::default(),
            rows: vec![FfiEntry::new(entry)],
        }
    }
}

impl From<Vec<Entry>> for FfiEntrySet {
    fn from(entries: Vec<Entry>) -> Self {
        Self {
            pos: AtomicUsize::default(),
            rows: {
                let mut acc = Vec::with_capacity(entries.len());
                acc.extend(entries.into_iter().map(FfiEntry::new));
                acc
            },
        }
    }
}

impl Drop for FfiEntrySet {
    fn drop(&mut self) {
        self.rows.drain(..).for_each(FfiEntry::destroy);
    }
}

#[repr(C)]
pub struct FfiEntry {
    category: *const c_char,
    name: *const c_char,
    value: ByteBuffer,
    tags: *const c_char,
}

unsafe impl Send for FfiEntry {}
unsafe impl Sync for FfiEntry {}

impl Clone for FfiEntry {
    fn clone(&self) -> Self {
        Self {
            category: self.category,
            name: self.name,
            value: unsafe { ptr::read(&self.value) },
            tags: self.tags,
        }
    }
}

impl FfiEntry {
    pub fn new(entry: Entry) -> Self {
        let (category, name, value, tags) = entry.into_parts();
        let category = CString::new(category).unwrap().into_raw();
        let name = CString::new(name).unwrap().into_raw();
        let value = ByteBuffer::from_vec(value);
        let tags = match tags {
            Some(tags) => {
                let tags = serde_json::to_vec(&EntryTagSet::new(tags)).unwrap();
                CString::new(tags).unwrap().into_raw()
            }
            None => ptr::null(),
        };
        Self {
            category,
            name,
            value,
            tags,
        }
    }

    pub fn decode(&self) -> KvResult<Entry> {
        let category = unsafe { FfiStr::from_raw(self.category as *const c_char) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Entry category not provided"))?;
        let name = unsafe { FfiStr::from_raw(self.name as *const c_char) }
            .into_opt_string()
            .ok_or_else(|| err_msg!("Entry name not provided"))?;
        let value = self.value.as_slice();
        let tags = if let Some(tags) =
            unsafe { FfiStr::from_raw(self.tags as *const c_char) }.as_opt_str()
        {
            Some(
                serde_json::from_str::<EntryTagSet>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_inner(),
            )
        } else {
            None
        };
        let entry = Entry {
            category,
            name,
            value: value.to_vec(),
            tags,
        };
        Ok(entry)
    }

    pub fn destroy(self) {
        unsafe {
            CString::from_raw(self.category as *mut c_char);
            CString::from_raw(self.name as *mut c_char);
            self.value.destroy_into_vec().zeroize();
            if !self.tags.is_null() {
                CString::from_raw(self.tags as *mut c_char);
            }
        }
    }
}

#[repr(C)]
pub struct FfiEntryLock {
    lock: Mutex<Option<EntryLock>>,
    entry: FfiEntry,
    new_record: bool,
}

impl Drop for FfiEntryLock {
    fn drop(&mut self) {
        self.entry.clone().destroy();
    }
}

impl RefUnwindSafe for FfiEntryLock {}

#[repr(C)]
pub struct FfiUpdateEntry {
    entry: FfiEntry,
    expire_ms: i64,
}

impl FfiUpdateEntry {
    pub fn decode(&self) -> KvResult<UpdateEntry> {
        let (category, name, value, tags) = self.entry.decode()?.into_parts();
        Ok(UpdateEntry {
            category,
            name,
            value: Some(value),
            tags,
            expire_ms: if self.expire_ms < 0 {
                None
            } else {
                Some(self.expire_ms)
            },
        })
    }
}

#[repr(C)]
pub struct FfiUnpackResult {
    unpacked: ByteBuffer,
    recipient: *const c_char,
    sender: *const c_char,
}

#[no_mangle]
pub extern "C" fn askar_store_provision(
    spec_uri: FfiStr,
    wrap_key_method: FfiStr,
    pass_key: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Provision store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No provision spec URI provided"))?;
        let wrap_key_method = match wrap_key_method.as_opt_str() {
            Some(method) => WrapKeyMethod::parse_uri(method)?,
            None => WrapKeyMethod::default()
        };
        let pass_key = zeroize::Zeroizing::new(pass_key.into_opt_string());
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => cb(cb_id, ErrorCode::Success, sid),
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let spec = ProvisionStoreSpec::create(wrap_key_method, pass_key.as_ref().map(String::as_str)).await?;
                let store = spec_uri.provision_store(spec).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_open(
    spec_uri: FfiStr,
    pass_key: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Open store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No store URI provided"))?;
        let pass_key = zeroize::Zeroizing::new(pass_key.into_opt_string());
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => cb(cb_id, ErrorCode::Success, sid),
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = spec_uri.open_store(pass_key.as_ref().map(String::as_str)).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_generate_raw_key(
    seed: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Create raw key");
        check_useful_c_ptr!(result_p);
        let seed = seed.as_opt_str().map(str::as_bytes);
        let key = generate_raw_wrap_key(seed)?;
        unsafe { *result_p = rust_string_to_c(key); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_count(
    handle: StoreHandle,
    category: FfiStr,
    tag_filter: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, count: i64)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let tag_filter = tag_filter.as_opt_str().map(serde_json::from_str).transpose().map_err(err_map!("Error parsing tag query"))?;
        let cb = EnsureCallback::new(move |result: KvResult<i64>|
            match result {
                Ok(count) => cb(cb_id, ErrorCode::Success, count),
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
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Name not provided"))?;
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
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store start");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
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
    cb_id: CallbackId,
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
    updates: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let updates = updates.as_slice();
        let updates_len = updates.len();
        if updates_len <= 0 || updates_len % mem::size_of::<FfiUpdateEntry>() != 0 {
            return Err(err_msg!("Invalid length for updates"));
        }
        let upd_count = updates_len / mem::size_of::<FfiUpdateEntry>();
        let updates = unsafe { slice::from_raw_parts(updates as *const _ as *const FfiUpdateEntry, upd_count) };
        let entries = updates.into_iter().try_fold(
            Vec::with_capacity(upd_count),
            |mut acc, entry| {
                acc.push(entry.decode()?);
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
    cb_id: CallbackId,
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
                let new_record = lock.is_new_record();
                let lock_buf = FfiEntryLock {
                    lock: Mutex::new(Some(lock)),
                    entry: FfiEntry::new(entry),
                    new_record
                };
                Ok(LockHandle::new(lock_buf))
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_lock_get_result(
    handle: LockHandle,
    entry: *mut FfiEntry,
    new_record: *mut i32,
) -> ErrorCode {
    catch_err! {
        trace!("Get store lock entry");
        check_useful_c_ptr!(entry);
        let (found, is_new) = handle.get_result()?;
        unsafe {
            *entry = found;
            *new_record = is_new as i32;
        };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_lock_update(
    handle: LockHandle,
    updates: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update store lock");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let updates = updates.as_slice();
        let updates_len = updates.len();
        if updates_len <= 0 || updates_len % mem::size_of::<FfiUpdateEntry>() != 0 {
            return Err(err_msg!("Invalid length for updates"));
        }
        let upd_count = updates_len / mem::size_of::<FfiUpdateEntry>();
        let updates = unsafe { slice::from_raw_parts(updates as *const _ as *const FfiUpdateEntry, upd_count) };
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
pub extern "C" fn askar_store_create_keypair(
    handle: StoreHandle,
    alg: FfiStr,
    metadata: FfiStr,
    seed: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: *const c_char)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Create keypair");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let alg = alg.as_opt_str().map(|alg| KeyAlg::from_str(alg).unwrap()).ok_or_else(|| err_msg!("Key algorithm not provided"))?;
        let metadata = metadata.into_opt_string();
        let seed = if seed.as_slice().len() > 0 {
            Some(seed.as_slice().to_vec())
        } else {
            None
        };

        let cb = EnsureCallback::new(move |result|
                match result {
                    Ok(ident) => {
                        cb(cb_id, ErrorCode::Success, rust_string_to_c(ident))
                    }
                    Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
                }
            );

        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let key_entry = store.create_keypair(
                        None,
                        alg,
                        metadata,
                        seed.as_ref().map(Vec::as_ref),
                        None,
                ).await?;
                Ok(key_entry.ident.clone())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_fetch_keypair(
    handle: StoreHandle,
    ident: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: *const FfiEntrySet)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch keypair");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let ident = ident.into_opt_string().ok_or_else(|| err_msg!("No key ident provided"))?;

        let cb = EnsureCallback::new(move |result|
                match result {
                    Ok(Some(entry)) => {
                        let results = Box::into_raw(Box::new(FfiEntrySet::from(entry)));
                        cb(cb_id, ErrorCode::Success, results)
                    }
                    Ok(None) => {
                        cb(cb_id, ErrorCode::Success, ptr::null())
                    }
                    Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
                }
            );

        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let key_entry = store.fetch_key(
                        None,
                        KeyCategory::KeyPair,
                        ident,
                        Default::default()
                ).await?;
                Ok(key_entry.map(export_key_entry).transpose()?)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_sign_message(
    handle: StoreHandle,
    key_ident: FfiStr,
    message: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: ByteBuffer)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Sign message");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let key_ident = key_ident.into_opt_string().ok_or_else(|| err_msg!("Key identity not provided"))?;
        // copy message so the caller can drop it
        let message = message.as_slice().to_vec();

        let cb = EnsureCallback::new(move |result|
                match result {
                    Ok(sig) => {
                        cb(cb_id, ErrorCode::Success, ByteBuffer::from_vec(sig))
                    }
                    Err(err) => cb(cb_id, set_last_error(Some(err)), ByteBuffer::default()),
                }
            );

        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let signature = store.sign_message(
                        None,
                        key_ident,
                        message,
                ).await?;
                Ok(signature)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_verify_signature(
    handle: StoreHandle,
    signer_vk: FfiStr,
    message: ByteBuffer,
    signature: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, verify: i64)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Verify signature");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let signer_vk = signer_vk.into_opt_string().ok_or_else(|| err_msg!("Signer verkey not provided"))?;
        // copy inputs so the caller can drop them
        let message = message.as_slice().to_vec();
        let signature = signature.as_slice().to_vec();

        let cb = EnsureCallback::new(move |result|
                match result {
                    Ok(verify) => {
                        cb(cb_id, ErrorCode::Success, verify as i64)
                    }
                    Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
                }
            );

        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let verify = store.verify_signature(
                        signer_vk,
                        message,
                        signature
                ).await?;
                Ok(verify)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_pack_message(
    handle: StoreHandle,
    recipient_vks: FfiStr,
    from_key_ident: FfiStr,
    message: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, packed: ByteBuffer)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Pack message");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let mut recips = recipient_vks.as_opt_str().ok_or_else(|| err_msg!("Recipient verkey(s) not provided"))?;
        let mut recipient_vks = vec![];
        loop {
            if let Some(pos) = recips.find(",") {
                recipient_vks.push((&recips[..pos]).to_string());
                recips = &recips[(pos+1)..];
            } else {
                if !recips.is_empty() {
                    recipient_vks.push(recips.to_string());
                }
                break;
            }
        }
        let from_key_ident = from_key_ident.into_opt_string();
        let message = message.as_slice().to_vec();

        let cb = EnsureCallback::new(move |result|
                match result {
                    Ok(packed) => {
                        cb(cb_id, ErrorCode::Success, ByteBuffer::from_vec(packed))
                    }
                    Err(err) => cb(cb_id, set_last_error(Some(err)), ByteBuffer::default()),
                }
            );

        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let packed = store.pack_message(
                    None,
                        recipient_vks,
                        from_key_ident,
                        message
                ).await?;
                Ok(packed)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_unpack_message(
    handle: StoreHandle,
    message: ByteBuffer,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, result: FfiUnpackResult)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Unpack message");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let message = message.as_slice().to_vec();

        let cb = EnsureCallback::new(move |result: KvResult<(Vec<u8>, String, Option<String>)>|
                match result {
                    Ok((unpacked, recipient, sender)) => {
                        cb(cb_id, ErrorCode::Success, FfiUnpackResult {
                            unpacked: ByteBuffer::from_vec(unpacked), recipient: rust_string_to_c(recipient), sender: sender.map(rust_string_to_c).unwrap_or(ptr::null_mut())}
                        )
                    }
                    Err(err) => {
                        eprintln!("err: {:?}", &err);
                        cb(cb_id, set_last_error(Some(err)), FfiUnpackResult { unpacked: ByteBuffer::default(), recipient: ptr::null(), sender: ptr::null() })
                    }
                }
            );

        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let (unpacked, recipient, sender) = store.unpack_message(
                    None,
                    message
                ).await?;
                Ok((unpacked, recipient.to_string(), sender.map(|s| s.to_string())))
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_close(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
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

fn export_key_entry(key_entry: KeyEntry) -> KvResult<Entry> {
    let (category, name, mut params, tags) = key_entry.into_parts();
    let value = serde_json::to_string(&params)
        .map_err(err_map!("Error converting key entry to JSON"))?
        .into_bytes();
    params.zeroize();
    Ok(Entry {
        category: category.to_string(),
        name,
        value,
        tags,
    })
}
