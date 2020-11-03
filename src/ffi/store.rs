use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::os::raw::c_char;
use std::ptr;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_mutex::{Mutex, MutexGuardArc};
use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};
use indy_utils::new_handle_type;
use once_cell::sync::Lazy;
use zeroize::Zeroize;

use super::error::set_last_error;
use super::{CallbackId, EnsureCallback, ErrorCode};
use crate::any::{AnySession, AnyStore};
use crate::error::Result as KvResult;
use crate::future::spawn_ok;
use crate::keys::{wrap::WrapKeyMethod, KeyAlg, KeyCategory, KeyEntry};
use crate::store::{OpenStore, ProvisionStore, ProvisionStoreSpec, Scan};
use crate::types::{Entry, EntryOperation, EntryTagSet};

new_handle_type!(StoreHandle, FFI_STORE_COUNTER);
new_handle_type!(SessionHandle, FFI_SESSION_COUNTER);
new_handle_type!(ScanHandle, FFI_SCAN_COUNTER);

static FFI_STORES: Lazy<Mutex<BTreeMap<StoreHandle, Arc<AnyStore>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static FFI_SESSIONS: Lazy<Mutex<BTreeMap<SessionHandle, Arc<Mutex<AnySession>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static FFI_SCANS: Lazy<Mutex<BTreeMap<ScanHandle, Option<Scan<Entry>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

impl StoreHandle {
    pub async fn create(value: AnyStore) -> Self {
        let handle = Self::next();
        let mut repo = FFI_STORES.lock().await;
        repo.insert(handle, Arc::new(value));
        handle
    }

    pub async fn load(&self) -> KvResult<Arc<AnyStore>> {
        FFI_STORES
            .lock()
            .await
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn remove(&self) -> KvResult<Arc<AnyStore>> {
        FFI_STORES
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }
}

impl SessionHandle {
    pub async fn create(value: AnySession) -> Self {
        let handle = Self::next();
        let mut repo = FFI_SESSIONS.lock().await;
        repo.insert(handle, Arc::new(Mutex::new(value)));
        handle
    }

    pub async fn load(&self) -> KvResult<MutexGuardArc<AnySession>> {
        Ok(Mutex::lock_arc(
            FFI_SESSIONS
                .lock()
                .await
                .get(self)
                .ok_or_else(|| err_msg!("Invalid session handle"))?,
        )
        .await)
    }

    pub async fn remove(&self) -> KvResult<Arc<Mutex<AnySession>>> {
        FFI_SESSIONS
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid session handle"))
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
                store.arc_close().await
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_start(
    handle: StoreHandle,
    profile: FfiStr,
    category: FfiStr,
    tag_filter: FfiStr,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: ScanHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store start");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string();
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
                let scan = store.scan(profile, category, tag_filter, None, None).await?;
                Ok(ScanHandle::create(scan).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_next(
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
pub extern "C" fn askar_scan_free(handle: ScanHandle) -> ErrorCode {
    catch_err! {
        trace!("Close scan");
        spawn_ok(async move {
            handle.remove().await.ok();
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_set_next(
    result: *mut FfiEntrySet,
    entry: *mut FfiEntry,
    found: *mut i8,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(entry);
        check_useful_c_ptr!(found);
        let results = mem::ManuallyDrop::new(unsafe { Box::from_raw(result) });
        if let Some(next) = results.next() {
            unsafe { *entry = next };
            unsafe { *found = 1 };
        } else {
            unsafe { *found = 0 };
        }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_set_free(result: *mut FfiEntrySet) {
    unsafe { Box::from_raw(result) };
}

#[no_mangle]
pub extern "C" fn askar_session_start(
    handle: StoreHandle,
    profile: FfiStr,
    as_transaction: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: SessionHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Session start");
        let profile = profile.into_opt_string();
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: KvResult<SessionHandle>|
            match result {
                Ok(handle) => cb(cb_id, ErrorCode::Success, handle),
                Err(err) => cb(cb_id, set_last_error(Some(err)), SessionHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let session = if as_transaction == 0 {
                    store.session(profile).await?
                } else {
                    store.transaction(profile).await?
                };
                Ok(SessionHandle::create(session).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_count(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                session.count(&category, tag_filter).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                session.fetch(&category, &name).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_update(
    handle: SessionHandle,
    operation: i8,
    category: FfiStr,
    name: FfiStr,
    value: ByteBuffer,
    tags: FfiStr,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let operation = match operation {
            0 => EntryOperation::Insert,
            1 => EntryOperation::Replace,
            2 => EntryOperation::Remove,
            _ => return Err(err_msg!("Invalid update operation"))
        };
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Entry category not provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Entry name not provided"))?;
        let value = value.as_slice().to_vec();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_inner(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.update(operation, &category, &name, Some(value.as_slice()), tags.as_ref().map(Vec::as_slice), expiry_ms).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_create_keypair(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                let key_entry = session.create_keypair(
                    alg,
                    metadata.as_ref().map(String::as_str),
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
pub extern "C" fn askar_session_fetch_keypair(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                let key_entry = session.fetch_key(
                    KeyCategory::KeyPair,
                    &ident,
                ).await?;
                Ok(key_entry.map(export_key_entry).transpose()?)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_sign_message(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                let signature = session.sign_message(
                    &key_ident,
                    &message,
                ).await?;
                Ok(signature)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_pack_message(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                let packed = session.pack_message(
                    recipient_vks.iter().map(String::as_str),
                    from_key_ident.as_ref().map(String::as_str),
                    &message
                ).await?;
                Ok(packed)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_unpack_message(
    handle: SessionHandle,
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
                let mut session = handle.load().await?;
                let (unpacked, recipient, sender) = session.unpack_message(
                    &message
                ).await?;
                Ok((unpacked, recipient.to_string(), sender.map(|s| s.to_string())))
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_close(
    handle: SessionHandle,
    commit: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Close session");
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
                let session = handle.remove().await?;
                if let Ok(session) = Arc::try_unwrap(session) {
                    if commit == 0 {
                        // not necessary - rollback is automatic for txn,
                        // and for regular session there is no action to perform
                        // session.into_inner().rollback().await?;
                    } else {
                        session.into_inner().commit().await?;
                    }
                    Ok(())
                } else {
                    Err(err_msg!("Error closing session: has outstanding references"))
                }
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
