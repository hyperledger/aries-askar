use std::collections::BTreeMap;

use async_mutex::Mutex;
use async_resource::Executor;
use ffi_support::FfiStr;
use futures_util::future::FutureExt;
use indy_utils::new_handle_type;
use once_cell::sync::Lazy;

use super::error::set_last_error;
use super::{CallbackId, EnsureCallback, ErrorCode, RUNTIME};
use crate::keys::wrap::WrapKeyMethod;
use crate::store::{KvProvisionSpec, KvProvisionStore, KvStore};

new_handle_type!(StoreHandle, FFI_STORE_COUNTER);

static STORES: Lazy<Mutex<BTreeMap<StoreHandle, Box<dyn KvStore + Send>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

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
