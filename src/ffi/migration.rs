use ffi_support::FfiStr;

use crate::storage::future::spawn_ok;
use crate::storage::migration::IndySdkToAriesAskarMigration;

use super::{
    error::{store_error, ErrorHandle},
    CallbackId, EnsureCallback,
};

/// Migrate an sqlite wallet from an indy-sdk structure to an aries-askar structure.
/// It is important to note that this does not do any post-processing. If the record values, tags,
/// names, etc. have changed, it must be processed manually afterwards. This script does the following:
///
/// 1. Create and rename the required tables
/// 2. Fetch the indy key from the wallet
/// 3. Create a new configuration
/// 4. Initialize a profile
/// 5. Update the items from the indy-sdk
/// 6. Clean up (drop tables and add a version of "1")
#[no_mangle]
pub extern "C" fn askar_migrate_indy_sdk(
    spec_uri: FfiStr<'_>,
    wallet_name: FfiStr<'_>,
    wallet_key: FfiStr<'_>,
    kdf_level: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorHandle)>,
    cb_id: CallbackId,
) -> ErrorHandle {
    catch_err!(
        trace!("Migrate sqlite wallet from indy-sdk structure to aries-askar");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No provision spec URI provided"))?;
        let wallet_name = wallet_name.into_opt_string().ok_or_else(|| err_msg!("No wallet name provided"))?;
        let wallet_key = wallet_key.into_opt_string().ok_or_else(|| err_msg!("No wallet key provided"))?;
        let kdf_level = kdf_level.into_opt_string().ok_or_else(|| err_msg!("No KDF level provided"))?;

        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorHandle::OK),
                Err(err) => cb(cb_id, store_error(err)),
        });

        spawn_ok(async move {
            let result = async {
                let migrator = IndySdkToAriesAskarMigration::connect(&spec_uri, &wallet_name, &wallet_key, &kdf_level).await?;
                migrator.migrate().await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorHandle::OK)
    )
}
