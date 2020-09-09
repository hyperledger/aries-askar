use keychain_services::{
    item::GenericPassword, keychain, AccessControl, AttrAccessible, AttrKeyClass, AttrKeyType, Key,
    KeyPair, KeyPairGenerateParams, Keychain,
};

use std::path::Path;

// static SIGN_KEY_TYPES: &[&str] = &["ED25519"];

const TEST_PASSWORD: &str = "test";

/// Creates a temporary keychain in a temporary directory
struct TempKeychain {
    pub keychain: Keychain,
}

/// Create a temporary keychain we can use for testing
fn temp_keychain() -> TempKeychain {
    let keychain = Keychain::create(
        Path::new("/Users/andrew/test-keychain"),
        Some(TEST_PASSWORD),
    )
    .unwrap();

    TempKeychain { keychain }
}

struct AppleKeychainManager {}

impl AppleKeychainManager {
    pub fn create_key(&self) {
        let app_tag = "rs.keychain-services.test.integration.query";
        let label = "wallet key";

        let acl =
            AccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default())
                .unwrap();

        let kc = temp_keychain();

        let key = Key::build_random(AttrKeyType::EcSecPrimeRandom, 256)
            //.access_control(&acl)
            .application_tag(app_tag)
            .key_class(AttrKeyClass::Private)
            .label(label)
            .insert(&kc.keychain)
            .unwrap();

        let pwd = b"hel\0lo";

        let acl =
            AccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default())
                .unwrap();

        let pw = GenericPassword::builder(app_tag, label, pwd)
            .insert(&kc.keychain)
            .unwrap();

        let acl =
            AccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default())
                .unwrap();

        let generate_params = KeyPairGenerateParams::new(AttrKeyType::EcSecPrimeRandom, 256)
            .access_control(&acl)
            .application_tag(app_tag)
            .label(label);

        // let keypair = KeyPair::generate(generate_params).unwrap();
        // keypair.private_key.add_to_keychain(&kc.keychain).unwrap();

        let private_key_query = kc
            .keychain
            .query()
            .key_class(AttrKeyClass::Private)
            .key_type(AttrKeyType::EcSecPrimeRandom)
            .application_label(label.as_bytes());

        let private_key = Key::find(private_key_query).unwrap();

        let acl =
            AccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default())
                .unwrap();

        let generate_params =
            KeyPairGenerateParams::new(AttrKeyType::EcSecPrimeRandom, 256).access_control(&acl);

        let keypair = KeyPair::create(generate_params).unwrap();

        let public_key_bytes = keypair.public_key.to_external_representation().unwrap();
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn create_key() {
//         let inst = AppleKeychainManager {};

//         inst.create_key();
//     }
// }
