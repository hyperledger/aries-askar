# Askar Storage

Each database backend will have subtly different schemas, so this document describes only the general principles of the backing storage.

Encryption and decryption are performed by the Askar library, not by any database APIs, such that security issues in the database will not jeopardize any sensitive data.

## Configuration

Each database contains a key-value table for configuration. There are currently three entries:

- The `default_profile` entry contains the name of the default profile to open. Alternative profile names can be specified when connecting to an existing store.

- The `version` entry defines the version of the database schema in order to facilitate upgrades.

- The `key` entry contains metadata about the store key. This may be used as a hint for deriving the key used to decrypt each profile key. Three types of store keys are currently supported:

  - `raw` indicates that the store key is a random byte string provided when the store was provisioned. The key itself is not stored in the database.

  - `kdf:argon2i` indicates that the store key is derived from a passphrase using the Argon2i key derivation function. This method is CPU intensive and protects against brute force attempts at guessing the passphrase. The key metadata includes a hex-encoded random salt value used in the key derivation, for example `kdf:argon2i:13:mod?salt=a553cfb9c558b5c11c78efcfa06f3e29`.

  - `none` indicates that no store key is used. This key type should be used only for testing and inspecting profile contents without encryption.

  Each store provides a method for rekeying which re-encrypts the profile keys under the new key before updating the store key metadata.

## Profiles

The profiles table contains details of the profiles created within this store, which can be used to create separation between multiple sets of data. Each store is created with a single default profile.

Each profile has a name, an ID, and a profile key. The profile key is encrypted using the store key, and is used to encrypt any related items.

### Profile key

Profile keys are encoded in CBOR and contain a set of keys used for encrypting items in the store. There are four ChaCha20Poly1305 keys (category key, name key, tag name key, tag value key) and two HMAC keys (items HMAC key, tags HMAC key).

## Items

Items are stored with the following properties:

- ID: a database-specific ID used for referencing
- Profile ID: the identifier for the associated profile
- Kind: one of KMS (1) or Item (2), used to distinguish key material and other KMS data from user-created item records
- Category: an encrypted UTF-8 string value
- Name: an encrypted UTF-8 string value
- Value: an encrypted UTF-8 string value
- Expiry Time: a datetime value used to filter expired records

### Item tags

Each item may have a set of encrypted or unencrypted tags associated with it.

Tags consist of a name and value, represented as encrypted UTF-8 string values.

## Item encryption

The item encryption process is as follows:

For each of the item category and name, calculate the SHA-256 HMAC value of the plaintext using the item HMAC key. Take the first 12 bytes as the nonce value, and encrypt the value using the associated ChaCha20Poly1305 key (category key or name key). This produces a consistent encrypted value (nonce + ciphertext + 16-byte AEAD tag), allowing filtering for known category and name values.

For encrypting the item value, first the value key is derived. Using the item HMAC key, calculate `HMAC-SHA-256(u_int32(len(category)) || category || u_int32(len(name)) || name)`, producing 32 bytes of output. Generate a random nonce value, and using the HMAC output value as a ChaCha20Poly1305 key, encrypt the value, prepending the random nonce.

Finally, the item tags are encrypted. All tag names are encrypted as searchable values in the same manner and the item category and name, using the tag name key and tag HMAC key. For encrypted tags, the value is encrypted in the same manner, using the tag value key and tag HMAC key.
