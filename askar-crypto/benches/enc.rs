#[macro_use]
extern crate criterion;

#[macro_use]
extern crate hex_literal;

use askar_crypto::{
    alg::chacha20::{Chacha20Key, C20P},
    buffer::{SecretBytes, WriteBuffer, Writer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    repr::KeySecretBytes,
};

use criterion::{black_box, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    {
        let message = b"test message for encrypting";

        let key = &hex!("451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5ee");

        c.bench_function(&format!("chacha20-poly1305 encrypt"), move |b| {
            b.iter(|| {
                let key = Chacha20Key::<C20P>::from_secret_bytes(&key[..]).unwrap();
                let mut buffer = [0u8; 255];
                buffer[0..message.len()].copy_from_slice(black_box(&message[..]));
                let nonce = Chacha20Key::<C20P>::random_nonce();
                let mut writer = Writer::from_slice_position(&mut buffer, message.len());
                key.encrypt_in_place(&mut writer, &nonce, &[]).unwrap();
            })
        });
        c.bench_function(&format!("chacha20-poly1305 encrypt alloc"), move |b| {
            b.iter(|| {
                let key = Chacha20Key::<C20P>::from_secret_bytes(&key[..]).unwrap();
                let mut buffer = SecretBytes::with_capacity(255);
                buffer.buffer_write(black_box(&message[..])).unwrap();
                let nonce = Chacha20Key::<C20P>::random_nonce();
                key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
