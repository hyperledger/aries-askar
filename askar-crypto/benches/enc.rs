#[macro_use]
extern crate criterion;

use askar_crypto::{
    alg::{
        aes::{A128CbcHs256, A128Gcm, AesKey},
        chacha20::{Chacha20Key, C20P},
        AnyKey, AnyKeyCreate, Chacha20Types, KeyAlg,
    },
    buffer::{SecretBytes, WriteBuffer, Writer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    random::fill_random,
    repr::KeyGen,
};

use criterion::{black_box, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    {
        let message = b"test message for encrypting";

        c.bench_function(&format!("aes128gcm encrypt"), move |b| {
            let key = AesKey::<A128Gcm>::generate().unwrap();
            let nonce = AesKey::<A128Gcm>::random_nonce();
            b.iter(|| {
                let mut buffer = [0u8; 255];
                buffer[0..message.len()].copy_from_slice(black_box(&message[..]));
                let mut writer = Writer::from_slice_position(&mut buffer, message.len());
                key.encrypt_in_place(&mut writer, &nonce, &[]).unwrap();
            })
        });
        c.bench_function(&format!("aes128cbc-hs256 encrypt"), move |b| {
            let key = AesKey::<A128CbcHs256>::generate().unwrap();
            let nonce = AesKey::<A128CbcHs256>::random_nonce();
            b.iter(|| {
                let mut buffer = [0u8; 255];
                buffer[0..message.len()].copy_from_slice(black_box(&message[..]));
                let mut writer = Writer::from_slice_position(&mut buffer, message.len());
                key.encrypt_in_place(&mut writer, &nonce, &[]).unwrap();
            })
        });

        c.bench_function(&format!("chacha20-poly1305 encrypt"), move |b| {
            let key = Chacha20Key::<C20P>::generate().unwrap();
            let nonce = Chacha20Key::<C20P>::random_nonce();
            b.iter(|| {
                let mut buffer = [0u8; 255];
                buffer[0..message.len()].copy_from_slice(black_box(&message[..]));
                let mut writer = Writer::from_slice_position(&mut buffer, message.len());
                key.encrypt_in_place(&mut writer, &nonce, &[]).unwrap();
            })
        });

        // test overhead of SecretBytes
        c.bench_function(&format!("chacha20-poly1305 encrypt alloc"), move |b| {
            let key = Chacha20Key::<C20P>::generate().unwrap();
            let nonce = Chacha20Key::<C20P>::random_nonce();
            b.iter(|| {
                let mut buffer = SecretBytes::with_capacity(255);
                buffer.buffer_write(black_box(&message[..])).unwrap();
                key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            })
        });

        // test overhead of AnyKey
        c.bench_function(&format!("chacha20-poly1305 encrypt as any"), move |b| {
            let key = Box::<AnyKey>::generate(KeyAlg::Chacha20(Chacha20Types::C20P)).unwrap();
            let mut nonce = [0u8; 255];
            let nonce_len = key.aead_params().nonce_length;
            fill_random(&mut nonce[..nonce_len]);
            b.iter(|| {
                let mut buffer = [0u8; 255];
                buffer[0..message.len()].copy_from_slice(black_box(&message[..]));
                let mut writer = Writer::from_slice_position(&mut buffer, message.len());
                key.encrypt_in_place(&mut writer, &nonce[..nonce_len], &[])
                    .unwrap();
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
