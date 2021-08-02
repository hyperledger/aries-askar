#[macro_use]
extern crate criterion;

use askar_bbs::{DynGeneratorsV1, Message, SignatureMessages, VecGenerators};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::KeyGen,
};
use rand::{rngs::OsRng, RngCore};

use criterion::Criterion;

fn criterion_benchmark(c: &mut Criterion) {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();

    for message_count in vec![5, 25, 125] {
        c.bench_function(&format!("keygen for {} messages", message_count), |b| {
            b.iter(|| VecGenerators::from(&DynGeneratorsV1::new(&keypair, message_count)));
        });

        let gens = VecGenerators::from(&DynGeneratorsV1::new(&keypair, message_count));
        let messages: Vec<Message> = (0..message_count)
            .map(|_| Message::from(OsRng.next_u64()))
            .collect();
        c.bench_function(&format!("sign for {} messages", message_count), |b| {
            b.iter(|| {
                let mut signer = SignatureMessages::new(&gens);
                signer.append(messages.iter().copied()).unwrap();
                signer.sign(&keypair).unwrap();
            });
        });

        let mut signer = SignatureMessages::new(&gens);
        signer.append(messages.iter().copied()).unwrap();
        let sig = signer.sign(&keypair).unwrap();
        c.bench_function(&format!("verify for {} messages", message_count), |b| {
            b.iter(|| {
                let mut verify = SignatureMessages::new(&gens);
                verify.append(messages.iter().copied()).unwrap();
                assert!(verify.verify_signature(&keypair, &sig).unwrap());
            });
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
