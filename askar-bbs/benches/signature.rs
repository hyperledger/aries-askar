#[macro_use]
extern crate criterion;

use askar_bbs::{DynGenerators, Message, SignatureMessages};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::KeyGen,
};
use rand::{rngs::OsRng, RngCore};

use criterion::Criterion;

fn criterion_benchmark(c: &mut Criterion) {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();

    for message_count in vec![5, 25, 125] {
        let gens = DynGenerators::new(&keypair, message_count)
            .to_vec()
            .unwrap();
        let messages: Vec<Message> = (0..message_count)
            .map(|_| Message::from(OsRng.next_u64()))
            .collect();

        c.bench_function(&format!("sign for {} messages", message_count), |b| {
            b.iter(|| {
                let mut signer = SignatureMessages::signer(&gens, &keypair);
                signer.append(messages.iter().copied()).unwrap();
                signer.sign().unwrap();
            });
        });

        let mut signer = SignatureMessages::signer(&gens, &keypair);
        signer.append(messages.iter().copied()).unwrap();
        let sig = signer.sign().unwrap();
        c.bench_function(&format!("verify for {} messages", message_count), |b| {
            b.iter(|| {
                let mut verify = SignatureMessages::verifier(&gens, &keypair);
                verify.append(messages.iter().copied()).unwrap();
                verify.verify_signature(&sig).unwrap();
            });
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
