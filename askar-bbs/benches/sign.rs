#[macro_use]
extern crate criterion;

use askar_bbs::{
    DynGeneratorsV1, Message, Nonce, ProverMessages, SignatureMessages, VerifierMessages,
};
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
            b.iter(|| DynGeneratorsV1::new(&keypair, message_count).to_vec());
        });

        let gens = DynGeneratorsV1::new(&keypair, message_count).to_vec();
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

        let nonce = Nonce::new();
        c.bench_function(
            &format!("create signature pok for {} messages", message_count),
            |b| {
                b.iter(|| {
                    let mut prover = ProverMessages::new(&gens);
                    let hidden_count = message_count / 2;
                    for (index, msg) in messages.iter().enumerate() {
                        if index < hidden_count {
                            prover.push_hidden(*msg).unwrap();
                        } else {
                            prover.push_revealed(*msg).unwrap();
                        }
                    }
                    let ctx = prover.prepare(&sig).unwrap();
                    let challenge = ctx.create_challenge(nonce);
                    let _proof = ctx.complete(challenge).unwrap();
                });
            },
        );

        let mut prover = ProverMessages::new(&gens);
        let hidden_count = message_count / 2;
        for (index, msg) in messages.iter().enumerate() {
            if index < hidden_count {
                prover.push_hidden(*msg).unwrap();
            } else {
                prover.push_revealed(*msg).unwrap();
            }
        }
        let ctx = prover.prepare(&sig).unwrap();
        let challenge = ctx.create_challenge(nonce);
        let proof = ctx.complete(challenge).unwrap();
        c.bench_function(
            &format!("verify signature pok for {} messages", message_count),
            |b| {
                b.iter(|| {
                    let mut verify = VerifierMessages::new(&gens);
                    verify.push_hidden_count(hidden_count).unwrap();
                    for index in hidden_count..messages.len() {
                        verify.push_revealed(messages[index]).unwrap();
                    }
                    let challenge = proof.create_challenge(&verify, nonce);
                    let check = proof.verify(&keypair, &verify, challenge).unwrap();
                    assert!(check);
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
