#[macro_use]
extern crate criterion;

use askar_bbs::{
    CommitmentBuilder, CreateChallenge, DynGeneratorsV1, Message, Nonce, SignatureMessages,
    SignatureProver,
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
            b.iter(|| {
                DynGeneratorsV1::new(&keypair, message_count)
                    .to_vec()
                    .unwrap()
            });
        });

        let gens = DynGeneratorsV1::new(&keypair, message_count)
            .to_vec()
            .unwrap();

        // FIXME move to separate blind signature benchmarks
        if message_count == 5 {
            c.bench_function(&format!("create commitment"), |b| {
                b.iter(|| {
                    let mut committer = CommitmentBuilder::new(&gens);
                    committer.commit(0, Message::from(0)).unwrap();
                    let (_challenge, _blind, _commit, _proof) =
                        committer.complete(Nonce::new()).unwrap();
                });
            });
        }

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
                assert!(verify.verify_signature(&sig).unwrap());
            });
        });

        let nonce = Nonce::new();
        c.bench_function(
            &format!("create signature pok for {} messages", message_count),
            |b| {
                b.iter(|| {
                    let mut prover = SignatureProver::new(&gens, &sig);
                    let hidden_count = message_count / 2;
                    for (index, msg) in messages.iter().enumerate() {
                        if index < hidden_count {
                            prover.push_hidden(*msg).unwrap();
                        } else {
                            prover.push_revealed(*msg).unwrap();
                        }
                    }
                    let ctx = prover.prepare().unwrap();
                    let challenge = ctx.create_challenge(nonce);
                    let _proof = ctx.complete(challenge).unwrap();
                });
            },
        );

        let mut prover = SignatureProver::new(&gens, &sig);
        let hidden_count = message_count / 2;
        for (index, msg) in messages.iter().enumerate() {
            if index < hidden_count {
                prover.push_hidden(*msg).unwrap();
            } else {
                prover.push_revealed(*msg).unwrap();
            }
        }
        let ctx = prover.prepare().unwrap();
        let challenge = ctx.create_challenge(nonce);
        let proof = ctx.complete(challenge).unwrap();
        c.bench_function(
            &format!("verify signature pok for {} messages", message_count),
            |b| {
                b.iter(|| {
                    let mut verifier = proof.verifier(&gens, challenge).unwrap();
                    verifier.push_hidden_count(hidden_count).unwrap();
                    for index in hidden_count..messages.len() {
                        verifier.push_revealed(messages[index]).unwrap();
                    }
                    let v_challenge = verifier.create_challenge(nonce);
                    assert_eq!(challenge, v_challenge);
                    let check = verifier.verify(&keypair).unwrap();
                    assert!(check);
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
