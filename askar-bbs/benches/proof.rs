#[macro_use]
extern crate criterion;

use askar_bbs::{
    CreateChallenge, DynGenerators, Message, Nonce, SignatureBuilder, SignatureProver,
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
        let gens = DynGenerators::new(&keypair, message_count)
            .to_vec()
            .unwrap();

        let messages: Vec<Message> = (0..message_count)
            .map(|_| Message::from(OsRng.next_u64()))
            .collect();

        let mut signer = SignatureBuilder::new(&gens, &keypair);
        signer.append_messages(messages.iter().copied()).unwrap();
        let sig = signer.sign().unwrap();
        let nonce = Nonce::new();

        c.bench_function(
            &format!("create signature pok for {} messages", message_count),
            |b| {
                b.iter(|| {
                    let mut prover = SignatureProver::new(&gens, &sig);
                    let hidden_count = message_count / 2;
                    for (index, msg) in messages.iter().enumerate() {
                        if index < hidden_count {
                            prover.push_hidden_message(*msg).unwrap();
                        } else {
                            prover.push_message(*msg).unwrap();
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
                prover.push_hidden_message(*msg).unwrap();
            } else {
                prover.push_message(*msg).unwrap();
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
                    verifier.verify(&keypair).unwrap();
                    assert_eq!(challenge, v_challenge);
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
