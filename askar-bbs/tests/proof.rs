#[test]
fn prove_single_signature_hidden_message() {
    use askar_bbs::{
        CreateChallenge, DynGenerators, Message, Nonce, SignatureMessages, SignatureProver,
    };
    use askar_crypto::{
        alg::bls::{BlsKeyPair, G2},
        repr::KeySecretBytes,
    };
    use hex_literal::hex;

    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let messages = [Message::hash("hello"), Message::hash("there")];
    let gens = DynGenerators::new(&keypair, messages.len());
    let mut builder = SignatureMessages::signer(&gens, &keypair);
    builder
        .append(messages.iter().copied())
        .expect("Error building signature");
    let sig = builder.sign().expect("Error creating signature");
    let verify = builder.verify_signature(&sig).unwrap();
    assert!(verify);

    let mut prover = SignatureProver::new(&gens, &sig);
    prover.push_hidden(messages[0]).unwrap();
    prover.push_revealed(messages[1]).unwrap();
    let prepare = prover.prepare().unwrap();
    let nonce = Nonce::new();
    let challenge = prepare.create_challenge(nonce);
    let proof = prepare.complete(challenge).unwrap();

    let mut verifier = proof.verifier(&gens, challenge).unwrap();
    verifier.push_hidden_count(1).unwrap();
    verifier.push_revealed(messages[1]).unwrap();
    let challenge_v = verifier.create_challenge(nonce);
    let verify = verifier.verify(&keypair).unwrap();
    assert!(verify);
    assert_eq!(challenge, challenge_v);
}
