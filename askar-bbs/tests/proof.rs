#[cfg(feature = "getrandom")]
#[test]
fn prove_single_signature_hidden_message() {
    use askar_bbs::{
        CreateChallenge, DynGenerators, Message, Nonce, SignatureBuilder, SignatureProof,
        SignatureProver,
    };
    use askar_crypto::{
        alg::bls::{BlsKeyPair, G2},
        buffer::Writer,
        repr::KeySecretBytes,
    };
    use hex_literal::hex;

    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let messages = [Message::hash("hello"), Message::hash("there")];
    let gens = DynGenerators::new(&keypair, messages.len());
    let mut builder = SignatureBuilder::new(&gens, &keypair);
    builder
        .append_messages(messages.iter().copied())
        .expect("Error building signature");
    let sig = builder.sign().expect("Error creating signature");

    let mut prover = SignatureProver::new(&gens, &sig);
    prover.push_hidden_message(messages[0]).unwrap();
    prover.push_message(messages[1]).unwrap();
    let prepare = prover.prepare().unwrap();
    let nonce = Nonce::new();
    let challenge = prepare.create_challenge(nonce);
    let proof = prepare.complete(challenge).unwrap();

    let mut verifier = proof.verifier(&gens, &keypair, challenge).unwrap();
    verifier.push_hidden_count(1).unwrap();
    verifier.push_revealed(messages[1]).unwrap();
    let challenge_v = verifier.create_challenge(nonce);
    verifier.verify().expect("Error verifying signature PoK");
    assert_eq!(challenge, challenge_v);

    // test serialization round trip
    let mut buf = [0u8; 1024];
    let mut w = Writer::from_slice(&mut buf);
    proof.write_bytes(&mut w).expect("Error serializing proof");
    let proof_len = w.position();
    let proof_de =
        SignatureProof::from_bytes(&buf[..proof_len]).expect("Error deserializing proof");
    assert_eq!(proof, proof_de);
}
