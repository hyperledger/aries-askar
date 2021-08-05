use askar_bbs::{
    DynGeneratorsV1, Message, Nonce, ProverMessages, SignatureMessages, VerifierMessages,
};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::KeySecretBytes,
};
use hex_literal::hex;

#[test]
fn prove_single_signature_hidden_message() {
    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let messages = [Message::hash("hello"), Message::hash("there")];
    let gens = DynGeneratorsV1::new(&keypair, messages.len());
    let mut builder = SignatureMessages::new(&gens);
    builder
        .append(messages.iter().copied())
        .expect("Error building signature");
    let sig = builder.sign(&keypair).expect("Error creating signature");
    let verify = builder.verify_signature(&keypair, &sig).unwrap();
    assert!(verify);

    let mut prover = ProverMessages::new(&gens);
    prover.push_hidden(messages[0]).unwrap();
    prover.push_revealed(messages[1]).unwrap();
    let prepare = prover.prepare(&sig).unwrap();
    let nonce = Nonce::new();
    let challenge = prepare.challenge_values().create_challenge(&gens, nonce);
    let proof = prepare.complete(challenge).unwrap();

    let mut check_msgs = VerifierMessages::new(&gens);
    check_msgs.push_hidden_count(1).unwrap();
    check_msgs.push_revealed(messages[1]).unwrap();
    let verify = proof.verify(&keypair, &check_msgs, challenge).unwrap();
    assert!(verify);
}
