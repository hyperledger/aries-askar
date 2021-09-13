#[test]
fn sign_verify_expected() {
    use askar_bbs::{DynGenerators, Message, SignatureBuilder, SignatureVerifier};
    use askar_crypto::{
        alg::bls::{BlsKeyPair, G2},
        repr::KeySecretBytes,
    };
    use hex_literal::hex;

    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let messages = [Message::hash("hello")];
    let gens = DynGenerators::new(&keypair, messages.len());
    let mut builder = SignatureBuilder::new(&gens, &keypair);
    builder
        .append_messages(messages.iter().copied())
        .expect("Error building signature");
    let sig = builder.sign().expect("Error creating signature");

    let mut verifier = SignatureVerifier::new(&gens, &keypair);
    verifier
        .append_messages(messages.iter().copied())
        .expect("Error verifying signature");
    verifier.verify(&sig).expect("Error verifying signature");
}
