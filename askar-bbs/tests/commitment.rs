use askar_bbs::{CommittedMessages, DynGeneratorsV1, Message, Nonce, SignatureMessages};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::KeyGen,
};
use rand::rngs::OsRng;

#[test]
fn test_commitment_verify() {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();
    let gens = DynGeneratorsV1::new(&keypair, 1);
    let nonce = Nonce::new();
    let commit_messages = [(0, Message::hash(b"hello"))];
    let mut committer = CommittedMessages::new(&gens);
    for (index, message) in commit_messages.iter().copied() {
        committer.insert(index, message).unwrap();
    }
    let (_blinding, commitment, proof) =
        committer.commit(nonce).expect("Error creating commitment");
    commitment
        .verify_proof(&[0], &gens, &proof, nonce)
        .expect("Error verifying commitment");
}

#[test]
fn test_blind_signature() {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();
    let gens = DynGeneratorsV1::new(&keypair, 2);
    let nonce = Nonce::new();
    let commit_messages = [(0, Message::hash(b"hello"))];
    let mut committer = CommittedMessages::new(&gens);
    for (index, message) in commit_messages.iter().copied() {
        committer.insert(index, message).unwrap();
    }
    let (blinding, commitment, proof) = committer.commit(nonce).expect("Error creating commitment");
    commitment
        .verify_proof(&[0], &gens, &proof, nonce)
        .expect("Error verifying commitment");

    let sign_messages = [Message::hash(b"world")];
    let mut signer = SignatureMessages::from_commitment(commitment, &gens);
    signer.push_committed(1).unwrap();
    signer.append(sign_messages.iter().copied()).unwrap();
    let blind_signature = signer.sign(&keypair).expect("Error creating signature");

    let signature = blind_signature.unblind(blinding);
    let mut prover = SignatureMessages::new(&gens);
    prover.push(commit_messages[0].1).unwrap();
    prover.append(sign_messages.iter().copied()).unwrap();
    let verify = prover
        .verify_signature(&keypair, &signature)
        .expect("Error verifying signature");
    assert!(verify);
}
