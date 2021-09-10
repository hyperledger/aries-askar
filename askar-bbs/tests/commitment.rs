#[cfg(feature = "getrandom")]
use askar_bbs::{CommitmentBuilder, DynGeneratorsV1, Message, Nonce, SignatureMessages};

#[cfg(feature = "getrandom")]
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::KeyGen,
};

#[cfg(feature = "getrandom")]
use rand::rngs::OsRng;

#[cfg(all(feature = "getrandom"))]
#[test]
fn test_commitment_verify() {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();
    let gens = DynGeneratorsV1::new(&keypair, 5);
    let nonce = Nonce::new();
    let commit_messages = [(0, Message::hash(b"hello"))];
    let mut committer = CommitmentBuilder::new(&gens);
    for (index, message) in commit_messages.iter().copied() {
        committer.commit(index, message).unwrap();
    }
    let (challenge, _blinding, commitment, proof) = committer
        .complete(nonce)
        .expect("Error completing commitment");
    proof
        .verify(&gens, commitment, [0].iter().cloned(), challenge, nonce)
        .expect("Error verifying commitment");
}

#[cfg(all(feature = "getrandom"))]
#[test]
fn test_blind_signature() {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();
    let gens = DynGeneratorsV1::new(&keypair, 2);
    let nonce = Nonce::new();
    let commit_messages = [(0, Message::hash(b"hello"))];
    let mut committer = CommitmentBuilder::new(&gens);
    for (index, message) in commit_messages.iter().copied() {
        committer.commit(index, message).unwrap();
    }
    let (challenge, blinding, commitment, proof) = committer
        .complete(nonce)
        .expect("Error completing commitment");
    proof
        .verify(&gens, commitment, [0].iter().cloned(), challenge, nonce)
        .expect("Error verifying commitment");

    let sign_messages = [Message::hash(b"world")];
    let mut signer = SignatureMessages::from_commitment(commitment, &gens);
    signer.push_committed_count(1).unwrap();
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
