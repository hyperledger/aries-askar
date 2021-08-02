use askar_bbs::{DynGeneratorsV1, Generators};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::KeySecretBytes,
};
use bls12_381::G1Projective;
use hex_literal::hex;

#[test]
fn dyn_generators_v1_expected() {
    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let message_count = 10;
    let gens_count = message_count + 1;
    let gens = DynGeneratorsV1::new(&keypair, message_count);
    let iter = gens.iter();
    assert_eq!(iter.size_hint(), (gens_count, Some(gens_count)));
    let hm: Vec<G1Projective> = iter.collect();
    assert_eq!(hm.len(), gens_count);
}
