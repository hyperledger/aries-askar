use elliptic_curve::{
    bigint::{Encoding, Limb},
    Curve, SecretKey,
};

pub fn write_sk<C: Curve>(sk: &SecretKey<C>, out: &mut [u8]) {
    let limbs = sk.as_scalar_core().as_limbs();
    debug_assert_eq!(out.len(), Limb::BYTE_SIZE * limbs.len());

    for (src, dst) in limbs
        .iter()
        .rev()
        .cloned()
        .zip(out.chunks_exact_mut(Limb::BYTE_SIZE))
    {
        dst.copy_from_slice(&src.to_be_bytes());
    }
}
