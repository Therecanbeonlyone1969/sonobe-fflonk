//! FFLONK Verifier Key for Solidity template generation.
//!
//! Uses FFLONK polynomial aggregation: g(X) = W(X^t) + E(X^t)*X
//! where t = 2 for combining W and E polynomials.

use crate::utils::HeaderInclusion;
use crate::{ProtocolVerifierKey, MIT_SDPX_IDENTIFIER};
use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use askama::Template;

use super::PRAGMA_KZG10_VERIFIER;

/// Number of polynomials aggregated (W and E)
pub const FFLONK_T: usize = 2;

/// FFLONK Verifier template for Askama rendering
#[derive(Template, Default)]
#[template(path = "fflonk_decider.askama.sol", ext = "sol")]
pub struct FflonkDeciderVerifier {
    /// Public parameters hash (pp_hash)
    pub(crate) pp_hash: String,
    /// Number of polynomials being aggregated (t = 2)
    pub(crate) t: usize,
    /// Length of z_0 and z_i vectors
    pub(crate) z_len: usize,
}

impl From<FflonkVerifierKey> for FflonkDeciderVerifier {
    fn from(data: FflonkVerifierKey) -> Self {
        // Convert pp_hash to hex string manually
        let pp_hash_bytes = data.pp_hash.into_bigint().to_bytes_be();
        let pp_hash_hex: String = pp_hash_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        
        Self {
            pp_hash: format!("0x{}", pp_hash_hex),
            t: FFLONK_T,
            z_len: data.z_len,
        }
    }
}

/// FFLONK Verifier Key data structure
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone, PartialEq, Debug)]
pub struct FflonkVerifierKey {
    /// Public parameters hash
    pub pp_hash: Fr,
    /// Length of IVC state vectors (z_0, z_i)
    pub z_len: usize,
    /// G1 generator
    pub g1: G1Affine,
    /// G2 generator
    pub g2: ark_bn254::G2Affine,
    /// Verification key (tau * g2)
    pub vk: ark_bn254::G2Affine,
}

impl FflonkVerifierKey {
    /// Create a new FflonkVerifierKey from KZG verification key components
    pub fn new(
        pp_hash: Fr,
        z_len: usize,
        g1: G1Affine,
        g2: ark_bn254::G2Affine,
        vk: ark_bn254::G2Affine,
    ) -> Self {
        Self {
            pp_hash,
            z_len,
            g1,
            g2,
            vk,
        }
    }
}

impl ProtocolVerifierKey for FflonkVerifierKey {
    const PROTOCOL_NAME: &'static str = "FFLONK";

    fn render_as_template(self, pragma: Option<String>) -> Vec<u8> {
        HeaderInclusion::<FflonkDeciderVerifier>::builder()
            .sdpx(MIT_SDPX_IDENTIFIER.to_string())
            .pragma_version(pragma.unwrap_or(PRAGMA_KZG10_VERIFIER.to_string()))
            .template(self)
            .build()
            .render()
            .unwrap()
            .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_std::Zero;

    #[test]
    fn fflonk_vk_can_be_created() {
        let pp_hash = Fr::from(12345u64);
        let z_len = 3;
        let g1 = G1Affine::generator();
        let g2 = ark_bn254::G2Affine::generator();
        let vk = ark_bn254::G2Affine::generator(); // Placeholder

        let fflonk_vk = FflonkVerifierKey::new(pp_hash, z_len, g1, g2, vk);

        assert_eq!(fflonk_vk.pp_hash, pp_hash);
        assert_eq!(fflonk_vk.z_len, z_len);
        assert!(!fflonk_vk.g1.is_zero());
    }

    #[test]
    fn fflonk_vk_serde_roundtrip() {
        let pp_hash = Fr::from(67890u64);
        let z_len = 5;
        let g1 = G1Affine::generator();
        let g2 = ark_bn254::G2Affine::generator();
        let vk = ark_bn254::G2Affine::generator();

        let fflonk_vk = FflonkVerifierKey::new(pp_hash, z_len, g1, g2, vk);

        let mut bytes = vec![];
        fflonk_vk.serialize_protocol_verifier_key(&mut bytes).unwrap();

        let obtained_fflonk_vk =
            FflonkVerifierKey::deserialize_protocol_verifier_key(bytes.as_slice()).unwrap();

        assert_eq!(fflonk_vk, obtained_fflonk_vk);
    }
    
    /// E2E test: Generate FFLONK Solidity verifier from key
    #[test]
    fn fflonk_verifier_template_renders() {
        let pp_hash = Fr::from(0xDEADBEEFu64);
        let z_len = 4;
        let g1 = G1Affine::generator();
        let g2 = ark_bn254::G2Affine::generator();
        let vk = ark_bn254::G2Affine::generator();

        let fflonk_vk = FflonkVerifierKey::new(pp_hash, z_len, g1, g2, vk);
        
        // Render as Solidity template
        let solidity_bytes = fflonk_vk.render_as_template(None);
        let solidity_code = String::from_utf8(solidity_bytes).expect("Invalid UTF-8");
        
        // Verify template contains expected elements
        assert!(solidity_code.contains("contract FflonkDecider"), "Missing contract declaration");
        assert!(solidity_code.contains("PP_HASH"), "Missing PP_HASH constant");
        assert!(solidity_code.contains("T = 2"), "Missing T constant");
        assert!(solidity_code.contains("Z_LEN = 4"), "Missing Z_LEN constant");
        assert!(solidity_code.contains("verifyFflonkProof"), "Missing verifyFflonkProof function");
        assert!(solidity_code.contains("pragma solidity"), "Missing pragma");
        
        println!("✓ FFLONK Solidity template rendered successfully ({} bytes)", solidity_code.len());
    }
}
