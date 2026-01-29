/// FFLONK-based Decider for Nova's onchain (Ethereum's EVM) verification.
/// 
/// This is an alternative to the Groth16-based decider that offers:
/// - Smaller VK generation memory requirements
/// - Universal trusted setup (per-curve, not per-circuit)
/// - Slightly larger proofs but still constant-size
///
/// Based on the paper: https://eprint.iacr.org/2021/1167

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use core::marker::PhantomData;

pub use super::decider_eth_circuit::DeciderEthCircuit;
use super::Nova;
use crate::commitment::{kzg::Proof as KZGProof, pedersen::Params as PedersenParams, CommitmentScheme};
use crate::folding::traits::Dummy;
use crate::frontend::FCircuit;
use crate::{Curve, Error};
use crate::{Decider as DeciderTrait, FoldingScheme};

// Use w3f-pcs types for KZG
use w3f_pcs::pcs::kzg::params::{KzgCommitterKey, RawKzgVerifierKey};
use w3f_pcs::pcs::kzg::urs::URS;
use w3f_pcs::pcs::PcsParams;

/// FFLONK Proof structure with real KZG types
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkProof<C, CS>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
{
    /// KZG commitments for witness polynomials
    pub witness_commitments: Vec<C>,
    /// Polynomial evaluations at challenge point
    pub evaluations: Vec<C::ScalarField>,
    /// KZG proofs for polynomial openings (using Sonobe's KZG proof type)
    pub kzg_proofs: [CS::Proof; 2],
    /// Commitment to T (for NIFS verification)
    pub cmT: C,
    /// Randomness for final fold
    pub r: C::ScalarField,
    /// KZG challenges
    pub kzg_challenges: [C::ScalarField; 2],
}

/// FFLONK Verifier Parameters with real KZG types
/// Uses RawKzgVerifierKey which is serializable (non-prepared G2 elements)
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkVerifierParam<F, E, CS_VerifyingKey>
where
    F: ark_ff::PrimeField,
    E: Pairing,
    CS_VerifyingKey: Clone + CanonicalSerialize + CanonicalDeserialize,
{
    /// Hash of preprocessing parameters (for binding public inputs)
    pub pp_hash: F,
    /// FFLONK/KZG verification key (serializable form)
    pub kzg_vk: RawKzgVerifierKey<E>,
    /// Sonobe's commitment scheme verification params
    pub cs_vp: CS_VerifyingKey,
}

/// FFLONK Prover Parameters with real KZG types
#[derive(Debug, Clone)]
pub struct FflonkProverParam<E, CS_ProverParams>
where
    E: Pairing,
    CS_ProverParams: Clone,
{
    /// KZG committer key (powers of tau in G1)
    pub kzg_ck: KzgCommitterKey<E::G1Affine>,
    /// Sonobe's commitment scheme prover params
    pub cs_pp: CS_ProverParams,
}

/// Onchain Decider using FFLONK instead of Groth16
#[derive(Clone, Debug)]
pub struct DeciderFflonk<C1, C2, FC, CS1, CS2, FS> {
    _c1: PhantomData<C1>,
    _c2: PhantomData<C2>,
    _fc: PhantomData<FC>,
    _cs1: PhantomData<CS1>,
    _cs2: PhantomData<CS2>,
    _fs: PhantomData<FS>,
}

impl<C1, C2, FC, CS1, CS2, FS> DeciderTrait<C1, C2, FC, FS>
    for DeciderFflonk<C1, C2, FC, CS1, CS2, FS>
where
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<
        C1,
        ProverChallenge = C1::ScalarField,
        Challenge = C1::ScalarField,
        Proof = KZGProof<C1>,
    >,
    CS2: CommitmentScheme<C2, ProverParams = PedersenParams<C2>>,
    FS: FoldingScheme<C1, C2, FC>,
    Nova<C1, C2, FC, CS1, CS2, false>: From<FS>,
    crate::folding::nova::ProverParams<C1, C2, CS1, CS2, false>:
        From<<FS as FoldingScheme<C1, C2, FC>>::ProverParam>,
    crate::folding::nova::VerifierParams<C1, C2, CS1, CS2, false>:
        From<<FS as FoldingScheme<C1, C2, FC>>::VerifierParam>,
    // Additional bounds for FFLONK/Pairing
    C1: ark_ec::CurveGroup,
    <C1 as ark_ec::CurveGroup>::Config: ark_ec::pairing::Pairing,
{
    type PreprocessorParam = ((FS::ProverParam, FS::VerifierParam), usize);
    type ProverParam = FflonkProverParam<ark_bn254::Bn254, CS1::ProverParams>;
    type Proof = FflonkProof<C1, CS1>;
    type VerifierParam = FflonkVerifierParam<C1::ScalarField, ark_bn254::Bn254, CS1::VerifierParams>;
    type PublicInput = Vec<C1::ScalarField>;
    type CommittedInstance = Vec<C1>;

    fn preprocess(
        mut rng: impl RngCore + CryptoRng,
        ((pp, vp), state_len): Self::PreprocessorParam,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        // 1. Convert FoldingScheme params to Nova params
        let nova_pp: <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::ProverParam =
            pp.into();
        let nova_vp: <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::VerifierParam = 
            vp.into();

        // 2. Compute pp_hash for binding public inputs
        let pp_hash = nova_vp.pp_hash()?;

        // 3. Create dummy circuit to determine constraint count
        let circuit = DeciderEthCircuit::<C1, C2>::dummy((
            nova_vp.r1cs.clone(),
            nova_vp.cf_r1cs.clone(),
            nova_pp.cf_cs_pp.clone(),
            nova_pp.poseidon_config.clone(),
            (),
            (),
            state_len,
            2, // Nova's running CommittedInstance contains 2 commitments
        ));

        // 4. Estimate max polynomial degree from circuit size
        // For Plonkish circuits, we need degree = 2 * num_constraints + buffer
        let num_constraints = circuit.arith.A.n_rows;
        let max_degree = (num_constraints * 2).next_power_of_two();
        
        // 5. Generate KZG SRS (Universal Reference String)
        // This is the key difference from Groth16: universal setup, not circuit-specific
        let n1 = max_degree + 1; // G1 powers needed
        let n2 = 2; // G2: only need g2 and tau*g2 for verification
        let urs = URS::<ark_bn254::Bn254>::generate(n1, n2, &mut rng);
        
        // 6. Extract committer key and raw verifier key
        let kzg_ck = urs.ck();
        let kzg_vk = urs.raw_vk();

        // 7. Build prover and verifier params
        let prover_param = FflonkProverParam {
            kzg_ck,
            cs_pp: nova_pp.cs_pp,
        };
        
        let verifier_param = FflonkVerifierParam {
            pp_hash,
            kzg_vk,
            cs_vp: nova_vp.cs_vp,
        };

        Ok((prover_param, verifier_param))
    }

    fn prove(
        mut _rng: impl RngCore + CryptoRng,
        _pp: Self::ProverParam,
        _folding_scheme: FS,
    ) -> Result<Self::Proof, Error> {
        // TODO: Implement FFLONK proving (Sprint 2 task 2)
        //
        // Steps:
        // 1. Convert Nova accumulator to DeciderEthCircuit
        // 2. Convert R1CS witness to polynomial representation (Plonkish)
        // 3. Commit to witness polynomials using KZG
        // 4. Compute Fiat-Shamir challenge
        // 5. Generate opening proofs
        // 6. Generate KZG proofs for Nova commitments
        
        unimplemented!("FFLONK prove not yet implemented")
    }

    fn verify(
        _vp: Self::VerifierParam,
        _i: C1::ScalarField,
        _z_0: Vec<C1::ScalarField>,
        _z_i: Vec<C1::ScalarField>,
        _running_commitments: &Self::CommittedInstance,
        _incoming_commitments: &Self::CommittedInstance,
        _proof: &Self::Proof,
    ) -> Result<bool, Error> {
        // TODO: Implement FFLONK verification (Sprint 2 task 3)
        //
        // Steps:
        // 1. Check minimum steps (i > 1)
        // 2. Fold commitments using DeciderNovaGadget
        // 3. Recompute Fiat-Shamir challenge
        // 4. Verify KZG opening proofs
        // 5. Verify Nova commitment proofs
        
        unimplemented!("FFLONK verify not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests require Linux due to pprof/nix dev-dependencies.
    // Run via Docker: `docker build -f Dockerfile.test -t sonobe-fflonk-test . && docker run --rm sonobe-fflonk-test`

    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::AffineRepr;  // For is_zero() method on affine points
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use ark_std::test_rng;
    use w3f_pcs::pcs::{PcsParams, PCS};
    use w3f_pcs::pcs::kzg::KZG;
    use w3f_pcs::Poly;

    // ==================== Sprint 1 Tests (KZG Integration) ====================

    /// Verify the module compiles and types are accessible
    #[test]
    fn test_fflonk_types_exist() {
        fn _assert_send<T: Send>() {}
        fn _assert_sync<T: Sync>() {}
        
        // DeciderFflonk should be Send + Sync
        _assert_send::<DeciderFflonk<
            ark_bn254::G1Projective,
            ark_grumpkin::Projective,
            (),
            (),
            (),
            (),
        >>();
    }

    /// Test that w3f-pcs KZG is properly integrated with arkworks
    /// This validates Sprint 1 goal: "Verify arkworks compatibility"
    #[test]
    fn test_w3f_pcs_kzg_integration() {
        let rng = &mut test_rng();
        let max_degree = 15;

        // Setup KZG params
        let urs = KZG::<Bn254>::setup(max_degree, rng);
        let ck = urs.ck();
        let vk = urs.vk();

        // Create a test polynomial
        let poly = Poly::rand(max_degree, rng);
        let x = ark_bn254::Fr::from(42u64);
        let y = poly.evaluate(&x);

        // Commit to polynomial
        let commitment = KZG::<Bn254>::commit(&ck, &poly).expect("Commit failed");

        // Open at point x
        let proof = KZG::<Bn254>::open(&ck, &poly, x).expect("Open failed");

        // Verify opening
        let result = KZG::<Bn254>::verify(&vk, commitment, x, y, proof);
        assert!(result.is_ok(), "KZG verification failed");
    }

    /// Test that KZG batch verification works
    #[test]
    fn test_w3f_pcs_kzg_batch() {
        let rng = &mut test_rng();
        let max_degree = 15;

        let urs = KZG::<Bn254>::setup(max_degree, rng);
        let ck = urs.ck();
        let vk = urs.vk();

        // Create multiple polynomials and openings
        let mut commitments = Vec::new();
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut proofs = Vec::new();

        for i in 0..3 {
            let poly = Poly::rand(max_degree, rng);
            let x = ark_bn254::Fr::from((i + 1) as u64);
            let y = poly.evaluate(&x);

            commitments.push(KZG::<Bn254>::commit(&ck, &poly).unwrap());
            xs.push(x);
            ys.push(y);
            proofs.push(KZG::<Bn254>::open(&ck, &poly, x).unwrap());
        }

        // Batch verify
        let result = KZG::<Bn254>::batch_verify(&vk, commitments, xs, ys, proofs, rng);
        assert!(result.is_ok(), "KZG batch verification failed");
    }

    // ==================== Sprint 2 Tests (DeciderFflonk TDD) ====================
    
    /// Test that FflonkProverParam can be created with KZG committer key
    #[test]
    fn test_fflonk_prover_param_creation() {
        let rng = &mut test_rng();
        let max_degree = 31;
        
        let urs = URS::<Bn254>::generate(max_degree + 1, 2, rng);
        let kzg_ck = urs.ck();
        
        // Create prover param with placeholder commitment scheme params
        let _prover_param: FflonkProverParam<Bn254, ()> = FflonkProverParam {
            kzg_ck,
            cs_pp: (),
        };
        
        // If we got here, the type construction works
    }
    
    /// Test that FflonkVerifierParam can be created and serialized
    #[test]
    fn test_fflonk_verifier_param_serialization() {
        use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
        use ark_std::io::Cursor;
        
        let rng = &mut test_rng();
        let max_degree = 31;
        
        let urs = URS::<Bn254>::generate(max_degree + 1, 2, rng);
        let kzg_vk = urs.raw_vk();
        
        let verifier_param: FflonkVerifierParam<ark_bn254::Fr, Bn254, ()> = FflonkVerifierParam {
            pp_hash: ark_bn254::Fr::from(12345u64),
            kzg_vk: kzg_vk.clone(),
            cs_vp: (),
        };
        
        // Test serialization roundtrip
        let mut bytes = Vec::new();
        verifier_param.serialize_compressed(&mut bytes).expect("Serialization failed");
        
        let mut cursor = Cursor::new(&bytes);
        let deserialized: FflonkVerifierParam<ark_bn254::Fr, Bn254, ()> = 
            FflonkVerifierParam::deserialize_compressed(&mut cursor).expect("Deserialization failed");
        
        assert_eq!(verifier_param.pp_hash, deserialized.pp_hash);
        assert_eq!(verifier_param.kzg_vk.g1, deserialized.kzg_vk.g1);
    }
    
    /// Test that URS generation produces valid keys
    #[test]
    fn test_urs_generation_validity() {
        use w3f_pcs::pcs::CommitterKey;  // Import the trait
        
        let rng = &mut test_rng();
        let n1 = 64; // G1 powers
        let n2 = 2;  // G2 powers (g2 and tau*g2)
        
        let urs = URS::<Bn254>::generate(n1, n2, rng);
        
        // Verify the URS has correct sizes
        let ck = urs.ck();
        let vk = urs.raw_vk();
        
        // max_degree returns len - 1, so max_degree + 1 = len
        assert_eq!(ck.max_degree() + 1, n1);
        assert!(!vk.g1.is_zero(), "G1 generator should not be zero");
        assert!(!vk.g2.is_zero(), "G2 generator should not be zero");
        assert!(!vk.tau_in_g2.is_zero(), "tau*g2 should not be zero");
    }
    
    /// Test that KZG commitment and opening work with generated URS
    #[test]
    fn test_kzg_commit_open_verify_roundtrip() {
        let rng = &mut test_rng();
        let degree = 32;
        
        // Generate URS
        let urs = URS::<Bn254>::generate(degree + 1, 2, rng);
        let ck = urs.ck();
        let vk = urs.vk();
        
        // Create polynomial
        let poly = Poly::rand(degree, rng);
        
        // Commit
        let commitment = KZG::<Bn254>::commit(&ck, &poly).expect("Commit should succeed");
        
        // Open at multiple points
        for i in 1..=5 {
            let x = ark_bn254::Fr::from(i as u64);
            let y = poly.evaluate(&x);
            let proof = KZG::<Bn254>::open(&ck, &poly, x).expect("Open should succeed");
            
            // Verify (clone commitment since KZG::verify takes it by value)
            let result = KZG::<Bn254>::verify(&vk, commitment.clone(), x, y, proof);
            assert!(result.is_ok(), "Verification at point {} failed", i);
        }
    }
    
    /// Test that verification fails with wrong evaluation
    #[test]
    fn test_kzg_verification_rejects_wrong_eval() {
        let rng = &mut test_rng();
        let degree = 16;
        
        let urs = URS::<Bn254>::generate(degree + 1, 2, rng);
        let ck = urs.ck();
        let vk = urs.vk();
        
        let poly = Poly::rand(degree, rng);
        let commitment = KZG::<Bn254>::commit(&ck, &poly).unwrap();
        
        let x = ark_bn254::Fr::from(42u64);
        let y_correct = poly.evaluate(&x);
        let y_wrong = y_correct + ark_bn254::Fr::from(1u64); // Tamper with evaluation
        
        let proof = KZG::<Bn254>::open(&ck, &poly, x).unwrap();
        
        // Should reject wrong evaluation
        let result = KZG::<Bn254>::verify(&vk, commitment, x, y_wrong, proof);
        assert!(result.is_err(), "Should reject wrong evaluation");
    }
    
    // Note: Full integration tests (test_decider_fflonk_preprocess, prove, verify)
    // require setting up Nova infrastructure which is complex.
    // These will be added incrementally as prove() and verify() are implemented.
}
