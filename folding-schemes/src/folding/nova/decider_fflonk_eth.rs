/// FFLONK-based Decider for Nova's onchain (Ethereum's EVM) verification.
/// 
/// This is an alternative to the Groth16-based decider that offers:
/// - Smaller VK generation memory requirements
/// - Universal trusted setup (per-curve, not per-circuit)
/// - Slightly larger proofs but still constant-size
///
/// Based on the paper: https://eprint.iacr.org/2021/1167

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

// TODO: Import FFLONK crate when integrated
// use fflonk::{Fflonk, FflonkProof, FflonkProvingKey, FflonkVerifyingKey};

/// FFLONK Proof structure
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkProof<C, CS>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
{
    /// The FFLONK proof bytes
    fflonk_proof: Vec<u8>, // TODO: Replace with actual FFLONK proof type
    /// KZG proofs for polynomial openings
    kzg_proofs: [CS::Proof; 2],
    /// Commitment to T (for NIFS verification)
    cmT: C,
    /// Randomness for final fold
    r: C::ScalarField,
    /// KZG challenges
    kzg_challenges: [C::ScalarField; 2],
}

/// FFLONK Verifier Parameters
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkVerifierParam<C1, CS_VerifyingKey>
where
    C1: Curve,
    CS_VerifyingKey: Clone + CanonicalSerialize + CanonicalDeserialize,
{
    pub pp_hash: C1::ScalarField,
    pub fflonk_vk: Vec<u8>, // TODO: Replace with actual FFLONK VK type
    pub cs_vp: CS_VerifyingKey,
}

/// FFLONK Prover Parameters
#[derive(Debug, Clone)]
pub struct FflonkProverParam<C1, CS_ProverParams>
where
    C1: Curve,
    CS_ProverParams: Clone,
{
    pub fflonk_pk: Vec<u8>, // TODO: Replace with actual FFLONK PK type
    pub cs_pp: CS_ProverParams,
    _marker: PhantomData<C1>,
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
{
    type PreprocessorParam = ((FS::ProverParam, FS::VerifierParam), usize);
    type ProverParam = FflonkProverParam<C1, CS1::ProverParams>;
    type Proof = FflonkProof<C1, CS1>;
    type VerifierParam = FflonkVerifierParam<C1, CS1::VerifierParams>;
    type PublicInput = Vec<C1::ScalarField>;
    type CommittedInstance = Vec<C1>;

    fn preprocess(
        mut _rng: impl RngCore + CryptoRng,
        ((_pp, _vp), _state_len): Self::PreprocessorParam,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        // TODO: Implement FFLONK setup
        // 
        // Key differences from Groth16:
        // 1. Use universal SRS instead of circuit-specific setup
        // 2. Circuit-specific preprocessing is lighter weight
        // 3. Memory requirements should be significantly lower
        //
        // Steps:
        // 1. Load universal FFLONK SRS (per-curve, can be cached)
        // 2. Compile circuit to FFLONK format
        // 3. Generate circuit-specific proving/verifying keys
        
        unimplemented!("FFLONK preprocess not yet implemented")
    }

    fn prove(
        mut _rng: impl RngCore + CryptoRng,
        _pp: Self::ProverParam,
        _folding_scheme: FS,
    ) -> Result<Self::Proof, Error> {
        // TODO: Implement FFLONK proving
        //
        // Steps:
        // 1. Convert Nova accumulator to witness
        // 2. Generate FFLONK proof
        // 3. Generate KZG proofs for polynomial openings
        
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
        // TODO: Implement FFLONK verification
        //
        // Steps:
        // 1. Verify FFLONK proof against public inputs
        // 2. Verify KZG proofs
        // 3. Return verification result
        
        unimplemented!("FFLONK verify not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests require Linux due to pprof/nix dev-dependencies.
    // Run via Docker: `docker build -f Dockerfile.test -t sonobe-fflonk-test . && docker run --rm sonobe-fflonk-test`

    use super::*;
    use ark_bn254::Bn254;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use ark_std::test_rng;
    use w3f_pcs::pcs::{PcsParams, PCS};
    use w3f_pcs::pcs::kzg::KZG;
    use w3f_pcs::Poly;

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
}


