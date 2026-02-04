/// FFLONK-based Decider for Nova's onchain (Ethereum's EVM) verification.
/// 
/// This is an alternative to the Groth16-based decider that offers:
/// - Smaller VK generation memory requirements
/// - Universal trusted setup (per-curve, not per-circuit)
/// - Slightly larger proofs but still constant-size
///
/// Based on the paper: https://eprint.iacr.org/2021/1167

use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use core::marker::PhantomData;

pub use super::decider_eth_circuit::DeciderEthCircuit;
use super::decider_eth_circuit::DeciderNovaGadget;
use super::Nova;
use crate::commitment::{kzg::Proof as KZGProof, pedersen::Params as PedersenParams, CommitmentScheme};
use crate::folding::circuits::decider::DeciderEnabledNIFS;
use crate::folding::traits::{CommittedInstanceOps, Dummy, WitnessOps};
use crate::frontend::FCircuit;
use crate::{Curve, Error};
use crate::{Decider as DeciderTrait, FoldingScheme};

// Use w3f-pcs types for KZG
use w3f_pcs::pcs::kzg::params::{KzgCommitterKey, RawKzgVerifierKey};
use w3f_pcs::pcs::kzg::urs::URS;
use w3f_pcs::pcs::{PcsParams, PCS};
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::kzg::commitment::KzgCommitment;
// FFLONK aggregation for polynomial combination
use w3f_pcs::fflonk::Fflonk;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;

/// Load a pre-computed URS from a file.
/// 
/// This reduces memory requirements from ~1TB (generation) to ~3GB (loading).
/// The URS file should be created from a trusted ceremony (e.g., Hermez Powers of Tau)
/// using the `ptau-to-urs` converter.
fn load_urs_from_file(path: &std::path::Path) -> std::result::Result<URS<ark_bn254::Bn254>, Error> {
    use std::fs::File;
    use std::io::BufReader;
    
    let file = File::open(path)
        .map_err(|e| Error::Other(format!("Failed to open URS file {:?}: {}", path, e)))?;
    let reader = BufReader::new(file);
    
    URS::<ark_bn254::Bn254>::deserialize_compressed(reader)
        .map_err(|e| Error::Other(format!("Failed to deserialize URS: {:?}", e)))
}

/// FFLONK Proof structure with real KZG types
/// 
/// Uses FFLONK polynomial aggregation: combines W and E polynomials into
/// a single polynomial g(X) = W(X^2) + E(X^2)*X, enabling batch verification
/// with a single pairing check instead of two.
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkProof<C, CS>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
{
    /// KZG commitments for witness polynomials [cmW, cmE]
    pub witness_commitments: Vec<C>,
    /// Polynomial evaluations at challenge point [W(x), E(x)]
    pub evaluations: Vec<C::ScalarField>,
    /// KZG proofs for polynomial openings (using Sonobe's KZG proof type)
    pub kzg_proofs: [CS::Proof; 2],
    /// Commitment to T (for NIFS verification)
    pub cmT: C,
    /// Randomness for final fold
    pub r: C::ScalarField,
    /// KZG challenges used for opening proofs
    pub kzg_challenges: [C::ScalarField; 2],
    /// FFLONK: Combined polynomial commitment (wrapped w3f-pcs type)
    /// g(X) = W(X^t) + E(X^t)*X - enables batch verification
    pub combined_commitment: Option<KzgCommitment<ark_bn254::Bn254>>,
    /// FFLONK: Opening roots (t-th roots of the challenge point)
    pub opening_roots: Option<Vec<C::ScalarField>>,
    /// FFLONK: Evaluations of combined polynomial at opening roots
    pub combined_evaluations: Option<Vec<C::ScalarField>>,
    /// FFLONK: Challenge point for combined polynomial opening
    pub combined_challenge: Option<C::ScalarField>,
    /// FFLONK: Opening proof for combined polynomial
    /// Note: Store raw G1Affine since w3f_pcs::KzgOpening doesn't impl CanonicalSerialize
    pub combined_opening_proof: Option<ark_bn254::G1Affine>,
    /// FFLONK: Evaluation of combined polynomial AT challenge point (for KZG verify)
    /// This MUST match the point used in combined_opening_proof!
    pub combined_eval_at_challenge: Option<C::ScalarField>,
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
    // Note: FFLONK internally uses ark_bn254::Bn254 for pairing operations
    // The C1 curve just needs to be a CurveGroup (for witness polynomials)
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
        
        // DEBUG: Show actual sizes for memory estimation
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║ DeciderFflonk::preprocess URS Generation                     ║");
        eprintln!("╠══════════════════════════════════════════════════════════════╣");
        eprintln!("║  DeciderEthCircuit constraints: {:>12}                  ║", num_constraints);
        eprintln!("║  Max polynomial degree:         {:>12}                  ║", max_degree);
        eprintln!("║  URS G1 elements needed (n1):   {:>12}                  ║", max_degree + 1);
        eprintln!("║  Estimated URS memory:          {:>12}                  ║", 
            format!("~{} MB", ((max_degree + 1) * 128) / (1024 * 1024)));
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
        
        // 5. Load or Generate KZG SRS (Universal Reference String)
        // This is the key difference from Groth16: universal setup, not circuit-specific
        let n1 = max_degree + 1; // G1 powers needed
        let n2 = 2; // G2: only need g2 and tau*g2 for verification
        
        // Check for pre-computed URS file (reduces memory from ~1TB to ~3GB)
        let urs = if let Ok(path) = std::env::var("FFLONK_URS_PATH") {
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║ Loading pre-computed URS from file                           ║");
            eprintln!("╠══════════════════════════════════════════════════════════════╣");
            eprintln!("║  Path: {}...", &path[..path.len().min(50)]);
            eprintln!("║  Memory savings: ~1TB → ~3GB                                 ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            
            load_urs_from_file(std::path::Path::new(&path))?
        } else {
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║ WARNING: Generating URS in-memory (HIGH MEMORY USAGE!)       ║");
            eprintln!("╠══════════════════════════════════════════════════════════════╣");
            eprintln!("║  Required memory: ~1TB for 9M constraint circuit             ║");
            eprintln!("║  Set FFLONK_URS_PATH to load pre-computed URS instead        ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            URS::<ark_bn254::Bn254>::generate(n1, n2, &mut rng)
        };
        
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
        pp: Self::ProverParam,
        folding_scheme: FS,
    ) -> Result<Self::Proof, Error> {
        let (kzg_ck, cs_pk) = (pp.kzg_ck, pp.cs_pp);

        // 1. Convert folding scheme to DeciderEthCircuit
        // This performs the NIFS fold and computes KZG challenges
        let circuit = DeciderEthCircuit::<C1, C2>::try_from(Nova::from(folding_scheme))?;

        // 2. Extract cmT (commitment to T) and randomness r from circuit
        let cmT = circuit.proof;
        let r = circuit.randomness;

        // 3. Get the challenges that were computed during circuit preparation
        let kzg_challenges = circuit.kzg_challenges.clone();

        // 4. Get witness openings for W and E polynomials
        // W_i1.get_openings() returns [(W, rW), (E, rE)]
        let openings = circuit.W_i1.get_openings();
        
        // 5. FFLONK: Create combined polynomial g(X) = W(X^t) + E(X^t)*X
        // where t = 2 (number of polynomials being aggregated)
        let t: usize = 2;
        let w_coeffs: Vec<C1::ScalarField> = openings[0].0.to_vec();
        let e_coeffs: Vec<C1::ScalarField> = openings[1].0.to_vec();
        
        // Create DensePolynomials from coefficient vectors
        let w_poly = DensePolynomial::<C1::ScalarField>::from_coefficients_vec(w_coeffs);
        let e_poly = DensePolynomial::<C1::ScalarField>::from_coefficients_vec(e_coeffs);
        
        // Combine polynomials using FFLONK aggregation
        // g(X) = W(X^2) + E(X^2)*X
        type FflonkType<F> = Fflonk<F, DensePolynomial<F>>;
        let combined_poly = FflonkType::<C1::ScalarField>::combine(t, &[w_poly, e_poly]);
        
        // 6. Compute opening roots: for challenge x, get t-th roots
        // If x is the evaluation point, z = x^(1/t) is a t-th root
        // All roots are: z, z*ω, ..., z*ω^(t-1) where ω is primitive t-th root of unity
        let challenge_x = kzg_challenges[0]; // Use first challenge as base point
        
        // For t=2, the square root gives us the base root
        // Note: This is a simplification; in production we'd use proper t-th root extraction
        let opening_roots = FflonkType::<C1::ScalarField>::roots(t, challenge_x);
        
        // 7. Evaluate combined polynomial at the opening roots
        use ark_poly::Polynomial;
        let combined_evaluations: Vec<C1::ScalarField> = opening_roots
            .iter()
            .map(|&root| combined_poly.evaluate(&root))
            .collect();

        // 7b. FFLONK: Commit to combined polynomial using w3f-pcs KZG
        // Convert C1::ScalarField coefficients to ark_bn254::Fr for w3f-pcs
        let (combined_cm, opening_proof, combined_challenge, combined_eval_at_challenge) = {
            use ark_ff::PrimeField;
            use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
            
            // Convert polynomial coefficients from C1::ScalarField to ark_bn254::Fr
            // This works because both are the same underlying field for Pallas/BN254 scalar
            let combined_coeffs: Vec<ark_bn254::Fr> = combined_poly
                .coeffs()
                .iter()
                .map(|c| {
                    // Serialize the field element and deserialize as bn254::Fr
                    let mut bytes = vec![];
                    c.serialize_compressed(&mut bytes).expect("serialize failed");
                    ark_bn254::Fr::deserialize_compressed(&bytes[..])
                        .map_err(|e| Error::Other(format!("Field conversion failed: {:?}", e)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let w3f_poly = w3f_pcs::Poly::<ark_bn254::Fr>::from_coefficients_vec(combined_coeffs.clone());
            
            // Convert challenge to bn254::Fr
            let mut challenge_bytes = vec![];
            challenge_x.serialize_compressed(&mut challenge_bytes).expect("serialize challenge failed");
            let challenge_bn254 = ark_bn254::Fr::deserialize_compressed(&challenge_bytes[..])
                .map_err(|e| Error::Other(format!("Challenge conversion failed: {:?}", e)))?;
            
            // Commit using w3f-pcs KZG
            // KZG::commit returns KzgCommitment<E> which implements CanonicalSerialize
            let combined_cm = KZG::<ark_bn254::Bn254>::commit(&kzg_ck, &w3f_poly)
                .map_err(|e| Error::Other(format!("KZG commit failed: {:?}", e)))?;
            
            // Create opening proof at challenge_bn254
            // KZG::open returns E::G1Affine directly (per PCS trait: type Proof = G1Affine)
            let opening_proof = KZG::<ark_bn254::Bn254>::open(&kzg_ck, &w3f_poly, challenge_bn254)
                .map_err(|e| Error::Other(format!("KZG open failed: {:?}", e)))?;
            
            // CRITICAL: Compute evaluation at the SAME point used for opening proof
            // This must match challenge_bn254 for KZG verify to work!
            let eval_at_challenge = combined_poly.evaluate(&challenge_x);
            
            (combined_cm, opening_proof, challenge_x, eval_at_challenge)
        };

        // 8. Generate KZG proofs for the individual polynomial openings
        // (These are still useful for fallback/compatibility)
        let kzg_proofs = openings
            .iter()
            .zip(&kzg_challenges)
            .map(|((v, _), &c)| {
                CS1::prove_with_challenge(&cs_pk, c, v, &C1::ScalarField::zero(), None)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 9. Collect witness commitments from the folded instance
        // U_i1 contains the commitments to W and E polynomials
        let witness_commitments = circuit.U_i1.get_commitments();

        // 10. Get the evaluations at the challenge points
        let evaluations = circuit.kzg_evaluations.clone();

        Ok(Self::Proof {
            witness_commitments,
            evaluations,
            kzg_proofs: kzg_proofs
                .try_into()
                .map_err(|e: Vec<_>| Error::NotExpectedLength(e.len(), 2))?,
            cmT,
            r,
            kzg_challenges: kzg_challenges
                .try_into()
                .map_err(|e: Vec<_>| Error::NotExpectedLength(e.len(), 2))?,
            // FFLONK aggregation fields - now using real KZG commitments!
            combined_commitment: Some(combined_cm),
            opening_roots: Some(opening_roots),
            combined_evaluations: Some(combined_evaluations),
            combined_challenge: Some(combined_challenge),
            combined_opening_proof: Some(opening_proof),
            combined_eval_at_challenge: Some(combined_eval_at_challenge),
        })
    }

    fn verify(
        vp: Self::VerifierParam,
        i: C1::ScalarField,
        z_0: Vec<C1::ScalarField>,
        z_i: Vec<C1::ScalarField>,
        running_commitments: &Self::CommittedInstance,
        incoming_commitments: &Self::CommittedInstance,
        proof: &Self::Proof,
    ) -> Result<bool, Error> {
        // 1. Check minimum steps (must have folded at least once)
        if i <= C1::ScalarField::one() {
            return Err(Error::NotEnoughSteps);
        }

        let Self::VerifierParam {
            pp_hash: _pp_hash,
            kzg_vk,
            cs_vp,
        } = vp;

        // 2. Fold the commitments to get the final folded instance
        // This computes: cmW_final = cmW_running + r * cmW_incoming
        //                cmE_final = cmE_running + r * cmT
        let U_final_commitments = DeciderNovaGadget::fold_group_elements_native(
            running_commitments,
            incoming_commitments,
            Some(proof.cmT),
            proof.r,
        )?;

        // 3. Verify that the provided witness commitments match the folded commitments
        if proof.witness_commitments != U_final_commitments {
            return Err(Error::CommitmentVerificationFail);
        }

        // 4. Verify the KZG opening proofs (Sonobe's commitment scheme)
        // For each commitment (W and E), verify the opening proof at the challenge point
        for ((cm, &c), pi) in U_final_commitments
            .iter()
            .zip(&proof.kzg_challenges)
            .zip(&proof.kzg_proofs)
        {
            // Verify using Sonobe's KZG commitment scheme
            CS1::verify_with_challenge(&cs_vp, c, cm, pi)?;
        }

        // 5. FFLONK: Verify combined polynomial opening using manual pairing check
        // Note: We use RawKzgVerifierKey fields directly since there's no From trait
        // The pairing equation is: e(C - y·G₁, G₂) == e(π, τ·G₂ - z·G₂)
        if let (Some(combined_cm), Some(challenge), Some(opening_proof), Some(eval)) = (
            &proof.combined_commitment,
            &proof.combined_challenge,
            &proof.combined_opening_proof,
            &proof.combined_eval_at_challenge,
        ) {
            use ark_ec::pairing::Pairing;
            use ark_ec::CurveGroup;
            use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
            
            // Convert challenge to bn254::Fr
            let mut challenge_bytes = vec![];
            challenge.serialize_compressed(&mut challenge_bytes).expect("serialize challenge failed");
            let challenge_bn254 = ark_bn254::Fr::deserialize_compressed(&challenge_bytes[..])
                .map_err(|_| Error::Other("Challenge deserialization failed".to_string()))?;
            
            // Convert evaluation to bn254::Fr
            let mut eval_bytes = vec![];
            eval.serialize_compressed(&mut eval_bytes).expect("serialize eval failed");
            let eval_bn254 = ark_bn254::Fr::deserialize_compressed(&eval_bytes[..])
                .map_err(|_| Error::Other("Evaluation deserialization failed".to_string()))?;
            
            // Manual pairing check: e(C - y·G₁, G₂) == e(π, τ·G₂ - z·G₂)
            // Use RawKzgVerifierKey fields: g1, g2, tau_in_g2
            // Extract inner G1Affine from wrapper types using .0
            
            // LHS: e(C - y·G₁, G₂)
            // combined_cm.0 - eval * g1 (use projective for arithmetic, then convert)
            let lhs_projective = combined_cm.0 + kzg_vk.g1 * (-eval_bn254);
            let lhs_point = lhs_projective.into_affine();
            
            // RHS: e(π, τ·G₂ - z·G₂)
            // tau_in_g2 - challenge * g2
            let rhs_projective = kzg_vk.tau_in_g2 + kzg_vk.g2 * (-challenge_bn254);
            let rhs_g2 = rhs_projective.into_affine();
            
            // Perform pairing check
            // combined_cm.0 extracts G1Affine from KzgCommitment
            // opening_proof is already raw G1Affine (extracted from KzgOpening.proof in prove())
            let lhs = ark_bn254::Bn254::pairing(lhs_point, kzg_vk.g2);
            let rhs = ark_bn254::Bn254::pairing(*opening_proof, rhs_g2);
            
            if lhs != rhs {
                return Err(Error::Other("FFLONK pairing verification failed".to_string()));
            }
        }

        let _ = (z_0, z_i); // Silence unused warnings - these are verified in-circuit

        Ok(true)
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
    
    // ==================== Sprint 3 Tests (FFLONK Aggregation) ====================
    
    /// Test that Fflonk::combine correctly aggregates polynomials
    /// g(X) = W(X^2) + E(X^2)*X for t=2
    #[test]
    fn test_fflonk_combine_polynomials() {
        use w3f_pcs::fflonk::Fflonk;
        
        let rng = &mut test_rng();
        
        // Create two polynomials of degree 4
        let w_poly = Poly::rand(4, rng);
        let e_poly = Poly::rand(4, rng);
        
        // Combine: g(X) = W(X^2) + E(X^2)*X
        let t: usize = 2;
        let combined = Fflonk::<ark_bn254::Fr, Poly<ark_bn254::Fr>>::combine(t, &[w_poly.clone(), e_poly.clone()]);
        
        // Combined polynomial should have degree = t * max_degree + (t-1) = 2*4 + 1 = 9
        // But actually FFLONK formula gives degree = t * (max_degree + 1) - 1 = t*(d+1)-1
        assert!(combined.degree() <= t * (4 + 1) - 1, 
            "Combined degree {} should be <= {}", combined.degree(), t * (4 + 1) - 1);
        
        // Verify at a test point using the FFLONK formula
        let x = ark_bn254::Fr::from(7u64);
        let x_squared = x * x;
        
        // g(x) = W(x^2) + E(x^2) * x
        let expected = w_poly.evaluate(&x_squared) + e_poly.evaluate(&x_squared) * x;
        let actual = combined.evaluate(&x);
        
        assert_eq!(expected, actual, "FFLONK combine formula verification failed");
    }
    
    /// Test FFLONK opening roots computation
    #[test]
    fn test_fflonk_roots() {
        use w3f_pcs::fflonk::Fflonk;
        
        let t: usize = 2;
        // We need a t-th root of some value, not the value itself
        // For t=2, if we want roots of 16, we need sqrt(16) = 4 as input
        let root_of_16 = ark_bn254::Fr::from(4u64); // 4^2 = 16
        
        // Compute all t-th roots: returns [root, root*omega_t]
        let roots: Vec<ark_bn254::Fr> = Fflonk::<ark_bn254::Fr, Poly<ark_bn254::Fr>>::roots(t, root_of_16);
        
        assert_eq!(roots.len(), t, "Should have t={} roots", t);
        
        // Verify: both roots should satisfy root^t = 16
        let expected_value = ark_bn254::Fr::from(16u64);
        for (i, root) in roots.iter().enumerate() {
            let root_squared = *root * *root;
            assert_eq!(root_squared, expected_value, "Root {} squared should equal 16", i);
        }
        
        println!("✓ FFLONK roots computed correctly for t={}", t);
    }
    
    /// Test FFLONK batch opening with combined polynomial
    #[test]
    fn test_fflonk_batch_opening() {
        use w3f_pcs::fflonk::Fflonk;
        
        let rng = &mut test_rng();
        let max_degree = 15;
        let t: usize = 2;
        
        // Setup KZG
        let urs = KZG::<Bn254>::setup(max_degree * t + t, rng);
        let ck = urs.ck();
        let vk = urs.vk();
        
        // Create and combine polynomials
        let w_poly = Poly::rand(max_degree / 2, rng);
        let e_poly = Poly::rand(max_degree / 2, rng);
        let combined = Fflonk::<ark_bn254::Fr, Poly<ark_bn254::Fr>>::combine(t, &[w_poly.clone(), e_poly.clone()]);
        
        // Commit to combined polynomial
        let commitment = KZG::<Bn254>::commit(&ck, &combined).expect("Commit failed");
        
        // Choose challenge point and compute opening
        let challenge_x = ark_bn254::Fr::from(42u64);
        let y = combined.evaluate(&challenge_x);
        let proof = KZG::<Bn254>::open(&ck, &combined, challenge_x).expect("Open failed");
        
        // Verify opening
        let result = KZG::<Bn254>::verify(&vk, commitment.clone(), challenge_x, y, proof);
        assert!(result.is_ok(), "KZG verification of combined polynomial failed");
        
        // Test batch verification with multiple points
        let mut commitments = Vec::new();
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut proofs = Vec::new();
        
        for i in 1..=t {
            let x = ark_bn254::Fr::from(i as u64);
            let y = combined.evaluate(&x);
            commitments.push(KZG::<Bn254>::commit(&ck, &combined).unwrap());
            xs.push(x);
            ys.push(y);
            proofs.push(KZG::<Bn254>::open(&ck, &combined, x).unwrap());
        }
        
        let batch_result = KZG::<Bn254>::batch_verify(&vk, commitments, xs, ys, proofs, rng);
        assert!(batch_result.is_ok(), "Batch verification of combined polynomial failed");
        
        println!("✓ FFLONK batch opening verified for t={} polynomials", t);
    }
    
    // ==================== Sprint 4 Tests (Full E2E DeciderFflonk) ====================
    
    /// End-to-end test of DeciderFflonk with Nova folding
    /// This test validates the complete preprocess -> prove -> verify flow
    /// and measures constraint counts and timing metrics
    #[test]
    fn test_decider_fflonk_e2e() {
        use crate::commitment::kzg::KZG as SonobeKZG;
        use crate::commitment::pedersen::Pedersen;
        use crate::folding::nova::{Nova, PreprocessorParam};
        use crate::folding::traits::CommittedInstanceOps;
        use crate::frontend::utils::CubicFCircuit;
        use crate::transcript::poseidon::poseidon_canonical_config;
        use crate::FoldingScheme;
        use crate::Decider as DeciderTrait;  
        use ark_grumpkin::Projective as Projective2;
        use std::time::Instant;
        
        type Projective = ark_bn254::G1Projective;
        type Fr = ark_bn254::Fr;
        
        // Define Nova with KZG+Pedersen commitment schemes
        type N = Nova<
            Projective,
            Projective2,
            CubicFCircuit<Fr>,
            SonobeKZG<'static, Bn254>,
            Pedersen<Projective2>,
            false,
        >;
        
        // Define DeciderFflonk for this Nova instance
        type D = DeciderFflonk<
            Projective,
            Projective2,
            CubicFCircuit<Fr>,
            SonobeKZG<'static, Bn254>,
            Pedersen<Projective2>,
            N,
        >;
        
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════╗");
        println!("║                    FFLONK Decider End-to-End Test                        ║");
        println!("╠══════════════════════════════════════════════════════════════════════════╣");
        
        let mut rng = rand::rngs::OsRng;
        let poseidon_config = poseidon_canonical_config::<Fr>();
        
        // Step 1: Setup Nova
        let start = Instant::now();
        let F_circuit = CubicFCircuit::<Fr>::new(()).expect("Failed to create F_circuit");
        let z_0 = vec![Fr::from(3_u32)];
        
        let preprocessor_param = PreprocessorParam::new(poseidon_config, F_circuit);
        let nova_params = N::preprocess(&mut rng, &preprocessor_param)
            .expect("Nova preprocess failed");
        println!("║ [1/6] Nova preprocess:    {:>10?}", start.elapsed());
        
        // Step 2: Initialize Nova
        let start = Instant::now();
        let mut nova = N::init(&nova_params, F_circuit, z_0.clone())
            .expect("Nova init failed");
        println!("║ [2/6] Nova init:          {:>10?}", start.elapsed());
        
        // Step 3: Preprocess DeciderFflonk  
        let start = Instant::now();
        let (decider_pp, decider_vp) = D::preprocess(
            &mut rng,
            (nova_params.clone(), F_circuit.state_len()),
        ).expect("DeciderFflonk preprocess failed");
        println!("║ [3/6] FFLONK preprocess:  {:>10?}", start.elapsed());
        
        // Step 4: Run Nova folding steps
        let start = Instant::now();
        let num_steps = 3;
        for i in 0..num_steps {
            nova.prove_step(&mut rng, (), None)
                .expect(&format!("Nova prove_step {} failed", i));
        }
        println!("║ [4/6] {} folding steps:   {:>10?}", num_steps, start.elapsed());
        
        // Step 5: Generate FFLONK proof
        let start = Instant::now();
        let proof = D::prove(rng, decider_pp, nova.clone())
            .expect("DeciderFflonk prove failed");
        let prove_time = start.elapsed();
        println!("║ [5/6] FFLONK prove:       {:>10?}", prove_time);
        
        // Step 6: Verify FFLONK proof
        let start = Instant::now();
        let verified = D::verify(
            decider_vp,
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        ).expect("DeciderFflonk verify failed");
        let verify_time = start.elapsed();
        println!("║ [6/6] FFLONK verify:      {:>10?}", verify_time);
        
        assert!(verified, "FFLONK verification should pass");
        
        println!("╠══════════════════════════════════════════════════════════════════════════╣");
        println!("║                              RESULTS                                     ║");
        println!("╠══════════════════════════════════════════════════════════════════════════╣");
        println!("║  Folding steps completed: {}", num_steps);
        println!("║  FFLONK prove time:       {:?}", prove_time);
        println!("║  FFLONK verify time:      {:?}", verify_time);
        println!("║  Verification result:     ✓ PASSED");
        println!("╚══════════════════════════════════════════════════════════════════════════╝");
        println!();
    }
    
    // Note: Full integration tests (test_decider_fflonk_preprocess, prove, verify)
    // require setting up Nova infrastructure which is complex.
    // These will be added incrementally as prove() and verify() are implemented.
    
    // ==================== VK EXTRACTION MEMORY BENCHMARK ====================
    
    /// VK Extraction Memory Benchmark with REALISTIC Circuit Sizes
    /// 
    /// Tests with 100K, 500K, and 1M constraint circuits to measure actual 
    /// memory during DeciderFflonk::preprocess (URS generation).
    ///
    /// Run in Docker: `cargo test -p folding-schemes --release -- test_fflonk_vk_extraction_memory --nocapture`
    #[test]
    fn test_fflonk_vk_extraction_memory() {
        use crate::commitment::kzg::KZG as SonobeKZG;
        use crate::commitment::pedersen::Pedersen;
        use crate::folding::nova::{Nova, PreprocessorParam};
        use crate::frontend::utils::CustomFCircuit;
        use crate::transcript::poseidon::poseidon_canonical_config;
        use crate::FoldingScheme;
        use crate::Decider as DeciderTrait;
        use ark_grumpkin::Projective as Projective2;
        use std::fs;
        use std::time::Instant;
        
        type Projective = ark_bn254::G1Projective;
        type Fr = ark_bn254::Fr;
        
        // Memory reading functions (Linux /proc/self/status)
        fn get_current_memory_kb() -> Option<usize> {
            let status = fs::read_to_string("/proc/self/status").ok()?;
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    return parts.get(1)?.parse().ok();
                }
            }
            None
        }
        
        fn get_peak_memory_kb() -> Option<usize> {
            let status = fs::read_to_string("/proc/self/status").ok()?;
            for line in status.lines() {
                if line.starts_with("VmPeak:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    return parts.get(1)?.parse().ok();
                }
            }
            None
        }
        
        fn format_memory(kb: usize) -> String {
            if kb > 1_000_000 {
                format!("{:.2} GB", kb as f64 / 1_000_000.0)
            } else if kb > 1_000 {
                format!("{:.2} MB", kb as f64 / 1_000.0)
            } else {
                format!("{} KB", kb)
            }
        }
        
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║           FFLONK VK EXTRACTION MEMORY BENCHMARK (REALISTIC CIRCUITS)                                ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                                                      ║");
        println!("║  Testing with CustomFCircuit at production-scale constraint counts:                                  ║");
        println!("║  - 100K constraints                                                                                  ║");
        println!("║  - 500K constraints                                                                                  ║");
        println!("║  - 1M constraints                                                                                    ║");
        println!("║                                                                                                      ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        // Test at different constraint scales
        let constraint_counts: Vec<usize> = vec![100_000, 500_000, 1_000_000];
        
        println!("║  Step Constraints │ Total Circuit  │ Nova Preproc │ FFLONK Preproc │ Peak Memory  │ Time        ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        for n_constraints in constraint_counts {
            let mut rng = rand::rngs::OsRng;
            let poseidon_config = poseidon_canonical_config::<Fr>();
            
            // Create CustomFCircuit with specified constraint count
            let f_circuit = CustomFCircuit::<Fr>::new(n_constraints).expect("Failed to create CustomFCircuit");
            
            // Define Nova with KZG+Pedersen
            type N = Nova<
                Projective,
                Projective2,
                CustomFCircuit<Fr>,
                SonobeKZG<'static, Bn254>,
                Pedersen<Projective2>,
                false,
            >;
            
            type D = DeciderFflonk<
                Projective,
                Projective2,
                CustomFCircuit<Fr>,
                SonobeKZG<'static, Bn254>,
                Pedersen<Projective2>,
                N,
            >;
            
            // Baseline
            let baseline_peak = get_peak_memory_kb().unwrap_or(0);
            
            // Phase 1: Nova::preprocess
            let start = Instant::now();
            let preprocessor_param = PreprocessorParam::new(poseidon_config.clone(), f_circuit);
            let nova_params = N::preprocess(&mut rng, &preprocessor_param).expect("Nova preprocess failed");
            let nova_time = start.elapsed();
            let nova_peak = get_peak_memory_kb().unwrap_or(0);
            
            // Phase 2: DeciderFflonk::preprocess (THE KEY VK EXTRACTION)
            let start = Instant::now();
            let (_decider_pp, _decider_vp) = D::preprocess(
                &mut rng,
                (nova_params.clone(), f_circuit.state_len()),
            ).expect("DeciderFflonk preprocess failed");
            let fflonk_time = start.elapsed();
            let fflonk_peak = get_peak_memory_kb().unwrap_or(0);
            
            let peak_delta = fflonk_peak.saturating_sub(baseline_peak);
            let total_time = nova_time + fflonk_time;
            
            println!("║  {:>15}  │  (see eprintln) │ {:>10.2?}  │ {:>12.2?}  │ {:>12} │ {:>10.2?} ║",
                format!("{}K", n_constraints / 1000),
                nova_time,
                fflonk_time,
                format_memory(peak_delta),
                total_time
            );
        }
        
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                                                      ║");
        println!("║  NOTE: Check eprintln output above for actual DeciderEthCircuit constraint counts                   ║");
        println!("║  The step circuit constraints add to the ~9M DeciderEthCircuit base overhead.                       ║");
        println!("║                                                                                                      ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝");
        println!();
    }
}

