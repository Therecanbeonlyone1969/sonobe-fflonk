# Sprint 2: DeciderFflonk Implementation

> **Sprint Goal**: Implement `preprocess()`, `prove()`, and `verify()` methods for `DeciderFflonk`  
> **Duration**: ~3-5 days  
> **Dependencies**: Sprint 1 complete (w3f-pcs integrated, tests pass)

---

## 1. Sprint Objectives

| Task | Description | TDD Phase |
|------|-------------|-----------|
| `preprocess()` | Generate FFLONK proving/verifying keys from Nova params | RED → GREEN |
| `prove()` | Convert witness + generate FFLONK proof + KZG proofs | RED → GREEN |
| `verify()` | Verify FFLONK proof + KZG commitment openings | RED → GREEN |
| Integration test | End-to-end proof generation and verification | GREEN → REFACTOR |

---

## 2. Implementation Details

### 2.1 Data Structure Updates

**Current state** (skeleton types):
```rust
pub fflonk_proof: Vec<u8>,  // Placeholder
pub fflonk_vk: Vec<u8>,     // Placeholder
```

**Target state** (real types from w3f-pcs):
```rust
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::kzg::params::{KzgVerifierKey, KzgCommitterKey};
use w3f_pcs::pcs::kzg::urs::URS;

pub struct FflonkProof<E: Pairing> {
    /// KZG commitments for witness polynomials
    pub witness_commitments: Vec<E::G1Affine>,
    /// KZG opening proofs
    pub opening_proofs: Vec<E::G1Affine>,
    /// Polynomial evaluations at challenge point
    pub evaluations: Vec<E::ScalarField>,
    /// cmT from Nova NIFS
    pub cmT: E::G1Affine,
    /// Folding randomness r
    pub r: E::ScalarField,
}
```

### 2.2 preprocess() Implementation

**Pattern**: Mirror `decider_eth.rs::preprocess()` with FFLONK setup

```rust
fn preprocess(
    mut rng: impl RngCore + CryptoRng,
    ((pp, vp), state_len): Self::PreprocessorParam,
) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
    // 1. Convert Nova params (same as Groth16)
    let nova_pp = pp.into();
    let nova_vp = vp.into();
    let pp_hash = nova_vp.pp_hash()?;
    
    // 2. Create dummy circuit (same as Groth16)
    let circuit = DeciderEthCircuit::<C1, C2>::dummy(...);
    
    // 3. Generate KZG SRS (DIFFERENT from Groth16)
    let max_degree = circuit.num_constraints();
    let urs = KZG::<Bn254>::setup(max_degree, &mut rng);
    let ck = urs.ck();
    let vk = urs.vk();
    
    // 4. Return FFLONK-specific params
    Ok((
        FflonkProverParam { ck, cs_pp: nova_pp.cs_pp },
        FflonkVerifierParam { pp_hash, vk, cs_vp: nova_vp.cs_vp },
    ))
}
```

### 2.3 prove() Implementation

**Key difference**: No circuit-specific trusted setup like Groth16

```rust
fn prove(
    mut rng: impl RngCore + CryptoRng,
    pp: Self::ProverParam,
    folding_scheme: FS,
) -> Result<Self::Proof, Error> {
    let (fflonk_ck, cs_pk) = pp;
    
    // 1. Convert folding scheme to DeciderEthCircuit
    let circuit = DeciderEthCircuit::<C1, C2>::try_from(Nova::from(folding_scheme))?;
    
    // 2. Extract witness and public inputs
    let cmT = circuit.proof;
    let r = circuit.randomness;
    let kzg_challenges = circuit.kzg_challenges.clone();
    
    // 3. Convert R1CS witness to polynomial representation
    let witness_polys = r1cs_to_polynomials(&circuit)?;
    
    // 4. Commit to witness polynomials using KZG
    let commitments: Vec<_> = witness_polys.iter()
        .map(|p| KZG::<Bn254>::commit(&fflonk_ck, p))
        .collect::<Result<_, _>>()?;
    
    // 5. Compute evaluation challenge (Fiat-Shamir)
    let challenge = compute_challenge(&commitments)?;
    
    // 6. Generate opening proofs
    let openings: Vec<_> = witness_polys.iter()
        .map(|p| KZG::<Bn254>::open(&fflonk_ck, p, challenge))
        .collect::<Result<_, _>>()?;
    
    // 7. Also generate KZG proofs for Nova commitments
    let kzg_proofs = generate_kzg_proofs(&cs_pk, &circuit, &kzg_challenges)?;
    
    Ok(FflonkProof { cmT, r, commitments, openings, kzg_proofs, kzg_challenges })
}
```

### 2.4 verify() Implementation

```rust
fn verify(
    vp: Self::VerifierParam,
    i: C1::ScalarField,
    z_0: Vec<C1::ScalarField>,
    z_i: Vec<C1::ScalarField>,
    running_commitments: &Self::CommittedInstance,
    incoming_commitments: &Self::CommittedInstance,
    proof: &Self::Proof,
) -> Result<bool, Error> {
    // 1. Check minimum steps
    if i <= C1::ScalarField::one() {
        return Err(Error::NotEnoughSteps);
    }
    
    // 2. Fold commitments (same as Groth16)
    let U_final = DeciderNovaGadget::fold_group_elements_native(
        running_commitments, incoming_commitments, Some(proof.cmT), proof.r,
    )?;
    
    // 3. Recompute challenge (Fiat-Shamir)
    let challenge = compute_challenge(&proof.commitments)?;
    
    // 4. Verify KZG opening proofs
    for (commit, opening) in proof.commitments.iter().zip(&proof.openings) {
        if !KZG::<Bn254>::verify(&vp.vk, *commit, challenge, opening.eval, opening.proof)? {
            return Err(Error::FflonkVerificationFail);
        }
    }
    
    // 5. Verify KZG proofs for Nova commitments
    for ((cm, &c), pi) in U_final.iter().zip(&proof.kzg_challenges).zip(&proof.kzg_proofs) {
        CS1::verify_with_challenge(&vp.cs_vp, c, cm, pi)?;
    }
    
    Ok(true)
}
```

---

## 3. TDD Test Cases (RED Phase)

### 3.1 Unit Tests

| Test Name | Purpose | Expected Behavior |
|-----------|---------|-------------------|
| `test_preprocess_creates_valid_keys` | `preprocess()` returns valid KZG keys | Keys serialize/deserialize correctly |
| `test_preprocess_with_invalid_params` | Error handling | Returns `Error::InvalidParams` |
| `test_prove_requires_preprocessed_keys` | Dependency check | Panics without preprocess |
| `test_prove_generates_valid_proof` | Happy path | Proof struct is well-formed |
| `test_prove_with_invalid_witness` | Error handling | Returns `Error::FflonkProveFail` |
| `test_verify_accepts_valid_proof` | Happy path | Returns `Ok(true)` |
| `test_verify_rejects_tampered_proof` | Security | Returns `Err(FflonkVerificationFail)` |
| `test_verify_rejects_wrong_public_input` | Security | Returns `Err(FflonkVerificationFail)` |
| `test_verify_rejects_insufficient_steps` | Edge case | Returns `Err(NotEnoughSteps)` |

### 3.2 Integration Tests

| Test Name | Purpose | Steps |
|-----------|---------|-------|
| `test_decider_fflonk_end_to_end` | Full cycle | 1. Run Nova IVC (5 steps) → 2. preprocess() → 3. prove() → 4. verify() |
| `test_decider_fflonk_serialization` | Persistence | Serialize/deserialize proof and verify still works |

---

## 4. Verification Plan

### 4.1 Automated Tests (Docker)

```bash
# Build and run all FFLONK decider tests
docker build -f Dockerfile.test -t sonobe-fflonk-test .
docker run --rm sonobe-fflonk-test cargo test -p folding-schemes --release -- decider_fflonk

# Expected: All tests pass
# Target: 90%+ coverage on decider_fflonk_eth.rs
```

### 4.2 Coverage Check

```bash
docker run --rm sonobe-fflonk-test cargo tarpaulin --out Html --packages folding-schemes -- decider_fflonk
# Target: Line coverage >= 90%, Branch coverage >= 85%
```

### 4.3 Manual Verification

1. **Memory check**: Run `prove()` with `/usr/bin/time -v` and confirm peak RSS < 10GB
2. **Proof size check**: Serialize proof and confirm size < 1KB

---

## 5. Files to Modify

| File | Changes |
|------|---------|
| `folding-schemes/src/folding/nova/decider_fflonk_eth.rs` | Implement `preprocess`, `prove`, `verify` |
| `folding-schemes/src/error.rs` | Add `FflonkSetupFail`, `FflonkProveFail`, `FflonkVerificationFail` |
| `folding-schemes/src/lib.rs` | Re-export `DeciderFflonk` (if not already) |

---

## 6. Risk Mitigation

| Risk | Mitigation |
|------|------------|
| R1CS → Polynomial conversion complexity | Start with simplified plonkish conversion |
| w3f-pcs API changes | Pin git commit in Cargo.toml |
| Memory regression | Add benchmark test that fails if > 10GB |

---

## 7. Definition of Done

- [ ] All 11 TDD tests pass
- [ ] `cargo test decider_fflonk` succeeds in Docker
- [ ] Integration test generates valid proof in < 30 seconds
- [ ] Code committed to `feat/fflonk-decider` branch
- [ ] walkthrough.md updated with proof-of-work
