# Implementation Plan: FFLONK Decider Integration

> **Project**: Sonobe FFLONK Decider  
> **Version**: 1.0  
> **Status**: Draft  
> **Last Updated**: January 28, 2026

---

## 1. Executive Summary

### 1.1 Objective
Implement `DeciderFflonk` as an alternative to the Groth16-based `Decider` in Sonobe's Nova folding scheme, enabling on-chain verification of Nova IVC proofs with reduced memory requirements (~100-150GB vs ~400GB for VK generation).

### 1.2 Scope

| In Scope | Out of Scope |
|----------|--------------|
| `DeciderFflonk` struct implementing `DeciderTrait` | Migration tools for existing Groth16 proofs |
| FFLONK proof generation and verification | Alternative curves (only BN254) |
| Solidity verifier template | ZK property modifications |
| Memory benchmarks | Performance optimization (Phase 2) |

### 1.3 Key Decisions
- **FFLONK Crate**: `w3f/fflonk` — Rationale: arkworks-native, reference implementation
- **Project Mode**: Prod-Oriented PoC — Rationale: Crypto security critical, but velocity acceptable
- **API Strategy**: Mirror existing `Decider<Groth16>` API for drop-in compatibility

---

## 2. Source Specification Reference

> **Primary Spec**: `docs/PRD.md`  
> **Version**: 1.0 (January 28, 2026)

### 2.1 Specification Compliance Matrix

| Spec Requirement | Plan Section | Status | Notes |
|------------------|--------------|--------|-------|
| FR-001: FFLONK Decider Implementation | Section 4.1 | ✅ | Full implementation spec |
| FR-002: Solidity Verifier Generation | Section 4.2 | ✅ | Template + generator |
| FR-003: API Compatibility | Section 4.1 | ✅ | Same type parameters |
| FR-004: Memory Benchmarks | Section 10.3 | ✅ | Explicit benchmark commands |
| NFR-001: Security | Section 7.1 | ✅ | Threat model cross-ref |
| NFR-002: Performance | Section 10.3 | ✅ | Benchmark thresholds |
| NFR-003: Compatibility | Section 3.2 | ✅ | arkworks 0.5.x, Rust 1.75+ |

**Waiver Requests**: None

---

## 3. Component Bill of Materials (CBOM)

### 3.1 System Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `DeciderFflonk` | `folding-schemes/src/folding/nova/decider_fflonk_eth.rs` | FFLONK decider implementation |
| `FflonkProof` | Same file | Proof data structure |
| `FflonkVerifierParam` | Same file | Verification key |
| `FflonkProverParam` | Same file | Proving key |
| `FflonkVerifier.sol` | `solidity-verifiers/src/verifiers/fflonk.sol` | On-chain verifier template |
| `FflonkVerifierGenerator` | `solidity-verifiers/src/verifiers/fflonk.rs` | Solidity code generator |

### 3.2 External Dependencies

| Dependency | Version | License | Purpose | Security Status |
|------------|---------|---------|---------|-----------------|
| `w3f/fflonk` | main | Apache-2.0 | FFLONK prover/verifier | ⚠️ Unaudited |
| `ark-bn254` | 0.5.x | MIT/Apache-2.0 | BN254 curve | ✅ Audited |
| `ark-grumpkin` | 0.5.x | MIT/Apache-2.0 | Grumpkin curve | ✅ Audited |
| `ark-poly-commit` | 0.5.x | MIT/Apache-2.0 | KZG commitments | ✅ Audited |

### 3.3 Cryptographic Primitives (CBOM Cross-Reference)

> **Reference**: `docs/security/CBOM.md`

| Primitive | Algorithm | Parameters | Implementation | Status |
|-----------|-----------|------------|----------------|--------|
| Final Proof | FFLONK | 128-bit security | `w3f/fflonk::FflonkyKzg` | 🆕 New |
| Polynomial Commitment | KZG | BN254 | `w3f/fflonk::pcs::kzg::KZG` | 🆕 New |
| Aggregation | Shplonk | Multi-opening | `w3f/fflonk::shplonk::Shplonk` | 🆕 New |
| Circuit Hash | Poseidon | Width 5 | Inherited from Sonobe | ✅ Existing |

**Key Management Lifecycle**:

| Key Type | Generation | Storage | Rotation | Revocation |
|----------|------------|---------|----------|------------|
| SRS (Universal) | Powers of Tau ceremony | On-disk file | Never | N/A |
| Prover Key | `preprocess()` | Memory/serialized | Per-circuit change | N/A |
| Verifier Key | `preprocess()` | Embedded in contract | Per-circuit change | Redeploy |

---

## 4. Detailed Component Specifications

### 4.1 DeciderFflonk (Core Component)

**Purpose**: Final proof generation and verification for Nova IVC using FFLONK

**Source Files**:
```
folding-schemes/src/folding/nova/
├── decider_fflonk_eth.rs    # Main implementation
├── mod.rs                    # Module exports (already updated)
```

**Data Structures**:
```rust
/// FFLONK proof bundled with KZG proofs for Nova commitments
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkProof<C: Curve, CS: CommitmentScheme<C>> {
    /// The FFLONK aggregate proof
    pub fflonk_proof: AggregateProof<C::ScalarField, CS>,
    /// KZG proofs for commitment openings
    pub kzg_proofs: [CS::Proof; 2],
    /// The folding proof (cmT)
    pub cmT: C,
    /// Folding randomness
    pub r: C::ScalarField,
    /// KZG challenges used
    pub kzg_challenges: [C::ScalarField; 2],
}

/// Verification parameters for FFLONK decider
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct FflonkVerifierParam<C: Curve, CSVP> {
    /// Hash of preprocessing parameters
    pub pp_hash: C::ScalarField,
    /// FFLONK verification key
    pub fflonk_vk: FflonkVK,
    /// KZG verification parameters
    pub cs_vp: CSVP,
}

/// Prover parameters for FFLONK decider
pub type FflonkProverParam<C: Curve, CSPP> = (FflonkPK, CSPP);
```

**Interface Implementation**:
```rust
impl<C1, C2, FC, CS1, CS2, FS> DeciderTrait<C1, C2, FC, FS>
    for DeciderFflonk<C1, C2, FC, CS1, CS2, FS>
where
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, ProverChallenge = C1::ScalarField, Challenge = C1::ScalarField>,
    CS2: CommitmentScheme<C2, ProverParams = PedersenParams<C2>>,
    FS: FoldingScheme<C1, C2, FC>,
    Nova<C1, C2, FC, CS1, CS2, false>: From<FS>,
{
    type PreprocessorParam = ((FS::ProverParam, FS::VerifierParam), usize);
    type ProverParam = FflonkProverParam<C1, CS1::ProverParams>;
    type Proof = FflonkProof<C1, CS1>;
    type VerifierParam = FflonkVerifierParam<C1, CS1::VerifierParams>;
    type PublicInput = Vec<C1::ScalarField>;
    type CommittedInstance = Vec<C1>;

    fn preprocess(
        mut rng: impl RngCore + CryptoRng,
        ((pp, vp), state_len): Self::PreprocessorParam,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        // 1. Convert Nova params
        let nova_pp: NovaProverParams<...> = pp.into();
        let nova_vp: NovaVerifierParams<...> = vp.into();
        
        // 2. Compute pp_hash
        let pp_hash = nova_vp.pp_hash()?;
        
        // 3. Create dummy DeciderEthCircuit for constraint system
        let circuit = DeciderEthCircuit::<C1, C2>::dummy((
            nova_vp.r1cs,
            nova_vp.cf_r1cs,
            nova_pp.cf_cs_pp,
            nova_pp.poseidon_config,
            (),
            (),
            state_len,
            2,
        ));
        
        // 4. Get constraint matrices (R1CS -> PLONK arithmetization)
        // This is where FFLONK differs from Groth16
        let (pk, vk) = fflonk_setup(circuit, &mut rng)?;
        
        // 5. Return prover/verifier params
        let prover_param = (pk, nova_pp.cs_pp);
        let verifier_param = FflonkVerifierParam {
            pp_hash,
            fflonk_vk: vk,
            cs_vp: nova_vp.cs_vp,
        };
        
        Ok((prover_param, verifier_param))
    }

    fn prove(
        mut rng: impl RngCore + CryptoRng,
        pp: Self::ProverParam,
        folding_scheme: FS,
    ) -> Result<Self::Proof, Error> {
        let (fflonk_pk, cs_pk) = pp;
        
        // 1. Convert folding scheme to circuit
        let circuit = DeciderEthCircuit::<C1, C2>::try_from(Nova::from(folding_scheme))?;
        
        // 2. Extract witness and public inputs
        let cmT = circuit.proof;
        let r = circuit.randomness;
        let kzg_challenges = circuit.kzg_challenges.clone();
        
        // 3. Generate FFLONK proof
        let fflonk_proof = fflonk_prove(&fflonk_pk, circuit, &mut rng)?;
        
        // 4. Generate KZG proofs for commitment openings
        let kzg_proofs = circuit
            .W_i1
            .get_openings()
            .iter()
            .zip(&kzg_challenges)
            .map(|((v, _), &c)| {
                CS1::prove_with_challenge(&cs_pk, c, v, &C1::ScalarField::zero(), None)
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(FflonkProof {
            fflonk_proof,
            cmT,
            r,
            kzg_proofs: kzg_proofs.try_into()?,
            kzg_challenges: kzg_challenges.try_into()?,
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
        // 1. Check minimum steps
        if i <= C1::ScalarField::one() {
            return Err(Error::NotEnoughSteps);
        }
        
        // 2. Fold commitments
        let U_final = DeciderNovaGadget::fold_group_elements_native(
            running_commitments,
            incoming_commitments,
            Some(proof.cmT),
            proof.r,
        )?;
        
        // 3. Construct public input
        let public_input = [
            &[vp.pp_hash, i][..],
            &z_0,
            &z_i,
            &U_final.inputize_nonnative(),
            &proof.kzg_challenges,
            &proof.kzg_proofs.iter().map(|p| p.eval).collect::<Vec<_>>(),
            &proof.cmT.inputize_nonnative(),
        ].concat();
        
        // 4. Verify FFLONK proof
        let fflonk_valid = fflonk_verify(&vp.fflonk_vk, &public_input, &proof.fflonk_proof)?;
        if !fflonk_valid {
            return Err(Error::FflonkVerificationFail);
        }
        
        // 5. Verify KZG proofs
        for ((cm, &c), pi) in U_final.iter().zip(&proof.kzg_challenges).zip(&proof.kzg_proofs) {
            CS1::verify_with_challenge(&vp.cs_vp, c, cm, pi)?;
        }
        
        Ok(true)
    }
}
```

**Error Handling**:

| Error Code | Condition | Recovery |
|------------|-----------|----------|
| `Error::SRSNotFound` | Universal SRS file missing | Download from ceremony |
| `Error::FflonkSetupFail` | FFLONK setup failed | Check circuit constraints |
| `Error::FflonkProveFail` | Proof generation failed | Check witness validity |
| `Error::FflonkVerificationFail` | FFLONK proof invalid | Re-run prover |
| `Error::NotEnoughSteps` | i <= 1 | Run more IVC steps |

---

### 4.2 Solidity Verifier Generator

**Purpose**: Generate Ethereum-compatible Solidity verifier contract

**Source Files**:
```
solidity-verifiers/src/verifiers/
├── fflonk.rs       # Rust generator
├── fflonk.sol      # Solidity template
```

**Template Structure** (fflonk.sol):
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract FflonkVerifier {
    // BN254 curve order
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Verification key elements (embedded by generator)
    {{VK_ELEMENTS}}
    
    struct Proof {
        uint256[2] W_comm;     // Aggregated witness commitment
        uint256[2] W_prime;    // Opening argument
        uint256[4] evaluations; // Polynomial evaluations
    }
    
    function verifyProof(
        Proof calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // 1. Validate public inputs
        require(publicInputs.length == {{NUM_PUBLIC_INPUTS}}, "Invalid public input count");
        
        // 2. Compute challenges (Fiat-Shamir)
        uint256 alpha = computeAlpha(proof, publicInputs);
        uint256 beta = computeBeta(proof, alpha);
        
        // 3. Verify pairing equation
        return verifyPairing(proof, alpha, beta, publicInputs);
    }
    
    function verifyPairing(
        Proof calldata proof,
        uint256 alpha,
        uint256 beta,
        uint256[] calldata publicInputs
    ) internal view returns (bool) {
        // BN254 pairing check using precompiles
        // ecPairing at 0x08
        {{PAIRING_LOGIC}}
    }
}
```

**Gas Requirements**:

| Operation | Gas Estimate |
|-----------|--------------|
| Pairing check (2 pairings) | ~180K |
| Field operations | ~50K |
| Input processing | ~30K |
| **Total** | **~260-300K** |

---

## 5. Integration with w3f/fflonk

### 5.1 Dependency Configuration

**`folding-schemes/Cargo.toml`**:
```toml
[dependencies]
# Add FFLONK dependency
fflonk = { git = "https://github.com/w3f/fflonk", features = ["std"] }
```

### 5.2 arkworks Compatibility

The `w3f/fflonk` crate uses:
- `ark_ff::PrimeField` — Compatible with Sonobe's field usage
- `ark_poly::DensePolynomial` — Standard polynomial representation
- Custom `PCS` trait — Needs adapter for Sonobe's `CommitmentScheme`

**Adapter Pattern**:
```rust
/// Adapter to convert Sonobe's KZG to fflonk's PCS trait
impl<C: Curve> fflonk::pcs::PCS<C::ScalarField> for KZGAdapter<C> {
    type Params = KZGParams<C>;
    type CK = KZGCommitKey<C>;
    type VK = KZGVerifyKey<C>;
    type C = C;
    
    fn setup(max_degree: usize, rng: &mut impl Rng) -> Self::Params {
        KZG::<C>::setup(max_degree, rng)
    }
    
    fn commit(ck: &Self::CK, polynomial: &Poly<C::ScalarField>) -> Self::C {
        KZG::<C>::commit(ck, polynomial)
    }
    
    // ... other methods
}
```

---

## 6. Distributed Systems Analysis

### 6.1 Race Conditions

| Scenario | Risk | Mitigation |
|----------|------|------------|
| Concurrent VK generation | Memory exhaustion | Single-threaded constraint |
| Parallel proof generation | None | Stateless operation |

### 6.2 Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| SRS file corrupted | Hash verification fail | Re-download from ceremony |
| Prover memory exhaustion | OOM signal | Use larger VM |
| Verifier contract revert | Transaction fail | Debug proof generation |

---

## 7. Security Analysis

### 7.1 Threat Model Cross-Reference

> **Reference**: `docs/security/THREAT_MODEL.md`

| Threat | Mitigation in This Plan | Section |
|--------|-------------------------|---------|
| AV-001: Forged Proofs | FFLONK computational soundness | 4.1 |
| AV-002: SRS Compromise | Use Ethereum Powers of Tau | 3.3 |
| AV-003: Weak Randomness | Use `OsRng` only | 4.1 |
| AV-006: Verifier Bugs | Fuzz testing, test vectors | 10.2 |

### 7.2 Attack Surface

| Surface | Protection |
|---------|------------|
| `preprocess()` input | Validate Nova params |
| `prove()` witness | Circuit constraints |
| Solidity verifier | Input length validation, pairing check |

---

## 8. Sprint Breakdown

### Sprint 1: FFLONK Crate Integration (1 week)

- [ ] Add `w3f/fflonk` to `Cargo.toml`
- [ ] Verify arkworks 0.5.x compatibility
- [ ] Create adapter for `PCS` trait
- [ ] Minimal test: prove/verify single polynomial

**Deliverables**: Compiling integration with passing basic test

**TDD Sequence**:
1. **RED**: Write test that calls `FflonkyKzg::setup()` → Expect compile/link error
2. **GREEN**: Add dependency, implement adapter, test passes
3. **REFACTOR**: Clean up adapter code

---

### Sprint 2: DeciderFflonk Implementation (2 weeks)

- [ ] Implement `FflonkProof` and parameter structs
- [ ] Implement `preprocess()` method
- [ ] Implement `prove()` method
- [ ] Implement `verify()` method
- [ ] Unit tests for each method

**SECURITY GATE**:
- [ ] Code review of randomness usage
- [ ] Verify no hardcoded seeds
- [ ] CBOM verification

**TDD Sequence**:
1. **RED**: `test_decider_fflonk()` fails with unimplemented
2. **GREEN**: Implement methods one-by-one
3. **REFACTOR**: Optimize constraint generation

---

### Sprint 3: Solidity Verifier (1 week)

- [ ] Create `fflonk.sol` template
- [ ] Implement `FflonkVerifierGenerator` in Rust
- [ ] Generate verifier from test circuit
- [ ] Foundry tests with valid/invalid proofs

**Deliverables**: Working Solidity verifier contract

---

### Sprint 4: Integration & Benchmarks (1 week)

- [ ] Full integration test with Nova IVC
- [ ] Memory benchmarks (peak RSS)
- [ ] Performance benchmarks (proof time)
- [ ] Demo script (`demo_fflonk_decider.rs`)
- [ ] Update walkthrough.md

**SECURITY GATE**:
- [ ] Fuzz testing with random invalid proofs
- [ ] Final CBOM review

---

## 9. Verification Plan

### 9.1 Unit Tests

**Command**:
```bash
cd folding-schemes
cargo test decider_fflonk --release
```

**Expected**: All tests pass

**Test Cases**:
| Test Name | Description | Expected Result |
|-----------|-------------|-----------------|
| `test_fflonk_preprocess` | Generate prover/verifier params | Success, no panic |
| `test_fflonk_prove` | Generate proof from Nova state | Valid proof returned |
| `test_fflonk_verify_valid` | Verify valid proof | `Ok(true)` |
| `test_fflonk_verify_invalid` | Verify tampered proof | `Err(FflonkVerificationFail)` |
| `test_fflonk_roundtrip` | Prove then verify | `Ok(true)` |

### 9.2 Integration Tests

**Command**:
```bash
cd folding-schemes
cargo test --test integration_fflonk --release
```

**Test Cases**:
| Test | Description | Expected |
|------|-------------|----------|
| `test_fflonk_with_nova_ivc` | Full Nova → FFLONK flow | Proof verifies |
| `test_fflonk_serialization` | Serialize/deserialize all params | Round-trip success |

### 9.3 Memory Benchmarks

**Command**:
```bash
cd folding-schemes
/usr/bin/time -v cargo run --release --example fflonk_vk_gen 2>&1 | grep "Maximum resident set size"
```

**Expected**: Peak RSS < 150GB

### 9.4 Solidity Tests

**Command**:
```bash
cd solidity-verifiers
forge test --match-contract FflonkVerifierTest -vvv
```

**Test Cases**:
| Test | Description | Expected |
|------|-------------|----------|
| `testValidProof` | Verify valid test vector | Pass |
| `testInvalidProof` | Verify tampered proof | Revert |
| `testGasUsage` | Measure verification gas | < 500K |

### 9.5 Demo Script

**Command**:
```bash
cd folding-schemes
cargo run --release --example demo_fflonk_decider
```

**Expected Output**:
```
Nova IVC: Running 10 fold steps...
FFLONK Decider: Preprocessing...
FFLONK Decider: Generating proof...
FFLONK Decider: Verifying proof...
✅ Proof verified successfully!
```

---

## 10. Risk Assessment

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| w3f/fflonk incompatibility | High | Medium | Early integration testing |
| Memory target missed | Medium | Medium | Streaming SRS, lazy eval |
| Solidity verifier gas too high | Medium | Low | Optimize pairing batching |
| Undiscovered soundness issue | Critical | Low | Use audited SRS, test vectors |

---

## 11. Resource Requirements

| Resource | Requirement | Notes |
|----------|-------------|-------|
| Development Machine | 32GB RAM | For running tests |
| VK Generation VM | 128-256GB RAM | GCP n2-highmem-32 |
| SRS File | ~2GB | Powers of Tau download |
| Rust Version | 1.75+ | stable |

---

## 12. Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 28, 2026 | Agile SDLC Agent | Initial draft |
