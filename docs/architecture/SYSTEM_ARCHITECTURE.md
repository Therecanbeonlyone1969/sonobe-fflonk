# System Architecture

**Project**: Sonobe FFLONK Decider Integration  
**Version**: 1.0  
**Date**: January 2026

---

## 1. Overview

This document describes the architecture for integrating FFLONK as an alternative final proof system within Sonobe's Nova folding scheme. The FFLONK Decider provides the same on-chain verification capability as the current Groth16 Decider but with significantly reduced memory requirements for VK generation.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Sonobe Framework                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │   Nova IVC  │──▶│   Decider   │──▶│ Ethereum Verifier   │   │
│  │  (Folding)  │   │  (Final)    │   │    (Solidity)       │   │
│  └─────────────┘   └──────┬──────┘   └─────────────────────┘   │
│                           │                                     │
│              ┌────────────┴────────────┐                       │
│              ▼                         ▼                       │
│    ┌─────────────────┐       ┌─────────────────┐               │
│    │ DeciderEth      │       │ DeciderFflonk   │               │
│    │ (Groth16)       │       │ (FFLONK) ← NEW  │               │
│    └─────────────────┘       └─────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 Core Components

| Component | Responsibility | Crate Location |
|-----------|----------------|----------------|
| `DeciderFflonk` | Final proof generation/verification | `folding-schemes/src/folding/nova/decider_fflonk_eth.rs` |
| `FflonkProof` | Proof data structure | Same file |
| `FflonkVerifierParam` | Verification key | Same file |
| `FflonkProverParam` | Proving key | Same file |

### 2.2 External Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `w3f/fflonk` | main | FFLONK prover/verifier |
| `ark-bn254` | 0.5.x | BN254 curve operations |
| `ark-poly-commit` | 0.5.x | KZG commitments |
| `ark-grumpkin` | 0.5.x | CycleFold secondary curve |

---

## 3. Data Flow

### 3.1 VK/PK Generation (preprocess)

```
┌──────────────────┐     ┌───────────────┐     ┌─────────────────┐
│ Nova VerifierParams│──▶│ DeciderFflonk │──▶  │ FflonkProverParam│
│ (r1cs, cf_r1cs)   │    │  .preprocess()│     │ FflonkVerifierParam│
└──────────────────┘     └───────────────┘     └─────────────────┘
                                │
                                ▼
                    ┌─────────────────────┐
                    │ Universal SRS Load  │
                    │ (Powers of Tau)     │
                    └─────────────────────┘
```

**Key Difference from Groth16**: FFLONK uses universal SRS, reducing per-circuit setup memory.

### 3.2 Proof Generation (prove)

```
┌──────────────┐     ┌───────────────┐     ┌─────────────────┐
│ Nova<...>    │──▶  │ DeciderFflonk │──▶  │ FflonkProof     │
│ (IVC state)  │     │  .prove()     │     │ + KZG proofs    │
└──────────────┘     └───────────────┘     └─────────────────┘
        │                    │
        ▼                    ▼
   ┌─────────┐        ┌─────────────┐
   │ U_i, u_i│        │ FFLONK      │
   │ W_i, w_i│        │ Prover      │
   └─────────┘        └─────────────┘
```

### 3.3 Verification (verify)

```
┌─────────────────┐     ┌───────────────┐     ┌─────────┐
│ FflonkProof     │──▶  │ DeciderFflonk │──▶  │ bool    │
│ + public inputs │     │  .verify()    │     │ (valid?)│
└─────────────────┘     └───────────────┘     └─────────┘
        │                      │
        ▼                      ▼
  ┌───────────┐         ┌───────────┐
  │ FFLONK    │         │ KZG       │
  │ Verifier  │         │ Verifier  │
  └───────────┘         └───────────┘
```

---

## 4. Interface Specification

### 4.1 DeciderFflonk Trait Implementation

```rust
impl<C1, C2, FC, CS1, CS2, FS> DeciderTrait<C1, C2, FC, FS>
    for DeciderFflonk<C1, C2, FC, CS1, CS2, FS>
{
    type PreprocessorParam = ((FS::ProverParam, FS::VerifierParam), usize);
    type ProverParam = FflonkProverParam<C1, CS1::ProverParams>;
    type Proof = FflonkProof<C1, CS1>;
    type VerifierParam = FflonkVerifierParam<C1, CS1::VerifierParams>;
    type PublicInput = Vec<C1::ScalarField>;
    type CommittedInstance = Vec<C1>;

    fn preprocess(rng, params) -> Result<(ProverParam, VerifierParam), Error>;
    fn prove(rng, pp, folding_scheme) -> Result<Proof, Error>;
    fn verify(vp, i, z_0, z_i, U_i, u_i, proof) -> Result<bool, Error>;
}
```

### 4.2 Type Constraints

```rust
where
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, Proof = KZGProof<C1>>,
    CS2: CommitmentScheme<C2, ProverParams = PedersenParams<C2>>,
    FS: FoldingScheme<C1, C2, FC>,
    Nova<C1, C2, FC, CS1, CS2, false>: From<FS>,
```

---

## 5. Solidity Verifier Architecture

### 5.1 Contract Structure

```solidity
contract FflonkVerifier {
    // Verification key (embedded or deployed)
    struct VerifyingKey {
        uint256[2] alpha;     // G1 point
        uint256[2][2] beta;   // G2 point
        uint256[2][2] gamma;  // G2 point
        uint256[2][2] delta;  // G2 point
        uint256[] ic;         // Public input coefficients
    }
    
    // Verify FFLONK proof
    function verifyProof(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}
```

### 5.2 Gas Estimation

| Operation | Est. Gas |
|-----------|----------|
| Pairing check | ~180K |
| Field operations | ~50K |
| Input processing | ~20K |
| **Total** | **~250-300K** |

---

## 6. Memory Architecture

### 6.1 VK Generation Comparison

| Phase | Groth16 | FFLONK (Est.) |
|-------|---------|---------------|
| SRS Load | 100GB | 50GB (universal) |
| Circuit Compile | 150GB | 30GB |
| Key Generation | 150GB | 40GB |
| **Peak** | **~400GB** | **~100-150GB** |

### 6.2 Optimization Strategy

1. **Streaming SRS**: Load SRS in chunks, not all at once
2. **Lazy Evaluation**: Compute circuit constraints on-demand
3. **Memory-Mapped Files**: Use mmap for large coefficient arrays

---

## 7. Error Handling

| Error | Cause | Recovery |
|-------|-------|----------|
| `SRSNotFound` | Universal SRS file missing | Download from ceremony |
| `InvalidWitness` | Nova state malformed | Check IVC computation |
| `VerificationFailed` | Proof invalid | Re-run prover |
| `CircuitMismatch` | VK doesn't match circuit | Regenerate VK |

---

## 8. Security Considerations

See [THREAT_MODEL.md](security/THREAT_MODEL.md) for full analysis.

**Key Points**:
- Universal SRS from audited ceremony (Powers of Tau)
- 128-bit security level (BN254)
- No per-circuit toxic waste

---

## 9. Testing Strategy

| Test Type | Coverage |
|-----------|----------|
| Unit | Individual functions (preprocess, prove, verify) |
| Integration | Full Nova → FFLONK → Verify flow |
| Fuzz | Random invalid proofs must fail |
| Benchmark | Memory usage, proof time |

---

## 10. Deployment Considerations

### 10.1 Ethereum Mainnet

- Deploy `FflonkVerifier.sol` with embedded VK
- Gas cost ~250-300K per verification
- Supports EIP-197 BN254 precompiles

### 10.2 L2 Compatibility

- Same contract works on Arbitrum/Optimism
- Lower gas costs on L2s
