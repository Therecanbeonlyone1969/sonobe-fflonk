# Product Requirements Document (PRD)

**Project**: Sonobe FFLONK Decider Integration  
**Version**: 1.0  
**Date**: January 28, 2026  
**Mode**: Prod-Oriented PoC

---

## 1. Executive Summary

Integrate FFLONK as an alternative final proof system for Nova's onchain (Ethereum EVM) decider in Sonobe, reducing VK generation memory requirements from ~400GB to ~100-150GB while maintaining proof soundness and on-chain verifiability.

---

## 2. Problem Statement

### Current State
- Sonobe uses Groth16 for the final "Decider" proof that verifies Nova IVC on-chain
- Groth16 VK generation requires ~400GB+ RAM for complex circuits
- This limits accessibility to users with high-end hardware or expensive cloud VMs

### Desired State
- FFLONK-based Decider with ~100-150GB RAM requirement
- Same proof soundness guarantees
- Compatible Solidity verifier for Ethereum

---

## 3. Goals & Non-Goals

### Goals
1. **Memory Reduction**: VK generation in <150GB RAM
2. **API Compatibility**: Drop-in replacement for existing `DeciderEthCircuit`
3. **On-Chain Verification**: Ethereum-compatible Solidity verifier
4. **Soundness**: No reduction in cryptographic security

### Non-Goals
1. Migration of existing Groth16 proofs
2. Alternative curve support (BN254 only)
3. Zero-knowledge property changes

---

## 4. Functional Requirements

### FR-001: FFLONK Decider Implementation
- **Priority**: P0 (Must Have)
- **Description**: Implement `DeciderFflonk` struct implementing `DeciderTrait`
- **Acceptance Criteria**:
  - `preprocess()` loads universal SRS and generates circuit-specific keys
  - `prove()` converts Nova accumulator to FFLONK proof
  - `verify()` validates FFLONK proof + KZG polynomial openings

### FR-002: Solidity Verifier Generation
- **Priority**: P0 (Must Have)
- **Description**: Generate Ethereum-compatible Solidity verifier contract
- **Acceptance Criteria**:
  - Verifier compiles with Solidity 0.8.x
  - Gas cost <500K for verification
  - Passes all test vectors

### FR-003: API Compatibility
- **Priority**: P1 (Should Have)
- **Description**: Match existing `Decider<Groth16>` API pattern
- **Acceptance Criteria**:
  - Same type parameters as Groth16 decider
  - Drop-in replacement in user code

### FR-004: Memory Benchmarks
- **Priority**: P1 (Should Have)
- **Description**: Benchmark and document memory usage
- **Acceptance Criteria**:
  - VK generation <150GB RAM for test circuit
  - Documented comparison with Groth16

---

## 5. Non-Functional Requirements

### NFR-001: Security
- FFLONK proof must be computationally sound
- No trusted setup leakage
- SRS from audited ceremony

### NFR-002: Performance
- Prover time within 3x of Groth16 (acceptable trade-off)
- Verifier time comparable to Groth16

### NFR-003: Compatibility
- arkworks 0.5.x ecosystem
- Rust stable (1.75+)
- BN254/Grumpkin curve pair

---

## 6. Technical Approach

### Selected FFLONK Implementation
- **Crate**: `w3f/fflonk` (arkworks-native)
- **Rationale**: Best compatibility with existing Sonobe arkworks stack

### Architecture
```
Nova IVC State → DeciderFflonkEthCircuit → FFLONK Prover → Solidity Verifier
```

---

## 7. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| VK Generation Memory | <150GB | Peak RSS during generation |
| Proof Size | <1KB | Serialized proof bytes |
| Verification Gas | <500K | Foundry gas report |
| Test Coverage | >80% | `cargo tarpaulin` |

---

## 8. Timeline

| Sprint | Deliverable | Duration |
|--------|-------------|----------|
| Sprint 1 | FFLONK crate integration | 1 week |
| Sprint 2 | Decider implementation | 2 weeks |
| Sprint 3 | Solidity verifier | 1 week |
| Sprint 4 | Integration & benchmarks | 1 week |

**Total**: 5-6 weeks

---

## 9. Stakeholders

- **Developer**: Agile SDLC Agent Network
- **Reviewer**: User (crypto domain expert)
- **Upstream**: privacy-scaling-explorations/sonobe
