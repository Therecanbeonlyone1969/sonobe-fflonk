# Threat Model

**Project**: Sonobe FFLONK Decider Integration  
**Version**: 1.0  
**Date**: January 2026

---

## 1. Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| FFLONK Proofs | Final proofs for on-chain verification | HIGH |
| SRS (Structured Reference String) | Universal trusted setup | CRITICAL |
| Proving Key | Circuit-specific prover parameters | HIGH |
| Verifying Key | Public verification parameters | PUBLIC |
| Nova Accumulator | IVC state being finalized | HIGH |

---

## 2. Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Malicious Prover | Forge invalid proofs | Financial gain |
| Compromised SRS | Toxic waste access | Break soundness |
| Side-Channel Attacker | Timing/power analysis | Extract secrets |
| Supply Chain | Compromised dependencies | Code injection |

---

## 3. Attack Vectors & Mitigations

### AV-001: Forged Proofs
- **Threat**: Attacker generates proof for invalid statement
- **Risk**: HIGH
- **Mitigation**: FFLONK computational soundness (128-bit security)
- **Verification**: Unit tests with invalid inputs must fail verification

### AV-002: SRS Compromise (Toxic Waste)
- **Threat**: Access to SRS generation randomness
- **Risk**: CRITICAL
- **Mitigation**: 
  - Use Ethereum's Powers of Tau ceremony
  - Verify SRS provenance before use
  - Universal setup (per-curve, not per-circuit)
- **Verification**: Document SRS source in deployment

### AV-003: Weak Randomness in Prover
- **Threat**: Predictable Fiat-Shamir challenges
- **Risk**: HIGH
- **Mitigation**:
  - Use cryptographically secure RNG (`OsRng`)
  - Verify no `Math.random()` or seeded PRNGs
- **Verification**: Crypto-lint in CI

### AV-004: Nonce Reuse in Fiat-Shamir
- **Threat**: Repeated challenges enable extraction
- **Risk**: MEDIUM
- **Mitigation**:
  - Transcript binding includes all inputs
  - Unique domain separators per protocol step
- **Verification**: Code review of transcript handling

### AV-005: Malicious Dependencies
- **Threat**: Compromised crate introduces backdoor
- **Risk**: MEDIUM
- **Mitigation**:
  - `cargo audit` in CI
  - Pin dependency versions
  - Review `w3f/fflonk` source
- **Verification**: SBOM generation, license check

### AV-006: Verifier Contract Bugs
- **Threat**: Solidity verifier accepts invalid proofs
- **Risk**: CRITICAL
- **Mitigation**:
  - Comprehensive test vectors
  - Fuzz testing with invalid proofs
  - Gas estimation to detect DoS
- **Verification**: Foundry tests + fuzzing

### AV-007: Integer Overflow/Underflow
- **Threat**: Field arithmetic bugs in Solidity
- **Risk**: HIGH
- **Mitigation**:
  - Use established field arithmetic patterns
  - Solidity 0.8+ with built-in overflow checks
  - BN254 precompiles where available
- **Verification**: Static analysis (Slither)

---

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │   w3f/      │  │   Sonobe    │  │   arkworks      │ │
│  │   fflonk    │  │   core      │  │   ecosystem     │ │
│  └─────────────┘  └─────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                        │
│  ┌─────────────┐  ┌─────────────┐                      │
│  │   Prover    │  │   External  │                      │
│  │   Inputs    │  │   Callers   │                      │
│  └─────────────┘  └─────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Security Assumptions

1. BN254 pairing is secure against classical attacks
2. Powers of Tau ceremony was conducted honestly (1-of-N trust)
3. Poseidon hash function is collision-resistant
4. Rust memory safety prevents RCE vulnerabilities
5. `w3f/fflonk` implementation is correct

---

## 6. Residual Risks

| Risk | Likelihood | Impact | Acceptance |
|------|------------|--------|------------|
| Quantum attack on BN254 | LOW (2030+) | CRITICAL | Accept with monitoring |
| Undiscovered FFLONK bug | LOW | HIGH | Mitigate with testing |
| SRS ceremony compromise | VERY LOW | CRITICAL | Accept (Ethereum trust) |

---

## 7. Security Testing Requirements

- [ ] Unit tests for all proof/verify paths
- [ ] Invalid proof rejection tests
- [ ] Fuzz testing with random inputs
- [ ] `cargo audit` clean
- [ ] Solidity static analysis (Slither)
- [ ] Gas limit DoS testing
