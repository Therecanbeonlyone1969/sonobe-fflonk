# Crypto Bill of Materials (CBOM)

**Project**: Sonobe FFLONK Decider Integration  
**Version**: 0.1.0  
**Mode**: Prod-Oriented PoC

---

## Cryptographic Primitives

### 1. Proof Systems

| Primitive | Algorithm | Library | Status | Security Level |
|-----------|-----------|---------|--------|----------------|
| Final Proof | **FFLONK** | `w3f/fflonk` | 🆕 New | 128-bit |
| IVC Folding | Nova | `sonobe/folding-schemes` | ✅ Inherited | 128-bit |
| CycleFold | Nova secondary | `sonobe/folding-schemes` | ✅ Inherited | 128-bit |

### 2. Commitment Schemes

| Primitive | Algorithm | Curve | Library | Status |
|-----------|-----------|-------|---------|--------|
| Primary | KZG | BN254 | `ark-poly-commit` | ✅ Inherited |
| Secondary | Pedersen | Grumpkin | `ark-ec` | ✅ Inherited |
| FFLONK | KZG | BN254 | `w3f/fflonk` | 🆕 New |

### 3. Elliptic Curves

| Curve | Field Size | Purpose | Library |
|-------|------------|---------|---------|
| BN254 | 254-bit | Primary circuit, pairings | `ark-bn254` |
| Grumpkin | 254-bit | CycleFold secondary | `ark-grumpkin` |

### 4. Hash Functions

| Primitive | Algorithm | Purpose | Status |
|-----------|-----------|---------|--------|
| Circuit Hash | Poseidon | In-circuit hashing | ✅ Inherited |
| Fiat-Shamir | Poseidon Sponge | Transcript | ✅ Inherited |

### 5. Trusted Setup

| Component | Type | Status | Notes |
|-----------|------|--------|-------|
| KZG SRS | Powers of Tau | ✅ Required | Must use audited ceremony |
| FFLONK SRS | Universal | ✅ Shared | Same as KZG, universal per-curve |

### 6. FFLONK Polynomial Aggregation (Sprint 3)

| Primitive | Algorithm | Parameters | Purpose |
|-----------|-----------|------------|---------|
| Combine | `Fflonk::combine(t, fs)` | t=2 | Aggregates W,E into g(X) |
| Opening Roots | `Fflonk::roots(t, z)` | t=2 | Computes t-th roots for batch open |
| Batch Verify | KZG multi-point | t points | Single pairing for t openings |

**Formula**: `g(X) = W(X^t) + E(X^t)·X` where t=2 for Nova witness (W, E)

**Security Assumption**: FFLONK aggregation preserves KZG binding under discrete log hardness on BN254.

---

## Security Notes

### Quantum Resistance
- **Status**: ⚠️ NOT quantum-resistant
- **Mitigation**: BN254 pairing-based crypto will need migration post-quantum
- **Action**: Document as technical debt for future PQC migration

### Trusted Setup
- FFLONK uses universal trusted setup (per-curve, not per-circuit)
- Must verify SRS provenance before production use
- Recommendation: Use Ethereum's established Powers of Tau

### Known Vulnerabilities
- None for selected primitives as of January 2026

---

## Dependency Audit

| Crate | Version | Audit Status | License |
|-------|---------|--------------|---------|
| `ark-bn254` | 0.5.x | ✅ Audited | MIT/Apache-2.0 |
| `ark-grumpkin` | 0.5.x | ✅ Audited | MIT/Apache-2.0 |
| `ark-poly-commit` | 0.5.x | ✅ Audited | MIT/Apache-2.0 |
| `w3f/fflonk` | main | ⚠️ Unaudited | Apache-2.0 |
| `sonobe` | 0.x | ⚠️ Research | MIT |

---

## Action Items

- [ ] Verify `w3f/fflonk` has no known vulnerabilities
- [ ] Confirm SRS generation ceremony provenance
- [ ] Document FFLONK security assumptions
- [ ] Add `cargo audit` to CI pipeline
