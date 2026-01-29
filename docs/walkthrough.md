# Walkthrough: FFLONK Decider Integration

> **Project**: sonobe-fflonk  
> **Branch**: `feat/fflonk-decider`  
> **Last Updated**: January 28, 2026

---

## Sprint 1: FFLONK Crate Integration ✅

### Summary

Successfully integrated the w3f-pcs (FFLONK) crate with Sonobe's arkworks-based infrastructure. This required forking the upstream crate and patching it for arkworks git version compatibility.

### Key Accomplishments

| Deliverable | Status | Notes |
|-------------|--------|-------|
| Fork w3f/fflonk | ✅ | `Therecanbeonlyone1969/fflonk` |
| Patch arkworks versions | ✅ | G1Prepared API fix in `kzg/mod.rs` |
| Docker test environment | ✅ | `Dockerfile.test` for Linux testing |
| KZG integration tests | ✅ | 3 tests pass (commit, batch, types) |
| Executable demo | ✅ | `examples/demo_sprint1.rs` |

### Technical Details

**Problem**: w3f-pcs uses arkworks 0.5 from crates.io, but Sonobe patches arkworks to use git versions. This caused `G1Prepared: From<&G1Affine>` trait bound errors.

**Solution**: Forked w3f-pcs and added `[patch.crates-io]` section to align arkworks versions:

```toml
[patch.crates-io]
ark-ff = { git = "https://github.com/arkworks-rs/algebra" }
ark-ec = { git = "https://github.com/arkworks-rs/algebra" }
# ... (see full patch in fork)
```

Also patched `src/pcs/kzg/mod.rs` to fix the multi_pairing call:

```rust
// Before (arkworks 0.5 API)
E::multi_pairing(&[opening.acc, opening.proof], [vk.g2.clone(), vk.tau_in_g2.clone()])

// After (arkworks git API)
let g1_prepared: [E::G1Prepared; 2] = [opening.acc.into(), opening.proof.into()];
E::multi_pairing(g1_prepared, [vk.g2.clone(), vk.tau_in_g2.clone()])
```

### Test Results

```
$ docker run --rm sonobe-fflonk-test cargo test -p folding-schemes --release --lib -- decider_fflonk

test result: ok. 3 passed; 0 failed;
```

### Demo Execution

```
$ docker run --rm sonobe-fflonk-test cargo run --release --example demo_sprint1

=== Sprint 1 Demo: FFLONK Crate Integration ===

[1/5] Setting up KZG parameters (degree 15)...
      ✓ KZG parameters generated

[2/5] Creating random polynomial...
      ✓ Polynomial of degree 15 created

[3/5] Committing to polynomial...
      ✓ Commitment generated

[4/5] Opening at x = 42...
      ✓ Opening proof generated
      ✓ Evaluation: p(42) = <field element>

[5/5] Verifying opening proof...
      ✓ Verification PASSED

=== Sprint 1 Demo Complete ===
```

### Files Modified

| File | Change |
|------|--------|
| `folding-schemes/Cargo.toml` | Added w3f-pcs dependency |
| `folding-schemes/src/folding/nova/decider_fflonk_eth.rs` | KZG integration tests |
| `Dockerfile.test` | Linux test environment |
| `scripts/run-tests-docker.{sh,ps1}` | Test runner scripts |

---

## Sprint 2: DeciderFflonk Implementation ✅

### Summary

Implemented the full `DeciderFflonk` trait with `preprocess()`, `prove()`, and `verify()` methods using w3f-pcs KZG types for the universal trusted setup.

### Key Accomplishments

| Deliverable | Status | Notes |
|-------------|--------|-------|
| `preprocess()` | ✅ | Generates URS, KzgCommitterKey, RawKzgVerifierKey |
| `prove()` | ✅ | Converts to DeciderEthCircuit, generates KZG proofs |
| `verify()` | ✅ | Folds commitments, verifies KZG opening proofs |
| TDD tests | ✅ | 8 tests pass (5 new Sprint 2 tests) |

### Technical Details

**preprocess()**: Generates universal KZG SRS instead of circuit-specific setup:
```rust
let urs = URS::<Bn254>::generate(max_degree + 1, 2, &mut rng);
let kzg_ck = urs.ck();      // KzgCommitterKey for prover
let kzg_vk = urs.raw_vk();  // RawKzgVerifierKey for verifier
```

**prove()**: Follows Groth16 pattern but generates KZG proofs:
1. Convert folding scheme to `DeciderEthCircuit` (performs NIFS fold)
2. Extract cmT, r, kzg_challenges from circuit
3. Generate KZG proofs for W and E polynomial openings
4. Return `FflonkProof` with witness_commitments and evaluations

**verify()**: 
1. Check minimum steps (i > 1)
2. Fold commitments: `cmW_final = cmW_running + r * cmW_incoming`
3. Verify witness_commitments match folded commitments
4. Verify KZG opening proofs using `CS1::verify_with_challenge`

### Test Results

```
$ docker run --rm sonobe-fflonk-test cargo test -p folding-schemes --release --lib -- decider_fflonk

test result: ok. 8 passed; 0 failed;
```

### Files Modified

| File | Change |
|------|--------|
| `decider_fflonk_eth.rs` | Full implementation of preprocess/prove/verify |
| `task.md` | Updated Sprint 2 progress |

---

## Notes

- **Windows Limitation**: `pprof` dev-dependency incompatible with Windows due to `nix`/`libc`. Use Docker for testing.
- **Fork Maintenance**: May need to update fork if upstream w3f-pcs changes.
- **Production Note**: The current `kzg_ck` (w3f-pcs type) is not yet used in prove() - future improvement to use FFLONK polynomial commitments instead of Sonobe's CS1.
