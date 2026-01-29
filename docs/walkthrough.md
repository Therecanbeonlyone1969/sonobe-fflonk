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

## Sprint 2: DeciderFflonk Implementation (Planned)

See `docs/SPRINT_2_PLAN.md` for detailed implementation plan.

---

## Notes

- **Windows Limitation**: `pprof` dev-dependency incompatible with Windows due to `nix`/`libc`. Use Docker for testing.
- **Fork Maintenance**: May need to update fork if upstream w3f-pcs changes.
