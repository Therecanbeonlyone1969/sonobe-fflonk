# Sonobe FFLONK Fork

This is a fork of [privacy-scaling-explorations/sonobe](https://github.com/privacy-scaling-explorations/sonobe) with experimental FFLONK decider support.

## Goal

Add FFLONK as an alternative final proof system for Nova's onchain (Ethereum EVM) decider, reducing VK generation memory requirements from ~400GB to ~100-150GB.

## Status

**Branch**: `feat/fflonk-decider`

| Component | Status |
|-----------|--------|
| `DeciderFflonk` skeleton | ✅ Created |
| FFLONK crate integration | 🔲 TODO |
| `preprocess()` implementation | 🔲 TODO |
| `prove()` implementation | 🔲 TODO |
| `verify()` implementation | 🔲 TODO |
| Solidity verifier template | 🔲 TODO |
| Tests | 🔲 TODO |

## Key Files

- `folding-schemes/src/folding/nova/decider_fflonk_eth.rs` - FFLONK decider implementation
- `solidity-verifiers/src/verifiers/fflonk.rs` - Solidity verifier (TODO)

## Next Steps

1. Add `fflonk` crate dependency (either `w3f/fflonk` or ZKsync's)
2. Implement universal SRS loading in `preprocess()`
3. Implement witness conversion and proving logic
4. Add Solidity verifier template
5. Benchmark memory usage vs Groth16

## Usage (Once Complete)

```rust
use folding_schemes::folding::nova::decider_fflonk_eth::DeciderFflonk;

type D = DeciderFflonk<
    Projective,
    Projective2,
    MyCircuit<Fr>,
    KZG<'static, Bn254>,
    Pedersen<Projective2>,
    N,
>;

let (pp, vp) = D::preprocess(&mut rng, (nova_params, state_len))?;
let proof = D::prove(rng, pp, nova)?;
D::verify(vp, i, z_0, z_i, &U_i, &u_i, &proof)?;
```

## References

- [FFLONK Paper](https://eprint.iacr.org/2021/1167)
- [w3f/fflonk](https://github.com/w3f/fflonk) - Reference Rust implementation
- [zkVerify/fflonk_verifier](https://github.com/zkVerify/fflonk_verifier) - Polygon CDK verifier
