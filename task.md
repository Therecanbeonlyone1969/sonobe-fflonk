# FFLONK Decider Integration - Task Tracker

## Project Overview
Integrate FFLONK as an alternative final proof system for Nova's onchain (Ethereum EVM) decider in Sonobe, reducing VK generation memory requirements from ~400GB to ~100-150GB.

---

## Phase 1: Foundation (Human Gate)
> **Status**: COMPLETE

- [x] Set up Agile SDLC structure
- [x] Establish Project Mode (PoC vs Prod) → **Prod-Oriented PoC**
- [x] Define Tech Stack → **w3f/fflonk + arkworks**
- [x] Create PRD.md
- [x] Create CBOM.md (Crypto Bill of Materials)
- [x] Create THREAT_MODEL.md
- [x] Create SYSTEM_ARCHITECTURE.md
- [x] Create IMPLEMENTATION_PLAN.md

---

## Phase 2: Sprint Planning
> **Status**: IN PROGRESS

### Sprint 1: FFLONK Crate Integration ✅
- [x] Add `fflonk` dependency → Used `Therecanbeonlyone1969/fflonk` fork with arkworks patches
- [x] Verify arkworks compatibility → Patched G1Prepared API, all tests pass
- [x] Create minimal test circuit → 3 tests pass in Docker (KZG integration, batch, types)
- [x] Benchmark memory usage → Deferred to Sprint 4 (integration benchmarks)
- [x] **Law 9**: Executable demo (`examples/demo_sprint1.rs`) ✓
- [x] **Law 9**: Walkthrough artifact (`docs/walkthrough.md`) ✓

### Sprint 2: Decider Implementation [x]
- [x] Implement `preprocess()` - Universal SRS loading ✓
- [x] Implement `prove()` - Witness conversion and proof generation ✓
- [x] Implement `verify()` - FFLONK + KZG verification ✓
- [x] Write unit tests (TDD: Red-Green-Refactor) - 8 tests passing ✓
- [x] **Law 9**: Executable demo (`examples/demo_sprint1.rs` covers KZG flow) ✓
- [x] **Law 9**: Walkthrough artifact update ✓

### Sprint 3: Solidity Verifier [x]
- [x] Upgrade `prove()` with `Fflonk::combine()` polynomial aggregation ✓
- [x] Create FFLONK Solidity template (`fflonk_decider.askama.sol`) ✓
- [x] Create `FflonkVerifierKey` Rust generator ✓
- [x] Add Foundry to Dockerfile for Solidity compilation tests ✓
- [x] Verify generated contract compiles ✓
- [x] **Law 8**: Executable demo (`examples/demo_sprint3.rs`) ✓
- [x] **Law 9**: Walkthrough artifact update ✓
- [x] **Law 19**: Compliance matrix added to sprint_3_plan.md ✓

### Sprint 4: Benchmark Circuits & GitHub Runner [/]
- [x] Create `BenchCircuit` with configurable constraints (Tiny/Small/Medium/Large) ✓
- [x] Add `bench_circuits.rs` module with tests ✓
- [x] Create `constraint_scaling.rs` Criterion benchmark ✓
- [x] Create `vk-extraction.yml` GitHub Actions workflow (32-core/128GB runner) ✓
- [ ] Integrate with zk-proof-of-reserves circuit
- [ ] Memory benchmarks vs Groth16
- [ ] End-to-end testing on GitHub runner

---

## Phase 3: Verification & Audit
> **Status**: NOT STARTED

- [ ] Security Audit (Crypto Auditor)
- [ ] CBOM Validation
- [ ] Walking Code Demo
- [ ] Walkthrough Artifact

---

## Notes
- **Related Project**: `zk-proof-of-reserves`
- **Upstream**: `privacy-scaling-explorations/sonobe`
- **Branch**: `feat/fflonk-decider`
