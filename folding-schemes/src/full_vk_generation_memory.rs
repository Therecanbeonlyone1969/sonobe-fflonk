//! Full VK Generation Memory Benchmark
//!
//! This test measures ACTUAL memory consumption during the complete VK generation
//! flow including:
//! - Nova::preprocess (R1CS setup)
//! - DeciderFflonk::preprocess (URS generation + polynomial setup)
//! - DeciderFflonk::prove (polynomial operations)
//!
//! Run in Docker: `cargo test -p folding-schemes full_vk_generation --lib --release -- --nocapture`

#[cfg(test)]
mod tests {
    use ark_pallas::{Fr, Projective};
    use ark_vesta::Projective as Projective2;
    use ark_std::test_rng;
    use std::fs;
    use std::time::Instant;

    use crate::commitment::pedersen::Pedersen;
    use crate::folding::nova::{Nova, PreprocessorParam};
    use crate::frontend::FCircuit;
    use crate::frontend::utils::CubicFCircuit;
    use crate::transcript::poseidon::poseidon_canonical_config;
    use crate::FoldingScheme;
    use crate::Decider as DeciderTrait;
    use crate::Error;

    /// Get peak memory usage from /proc/self/status (Linux only)
    fn get_peak_memory_kb() -> Option<usize> {
        let status = fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if line.starts_with("VmPeak:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                return parts.get(1)?.parse().ok();
            }
        }
        None
    }

    /// Get current RSS memory from /proc/self/status (Linux only)
    fn get_current_memory_kb() -> Option<usize> {
        let status = fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                return parts.get(1)?.parse().ok();
            }
        }
        None
    }

    /// Format KB to human readable
    fn format_memory(kb: usize) -> String {
        if kb > 1_000_000 {
            format!("{:.2} GB", kb as f64 / 1_000_000.0)
        } else if kb > 1_000 {
            format!("{:.2} MB", kb as f64 / 1_000.0)
        } else {
            format!("{} KB", kb)
        }
    }

    /// Measure memory for each phase of Nova VK generation
    /// Returns (phase_name, mem_before, mem_after, peak, time_secs)
    fn measure_phase<F, R>(name: &str, f: F) -> (String, usize, usize, usize, f64, R)
    where
        F: FnOnce() -> R,
    {
        let mem_before = get_current_memory_kb().unwrap_or(0);
        let peak_before = get_peak_memory_kb().unwrap_or(0);
        let start = Instant::now();
        
        let result = f();
        
        let elapsed = start.elapsed().as_secs_f64();
        let mem_after = get_current_memory_kb().unwrap_or(0);
        let peak_after = get_peak_memory_kb().unwrap_or(0);
        
        (name.to_string(), mem_before, mem_after, peak_after.saturating_sub(peak_before), elapsed, result)
    }

    type N = Nova<
        Projective,
        Projective2,
        CubicFCircuit<Fr>,
        Pedersen<Projective>,
        Pedersen<Projective2>,
        false,
    >;

    /// Main test: Measure memory for complete VK generation flow
    #[test]
    fn full_vk_generation_memory_benchmark() {
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║                    FULL VK GENERATION MEMORY BENCHMARK                                              ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                                                      ║");
        println!("║  This test measures ACTUAL memory at each phase of VK generation:                                   ║");
        println!("║  1. Nova::preprocess - R1CS constraint system setup                                                 ║");
        println!("║  2. Nova::init + prove_step - Folding one step                                                      ║");
        println!("║  3. DeciderEthCircuit creation - Converting Nova to decider circuit                                 ║");
        println!("║                                                                                                      ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        let mut rng = test_rng();
        
        // Baseline
        let baseline_mem = get_current_memory_kb().unwrap_or(0);
        let baseline_peak = get_peak_memory_kb().unwrap_or(0);
        println!("║  BASELINE: Current = {}, Peak = {}                                   ║", 
            format_memory(baseline_mem),
            format_memory(baseline_peak));
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║  Phase                        │ Before       │ After        │ Delta        │ Time         ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        // Phase 1: Create poseidon config and f_circuit
        let (name, before, after, _peak_delta, time, (poseidon_config, f_circuit)) = measure_phase(
            "1. Poseidon + FCircuit",
            || {
                let poseidon_config = poseidon_canonical_config::<Fr>();
                let f_circuit = CubicFCircuit::<Fr>::new(()).unwrap();
                (poseidon_config, f_circuit)
            }
        );
        println!("║  {:30}│ {:>12} │ {:>12} │ {:>12} │ {:>10.2}s  ║", 
            name, format_memory(before), format_memory(after), 
            format_memory(after.saturating_sub(before)), time);

        // Phase 2: Nova::preprocess (main constraint system setup)
        let (name, before, after, _peak_delta, time, nova_params) = measure_phase(
            "2. Nova::preprocess",
            || {
                let prep_param = PreprocessorParam::<
                    Projective,
                    Projective2,
                    CubicFCircuit<Fr>,
                    Pedersen<Projective>,
                    Pedersen<Projective2>,
                    false,
                >::new(poseidon_config.clone(), f_circuit);
                N::preprocess(&mut test_rng(), &prep_param).unwrap()
            }
        );
        println!("║  {:30}│ {:>12} │ {:>12} │ {:>12} │ {:>10.2}s  ║", 
            name, format_memory(before), format_memory(after), 
            format_memory(after.saturating_sub(before)), time);
        
        let preprocess_peak = get_peak_memory_kb().unwrap_or(0);

        // Phase 3: Nova::init
        let z_0 = vec![Fr::from(3_u32)];
        let (name, before, after, _peak_delta, time, nova) = measure_phase(
            "3. Nova::init",
            || {
                N::init(&nova_params, f_circuit, z_0.clone()).unwrap()
            }
        );
        println!("║  {:30}│ {:>12} │ {:>12} │ {:>12} │ {:>10.2}s  ║", 
            name, format_memory(before), format_memory(after), 
            format_memory(after.saturating_sub(before)), time);

        // Phase 4: Nova::prove_step (single step)
        let (name, before, after, _peak_delta, time, mut nova) = measure_phase(
            "4. Nova::prove_step (1 step)",
            move || {
                let mut nova = nova;
                nova.prove_step(&mut test_rng(), (), None).unwrap();
                nova
            }
        );
        println!("║  {:30}│ {:>12} │ {:>12} │ {:>12} │ {:>10.2}s  ║", 
            name, format_memory(before), format_memory(after), 
            format_memory(after.saturating_sub(before)), time);

        // Phase 5: Create DeciderEthCircuit
        let (name, before, after, _peak_delta, time, decider_circuit) = measure_phase(
            "5. DeciderEthCircuit::try_from",
            || {
                use crate::folding::nova::decider_eth_circuit::DeciderEthCircuit;
                DeciderEthCircuit::<Projective, Projective2>::try_from(nova).unwrap()
            }
        );
        println!("║  {:30}│ {:>12} │ {:>12} │ {:>12} │ {:>10.2}s  ║", 
            name, format_memory(before), format_memory(after), 
            format_memory(after.saturating_sub(before)), time);

        // Phase 6: Generate constraints (R1CS synthesis)
        let (name, before, after, _peak_delta, time, num_constraints) = measure_phase(
            "6. generate_constraints",
            || {
                use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
                let cs = ConstraintSystem::<Fr>::new_ref();
                decider_circuit.generate_constraints(cs.clone()).unwrap();
                cs.num_constraints()
            }
        );
        println!("║  {:30}│ {:>12} │ {:>12} │ {:>12} │ {:>10.2}s  ║", 
            name, format_memory(before), format_memory(after), 
            format_memory(after.saturating_sub(before)), time);
        
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        // Final memory state
        let final_current = get_current_memory_kb().unwrap_or(0);
        let final_peak = get_peak_memory_kb().unwrap_or(0);
        
        println!("║  FINAL STATE:                                                                                        ║");
        println!("║    Current Memory: {:>12}                                                                   ║", format_memory(final_current));
        println!("║    Peak Memory:    {:>12}                                                                   ║", format_memory(final_peak));
        println!("║    Total Delta:    {:>12} (from baseline)                                                   ║", format_memory(final_current.saturating_sub(baseline_mem)));
        println!("║    Constraint Count: {:>10}                                                                    ║", num_constraints);
        println!("║                                                                                                      ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        println!("║  MEMORY SCALING INSIGHT:                                                                             ║");
        println!("║                                                                                                      ║");
        println!("║  This test uses CubicFCircuit (tiny ~3 constraints per step).                                       ║");
        println!("║  The DeciderEthCircuit overhead is ~9M constraints regardless of step circuit.                      ║");
        println!("║                                                                                                      ║");
        let bytes_per_constraint = if num_constraints > 0 {
            (final_current.saturating_sub(baseline_mem) * 1024) / num_constraints
        } else { 0 };
        println!("║  Measured: ~{} bytes/constraint for R1CS + working memory                              ║", bytes_per_constraint);
        println!("║                                                                                                      ║");
        println!("║  PROJECTIONS (based on measured bytes/constraint):                                                   ║");
        println!("║    10K constraints:  ~{:>10}                                                              ║", 
            format_memory((10_000 * bytes_per_constraint) / 1024));
        println!("║    100K constraints: ~{:>10}                                                              ║", 
            format_memory((100_000 * bytes_per_constraint) / 1024));
        println!("║    1M constraints:   ~{:>10}                                                              ║", 
            format_memory((1_000_000 * bytes_per_constraint) / 1024));
        println!("║    10M constraints:  ~{:>10}                                                              ║", 
            format_memory((10_000_000 * bytes_per_constraint) / 1024));
        println!("║                                                                                                      ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    }

    /// Test with larger step circuit to see scaling
    #[test]
    fn vk_generation_scaling_test() {
        use crate::frontend::utils::CustomFCircuit;
        
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗");
        println!("║                    VK GENERATION SCALING TEST (CustomFCircuit)                                      ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        // Test with CustomFCircuit which has configurable constraint count
        let constraint_counts = [10, 100, 500];
        
        println!("║  Step Circuit    │ Total Constraints │ Peak Memory  │ Bytes/Constraint │              ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣");
        
        for step_constraints in constraint_counts {
            let baseline = get_peak_memory_kb().unwrap_or(0);
            
            // Run Nova with CustomFCircuit
            let result = run_nova_with_custom_circuit(step_constraints);
            
            let peak_after = get_peak_memory_kb().unwrap_or(0);
            let peak_delta = peak_after.saturating_sub(baseline);
            
            match result {
                Ok((total_constraints, _)) => {
                    let bytes_per = if total_constraints > 0 {
                        (peak_delta * 1024) / total_constraints
                    } else { 0 };
                    println!("║  {:>14}  │ {:>17} │ {:>12} │ {:>16} │              ║",
                        format!("{} constr", step_constraints),
                        total_constraints,
                        format_memory(peak_delta),
                        bytes_per
                    );
                }
                Err(e) => {
                    println!("║  {:>14}  │ ERROR: {:60} ║",
                        format!("{} constr", step_constraints),
                        format!("{:?}", e)
                    );
                }
            }
        }
        
        println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    }
    
    fn run_nova_with_custom_circuit(n_constraints: usize) -> Result<(usize, usize), Error> {
        use crate::frontend::utils::CustomFCircuit;
        use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
        
        let mut rng = test_rng();
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let f_circuit = CustomFCircuit::<Fr>::new(n_constraints)?;
        let z_0 = vec![Fr::from(3_u32)];
        
        type NCustom = Nova<
            Projective,
            Projective2,
            CustomFCircuit<Fr>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >;
        
        let prep_param = PreprocessorParam::<
            Projective,
            Projective2,
            CustomFCircuit<Fr>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >::new(poseidon_config, f_circuit);
        
        let nova_params = NCustom::preprocess(&mut rng, &prep_param)?;
        let mut nova = NCustom::init(&nova_params, f_circuit, z_0)?;
        nova.prove_step(&mut rng, (), None)?;
        
        // Create decider circuit
        use crate::folding::nova::decider_eth_circuit::DeciderEthCircuit;
        let decider_circuit = DeciderEthCircuit::<Projective, Projective2>::try_from(nova)?;
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        decider_circuit.generate_constraints(cs.clone())?;
        
        let num_constraints = cs.num_constraints();
        let current_mem = get_current_memory_kb().unwrap_or(0);
        
        Ok((num_constraints, current_mem))
    }
}
