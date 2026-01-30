//! Parameterized benchmark circuits for testing FFLONK vs Groth16.
//!
//! These circuits have configurable constraint counts for local benchmarking.

use ark_ff::{PrimeField, Field};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// Configurable benchmark circuit with adjustable constraint count.
/// 
/// Each constraint is a simple multiplication: c = a * b
/// This creates R1CS constraints efficiently for benchmarking.
#[derive(Clone, Debug)]
pub struct BenchCircuit<F: PrimeField> {
    /// Number of constraints to generate
    pub num_constraints: usize,
    /// Witness value for generating constraints
    pub witness: F,
}

impl<F: PrimeField> Default for BenchCircuit<F> {
    fn default() -> Self {
        Self::tiny()
    }
}

impl<F: PrimeField> BenchCircuit<F> {
    /// Tiny circuit: ~100 constraints (runs in seconds)
    pub fn tiny() -> Self {
        Self {
            num_constraints: 100,
            witness: F::from(42u64),
        }
    }

    /// Small circuit: ~10K constraints (runs locally in ~1 min)
    pub fn small() -> Self {
        Self {
            num_constraints: 10_000,
            witness: F::from(42u64),
        }
    }

    /// Medium circuit: ~100K constraints (requires decent RAM)
    pub fn medium() -> Self {
        Self {
            num_constraints: 100_000,
            witness: F::from(42u64),
        }
    }

    /// Large circuit: ~1M constraints (requires GitHub runner)
    pub fn large() -> Self {
        Self {
            num_constraints: 1_000_000,
            witness: F::from(42u64),
        }
    }

    /// Custom constraint count
    pub fn with_constraints(num_constraints: usize) -> Self {
        Self {
            num_constraints,
            witness: F::from(42u64),
        }
    }

    /// Generate R1CS constraints
    pub fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Start with witness value
        let mut current = FpVar::new_witness(cs.clone(), || Ok(self.witness))?;
        
        // Generate chain of multiplications: each adds ~1 constraint
        for _ in 0..self.num_constraints {
            let next = &current * &current;
            current = next;
        }
        
        // Final constraint: ensure result is not zero
        let zero = FpVar::new_constant(cs, F::zero())?;
        current.enforce_not_equal(&zero)?;
        
        Ok(())
    }
}

/// Circuit size presets for benchmarking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitSize {
    Tiny,      // ~100 constraints
    Small,     // ~10K constraints
    Medium,    // ~100K constraints
    Large,     // ~1M constraints
}

impl CircuitSize {
    pub fn constraint_count(&self) -> usize {
        match self {
            Self::Tiny => 100,
            Self::Small => 10_000,
            Self::Medium => 100_000,
            Self::Large => 1_000_000,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tiny" => Some(Self::Tiny),
            "small" => Some(Self::Small),
            "medium" => Some(Self::Medium),
            "large" => Some(Self::Large),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn test_tiny_circuit_constraint_count() {
        let circuit = BenchCircuit::<Fr>::tiny();
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        circuit.generate_constraints(cs.clone()).unwrap();
        
        let num_constraints = cs.num_constraints();
        println!("Tiny circuit: {} constraints", num_constraints);
        
        // Should be close to 100 (plus/minus overhead)
        assert!(num_constraints >= 100 && num_constraints < 200);
    }

    #[test]
    fn test_small_circuit_constraint_count() {
        let circuit = BenchCircuit::<Fr>::small();
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        circuit.generate_constraints(cs.clone()).unwrap();
        
        let num_constraints = cs.num_constraints();
        println!("Small circuit: {} constraints", num_constraints);
        
        // Should be close to 10K
        assert!(num_constraints >= 10_000 && num_constraints < 11_000);
    }

    #[test]
    fn test_circuit_size_enum() {
        assert_eq!(CircuitSize::Tiny.constraint_count(), 100);
        assert_eq!(CircuitSize::Small.constraint_count(), 10_000);
        assert_eq!(CircuitSize::from_str("tiny"), Some(CircuitSize::Tiny));
        assert_eq!(CircuitSize::from_str("LARGE"), Some(CircuitSize::Large));
    }
}
