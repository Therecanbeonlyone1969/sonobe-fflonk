//! Sprint 1 Demo: FFLONK Crate Integration
//! 
//! This demo validates that w3f-pcs (FFLONK) is properly integrated with arkworks
//! and can perform KZG commitment, opening, and verification operations.
//!
//! Run via Docker:
//! ```
//! docker build -f Dockerfile.test -t sonobe-fflonk-test .
//! docker run --rm sonobe-fflonk-test cargo run --release --example demo_sprint1
//! ```

use ark_bn254::{Bn254, Fr};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::test_rng;
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::{PcsParams, PCS};
use w3f_pcs::Poly;

fn main() {
    println!("=== Sprint 1 Demo: FFLONK Crate Integration ===\n");

    let rng = &mut test_rng();
    let max_degree = 15;

    // Step 1: Setup KZG parameters (Universal SRS)
    println!("[1/5] Setting up KZG parameters (degree {})...", max_degree);
    let urs = KZG::<Bn254>::setup(max_degree, rng);
    let ck = urs.ck();
    let vk = urs.vk();
    println!("      ✓ KZG parameters generated\n");

    // Step 2: Create a test polynomial
    println!("[2/5] Creating random polynomial...");
    let poly = Poly::rand(max_degree, rng);
    println!("      ✓ Polynomial of degree {} created\n", poly.degree());

    // Step 3: Commit to polynomial
    println!("[3/5] Committing to polynomial...");
    let commitment = KZG::<Bn254>::commit(&ck, &poly).expect("Commit failed");
    println!("      ✓ Commitment generated\n");

    // Step 4: Open at evaluation point
    let x = Fr::from(42u64);
    println!("[4/5] Opening at x = 42...");
    let y = poly.evaluate(&x);
    let proof = KZG::<Bn254>::open(&ck, &poly, x).expect("Open failed");
    println!("      ✓ Opening proof generated");
    println!("      ✓ Evaluation: p(42) = {:?}\n", y);

    // Step 5: Verify opening
    println!("[5/5] Verifying opening proof...");
    let result = KZG::<Bn254>::verify(&vk, commitment, x, y, proof);
    match result {
        Ok(()) => println!("      ✓ Verification PASSED\n"),
        Err(_) => {
            println!("      ✗ Verification FAILED\n");
            std::process::exit(1);
        }
    }

    println!("=== Sprint 1 Demo Complete ===");
    println!("All FFLONK/KZG operations working correctly!");
    println!("\nSprint 1 Deliverables Validated:");
    println!("  ✓ w3f-pcs crate integrated (forked with arkworks patches)");
    println!("  ✓ KZG commitment scheme functional");
    println!("  ✓ KZG opening and verification working");
    println!("  ✓ Ready for Sprint 2: DeciderFflonk implementation");
}
