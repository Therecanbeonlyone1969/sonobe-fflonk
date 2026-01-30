//! Sprint 3 Manual Verification: Generate and compile FFLONK Solidity verifier
//!
//! Run in Docker:
//! ```
//! docker run --rm -v /tmp/fflonk_output:/output sonobe-fflonk-test \
//!   cargo run --release --example generate_fflonk_verifier
//! ```

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use solidity_verifiers::verifiers::{FflonkVerifierKey, ProtocolVerifierKey};
use std::fs;

fn main() {
    println!("=== FFLONK Solidity Verifier Generation ===\n");

    // 1. Create sample verifier key
    println!("[1/3] Creating sample FflonkVerifierKey...");
    let pp_hash = Fr::from(0xDEADBEEF_CAFEBABE_u64);
    let z_len = 9; // Nova state length for PoR
    let g1 = ark_bn254::G1Affine::generator();
    let g2 = ark_bn254::G2Affine::generator();
    let vk = ark_bn254::G2Affine::generator();
    
    let fflonk_vk = FflonkVerifierKey::new(pp_hash, z_len, g1, g2, vk);
    println!("      ✓ VK created: PP_HASH={:?}, Z_LEN={}", pp_hash, z_len);

    // 2. Render to Solidity
    println!("[2/3] Rendering Solidity template...");
    let solidity_bytes = fflonk_vk.render_as_template(Some("pragma solidity >=0.8.4;".to_string()));
    let solidity_code = String::from_utf8(solidity_bytes.clone())
        .expect("Invalid UTF-8 in generated Solidity");
    
    println!("      ✓ Generated {} bytes of Solidity code", solidity_code.len());
    
    // 3. Output to file
    println!("[3/3] Saving to /tmp/FflonkDecider.sol...");
    fs::write("/tmp/FflonkDecider.sol", &solidity_code)
        .expect("Failed to write Solidity file");
    println!("      ✓ Saved to /tmp/FflonkDecider.sol");
    
    // Print generated contract for inspection
    println!("\n=== Generated Solidity Contract ===");
    println!("```solidity");
    println!("{}", solidity_code);
    println!("```");
    
    // Verification summary
    println!("\n=== Manual Verification Checklist ===");
    println!("[ ] Contract contains 'contract FflonkDecider': {}", 
        solidity_code.contains("contract FflonkDecider"));
    println!("[ ] Has PP_HASH constant: {}", 
        solidity_code.contains("PP_HASH"));
    println!("[ ] Has T = 2 constant: {}", 
        solidity_code.contains("T = 2"));
    println!("[ ] Has Z_LEN = {}: {}", z_len, 
        solidity_code.contains(&format!("Z_LEN = {}", z_len)));
    println!("[ ] Has verifyFflonkProof function: {}", 
        solidity_code.contains("verifyFflonkProof"));
    println!("[ ] Has pragma solidity: {}", 
        solidity_code.contains("pragma solidity"));
    println!("[ ] Has BN254 scalar field constant: {}", 
        solidity_code.contains("BN254_SCALAR_FIELD"));
    
    println!("\n=== Next Step: Compile with Foundry ===");
    println!("Run: forge build --contracts /tmp/FflonkDecider.sol");
}
