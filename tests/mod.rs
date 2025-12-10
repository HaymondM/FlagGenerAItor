//! Test module declarations for CTF Assistant integration tests

pub mod integration_tests;
pub mod interface_parity_tests;
pub mod performance_tests;

use anyhow::Result;

/// Run all integration test suites
pub async fn run_all_tests() -> Result<()> {
    println!("🚀 Starting CTF Assistant Comprehensive Test Suite\n");
    
    // Run integration tests
    integration_tests::run_all_integration_tests().await?;
    
    println!();
    
    // Run interface parity tests
    interface_parity_tests::run_all_interface_parity_tests().await?;
    
    println!();
    
    // Run performance tests
    performance_tests::run_all_performance_tests().await?;
    
    println!("\n🎉 All test suites completed successfully!");
    
    Ok(())
}