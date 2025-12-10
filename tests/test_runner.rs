//! Main test runner for end-to-end integration tests
//! 
//! This module provides a comprehensive test runner that executes all
//! integration tests, interface parity tests, and performance tests.

use anyhow::Result;

mod integration_tests;
mod interface_parity_tests;
mod performance_tests;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging for tests
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    
    println!("🚀 CTF Assistant - End-to-End Integration Test Suite");
    println!("==================================================\n");
    
    let start_time = std::time::Instant::now();
    
    // Run all test suites
    match run_all_test_suites().await {
        Ok(()) => {
            let total_time = start_time.elapsed();
            println!("\n🎉 ALL TESTS PASSED! 🎉");
            println!("Total execution time: {:?}", total_time);
            println!("\nThe CTF Assistant is ready for production use!");
        }
        Err(e) => {
            let total_time = start_time.elapsed();
            eprintln!("\n❌ TESTS FAILED! ❌");
            eprintln!("Error: {}", e);
            eprintln!("Total execution time: {:?}", total_time);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

async fn run_all_test_suites() -> Result<()> {
    // 1. Integration Tests
    println!("📋 Phase 1: Integration Tests");
    println!("-----------------------------");
    integration_tests::run_all_integration_tests().await?;
    
    println!("\n📊 Phase 2: Interface Parity Tests");
    println!("----------------------------------");
    interface_parity_tests::run_all_interface_parity_tests().await?;
    
    println!("\n⚡ Phase 3: Performance Tests");
    println!("-----------------------------");
    performance_tests::run_all_performance_tests().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_complete_integration_suite() -> Result<()> {
        // This test runs the complete integration suite
        // It's designed to be run with `cargo test --test test_runner`
        run_all_test_suites().await
    }
}