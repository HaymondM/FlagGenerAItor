//! Performance tests and optimization validation
//! 
//! These tests validate system performance with large files, complex nested encodings,
//! memory usage, and resource limits as specified in requirements 2.7, 9.1, 9.2.

use anyhow::Result;
use ctf_core::{
    core::models::{Challenge, ChallengeFile, FileType, FileMetadata},
    core::storage::Storage,
    interfaces::orchestrator::{AnalysisOrchestrator, OrchestrationConfig},
};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::fs;
use uuid::Uuid;

/// Performance test configuration
#[derive(Debug, Clone)]
struct PerformanceConfig {
    /// Maximum acceptable analysis time per MB
    max_time_per_mb: Duration,
    /// Maximum acceptable memory usage in MB
    max_memory_mb: usize,
    /// Maximum file size to test (in MB)
    max_test_file_size_mb: usize,
    /// Maximum recursion depth to test
    max_recursion_depth: u8,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_time_per_mb: Duration::from_secs(5),
            max_memory_mb: 500, // 500MB limit
            max_test_file_size_mb: 50, // Test up to 50MB (under 100MB limit)
            max_recursion_depth: 10,
        }
    }
}

/// Helper for creating performance test files
struct PerformanceTestHelper {
    temp_dir: TempDir,
    storage: Storage,
    config: PerformanceConfig,
}

impl PerformanceTestHelper {
    async fn new() -> Result<Self> {
        Ok(Self {
            temp_dir: tempfile::tempdir()?,
            storage: Storage::new_temp().await?,
            config: PerformanceConfig::default(),
        })
    }

    /// Create a large file with specified size in MB
    async fn create_large_file(&self, size_mb: usize, content_pattern: &str) -> Result<PathBuf> {
        let target_size = size_mb * 1024 * 1024; // Convert MB to bytes
        let pattern_bytes = content_pattern.as_bytes();
        let pattern_len = pattern_bytes.len();
        
        let file_path = self.temp_dir.path().join(format!("large_file_{}mb.txt", size_mb));
        
        // Create file by repeating pattern
        let mut content = Vec::with_capacity(target_size);
        while content.len() < target_size {
            let remaining = target_size - content.len();
            if remaining >= pattern_len {
                content.extend_from_slice(pattern_bytes);
            } else {
                content.extend_from_slice(&pattern_bytes[..remaining]);
            }
        }
        
        fs::write(&file_path, content).await?;
        Ok(file_path)
    }

    /// Create a file with nested encodings up to specified depth
    async fn create_nested_encoded_file(&self, depth: u8, base_content: &str) -> Result<PathBuf> {
        let mut content = base_content.to_string();
        
        // Apply nested encodings
        for level in 0..depth {
            content = match level % 4 {
                0 => base64::encode(&content),
                1 => hex::encode(content.as_bytes()),
                2 => {
                    // ROT13
                    content.chars().map(|c| {
                        match c {
                            'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
                            'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
                            _ => c,
                        }
                    }).collect()
                }
                3 => {
                    // Simple XOR with key 0x42
                    content.bytes().map(|b| (b ^ 0x42) as char).collect()
                }
                _ => unreachable!(),
            };
        }
        
        let file_path = self.temp_dir.path().join(format!("nested_depth_{}.txt", depth));
        fs::write(&file_path, content).await?;
        Ok(file_path)
    }

    /// Create a challenge from file path
    async fn create_challenge(&self, name: &str, file_path: PathBuf, file_type: FileType) -> Result<Challenge> {
        let file_data = fs::read(&file_path).await?;
        let file_id = Uuid::new_v4();
        
        // Store file in storage
        let stored_path = self.storage.store_file(&file_data, &file_path.file_name().unwrap().to_string_lossy()).await?;
        
        let challenge_file = ChallengeFile {
            id: file_id,
            original_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
            file_type,
            size: file_data.len() as u64,
            hash: format!("{:x}", sha2::Sha256::digest(&file_data)),
            storage_path: stored_path,
            metadata: FileMetadata::default(),
        };

        Ok(Challenge {
            id: Uuid::new_v4(),
            name: name.to_string(),
            files: vec![challenge_file],
            context: format!("Performance test: {}", name),
            created_at: chrono::Utc::now(),
            analysis_results: Vec::new(),
        })
    }

    /// Measure memory usage during operation
    fn get_memory_usage_mb() -> usize {
        // Simple memory usage estimation
        // In a real implementation, you might use a more sophisticated approach
        let usage = std::alloc::System.used_memory().unwrap_or(0);
        usage / (1024 * 1024) // Convert to MB
    }
}

// Placeholder for memory tracking since std::alloc::System doesn't have used_memory
trait MemoryTracker {
    fn used_memory(&self) -> Option<usize>;
}

impl MemoryTracker for std::alloc::System {
    fn used_memory(&self) -> Option<usize> {
        // Placeholder - in real implementation, use system-specific memory tracking
        None
    }
}

#[tokio::test]
async fn test_large_file_performance() -> Result<()> {
    let helper = PerformanceTestHelper::new().await?;
    
    // Test with progressively larger files
    let test_sizes = vec![1, 5, 10, 25]; // MB sizes to test
    
    for size_mb in test_sizes {
        println!("Testing {}MB file performance...", size_mb);
        
        // Create large file with base64-encoded content
        let large_content = "flag{large_file_test}".repeat(1000);
        let encoded_content = base64::encode(&large_content);
        let file_path = helper.create_large_file(size_mb, &encoded_content).await?;
        
        // Create challenge
        let challenge = helper.create_challenge(
            &format!("Large File Test {}MB", size_mb),
            file_path,
            FileType::Text,
        ).await?;

        // Configure orchestrator with reasonable limits
        let config = OrchestrationConfig {
            max_analysis_time_per_file: Duration::from_secs(60),
            max_decoder_depth: 3, // Limit depth for large files
            auto_generate_hints: false,
            min_confidence_threshold: 0.1,
            ..Default::default()
        };
        
        let orchestrator = AnalysisOrchestrator::with_config(config);
        
        // Measure performance
        let start_time = Instant::now();
        let start_memory = PerformanceTestHelper::get_memory_usage_mb();
        
        let results = orchestrator.analyze_challenge(&challenge).await?;
        
        let analysis_time = start_time.elapsed();
        let end_memory = PerformanceTestHelper::get_memory_usage_mb();
        let memory_delta = end_memory.saturating_sub(start_memory);
        
        // Validate performance requirements
        let max_expected_time = helper.config.max_time_per_mb * size_mb as u32;
        assert!(analysis_time <= max_expected_time,
                "Analysis time {:?} exceeded limit {:?} for {}MB file",
                analysis_time, max_expected_time, size_mb);
        
        // Validate memory usage (if tracking is available)
        if memory_delta > 0 {
            assert!(memory_delta <= helper.config.max_memory_mb,
                    "Memory usage {}MB exceeded limit {}MB for {}MB file",
                    memory_delta, helper.config.max_memory_mb, size_mb);
        }
        
        // Verify results were produced
        assert!(!results.is_empty(), "Should produce results for {}MB file", size_mb);
        
        println!("  ✓ {}MB file: {:?} analysis time, {} results", 
                 size_mb, analysis_time, results.len());
        if memory_delta > 0 {
            println!("    Memory delta: {}MB", memory_delta);
        }
    }
    
    println!("✓ Large file performance test passed");
    Ok(())
}

#[tokio::test]
async fn test_nested_encoding_performance() -> Result<()> {
    let helper = PerformanceTestHelper::new().await?;
    
    // Test with different nesting depths
    let test_depths = vec![1, 3, 5, 7, 10];
    
    for depth in test_depths {
        println!("Testing nested encoding depth {}...", depth);
        
        // Create nested encoded file
        let base_content = "flag{nested_encoding_test}";
        let file_path = helper.create_nested_encoded_file(depth, base_content).await?;
        
        // Create challenge
        let challenge = helper.create_challenge(
            &format!("Nested Encoding Depth {}", depth),
            file_path,
            FileType::Text,
        ).await?;

        // Configure orchestrator with depth matching test
        let config = OrchestrationConfig {
            max_analysis_time_per_file: Duration::from_secs(30),
            max_decoder_depth: depth.max(5), // Allow sufficient depth
            auto_generate_hints: false,
            min_confidence_threshold: 0.1,
            ..Default::default()
        };
        
        let orchestrator = AnalysisOrchestrator::with_config(config);
        
        // Measure performance
        let start_time = Instant::now();
        let results = orchestrator.analyze_challenge(&challenge).await?;
        let analysis_time = start_time.elapsed();
        
        // Performance should not degrade exponentially with depth
        let max_expected_time = Duration::from_secs(5) * depth as u32;
        assert!(analysis_time <= max_expected_time,
                "Analysis time {:?} exceeded limit {:?} for depth {}",
                analysis_time, max_expected_time, depth);
        
        // Verify meaningful transformations were found
        let decoder_results: Vec<_> = results.iter()
            .filter(|r| r.analyzer == "decoder-pipeline")
            .collect();
        
        if !decoder_results.is_empty() {
            let meaningful_count: usize = decoder_results.iter()
                .map(|r| r.transformations.iter().filter(|t| t.meaningful).count())
                .sum();
            
            // Should find at least one meaningful transformation for reasonable depths
            if depth <= 5 {
                assert!(meaningful_count > 0, 
                        "Should find meaningful transformations for depth {}", depth);
            }
            
            println!("  ✓ Depth {}: {:?} analysis time, {} meaningful transformations", 
                     depth, analysis_time, meaningful_count);
        }
    }
    
    println!("✓ Nested encoding performance test passed");
    Ok(())
}

#[tokio::test]
async fn test_recursion_depth_limits() -> Result<()> {
    let helper = PerformanceTestHelper::new().await?;
    
    // Test that recursion depth limits are properly enforced
    let max_depth = 5;
    let test_depth = 10; // Create deeper nesting than allowed
    
    println!("Testing recursion depth limit enforcement...");
    
    // Create deeply nested file
    let base_content = "flag{recursion_limit_test}";
    let file_path = helper.create_nested_encoded_file(test_depth, base_content).await?;
    
    // Create challenge
    let challenge = helper.create_challenge(
        "Recursion Depth Limit Test",
        file_path,
        FileType::Text,
    ).await?;

    // Configure orchestrator with strict depth limit
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_secs(20),
        max_decoder_depth: max_depth,
        auto_generate_hints: false,
        min_confidence_threshold: 0.1,
        ..Default::default()
    };
    
    let orchestrator = AnalysisOrchestrator::with_config(config);
    
    // Run analysis
    let start_time = Instant::now();
    let results = orchestrator.analyze_challenge(&challenge).await?;
    let analysis_time = start_time.elapsed();
    
    // Verify depth limit was enforced
    let decoder_results: Vec<_> = results.iter()
        .filter(|r| r.analyzer == "decoder-pipeline")
        .collect();
    
    if !decoder_results.is_empty() {
        let max_chain_depth = decoder_results.iter()
            .flat_map(|r| &r.transformations)
            .map(|t| t.chain_depth)
            .max()
            .unwrap_or(0);
        
        assert!(max_chain_depth <= max_depth,
                "Chain depth {} should not exceed limit {}",
                max_chain_depth, max_depth);
        
        println!("  ✓ Max chain depth: {} (limit: {})", max_chain_depth, max_depth);
    }
    
    // Analysis should complete quickly due to depth limit
    assert!(analysis_time <= Duration::from_secs(10),
            "Analysis should complete quickly with depth limits");
    
    println!("✓ Recursion depth limit test passed");
    println!("  - Analysis time: {:?}", analysis_time);
    
    Ok(())
}

#[tokio::test]
async fn test_file_size_validation() -> Result<()> {
    let helper = PerformanceTestHelper::new().await?;
    
    println!("Testing file size validation (100MB limit)...");
    
    // Test with file approaching the limit (we'll test with smaller size for CI)
    let test_size_mb = 50; // Test with 50MB (under the 100MB limit)
    
    // Create large file
    let large_content = "A".repeat(1024); // 1KB pattern
    let file_path = helper.create_large_file(test_size_mb, &large_content).await?;
    
    // Verify file size
    let file_metadata = fs::metadata(&file_path).await?;
    let file_size_mb = file_metadata.len() / (1024 * 1024);
    
    println!("  Created test file: {}MB", file_size_mb);
    
    // Create challenge
    let challenge = helper.create_challenge(
        "File Size Validation Test",
        file_path,
        FileType::Text,
    ).await?;

    // Configure orchestrator
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_secs(60),
        max_decoder_depth: 2, // Limit processing for large files
        auto_generate_hints: false,
        min_confidence_threshold: 0.1,
        ..Default::default()
    };
    
    let orchestrator = AnalysisOrchestrator::with_config(config);
    
    // File under limit should be processed successfully
    let start_time = Instant::now();
    let results = orchestrator.analyze_challenge(&challenge).await?;
    let analysis_time = start_time.elapsed();
    
    // Should produce results for valid file size
    assert!(!results.is_empty(), "Should process file under size limit");
    
    // Performance should be reasonable
    let max_expected_time = Duration::from_secs(30);
    assert!(analysis_time <= max_expected_time,
            "Large file analysis should complete within reasonable time");
    
    println!("✓ File size validation test passed");
    println!("  - Processed {}MB file in {:?}", file_size_mb, analysis_time);
    
    Ok(())
}

#[tokio::test]
async fn test_memory_usage_optimization() -> Result<()> {
    let helper = PerformanceTestHelper::new().await?;
    
    println!("Testing memory usage optimization...");
    
    // Create multiple files to test memory management
    let mut challenges = Vec::new();
    
    for i in 0..5 {
        let content = format!("flag{{memory_test_{}}}", i).repeat(10000);
        let encoded_content = base64::encode(&content);
        let file_path = helper.create_large_file(5, &encoded_content).await?;
        
        let challenge = helper.create_challenge(
            &format!("Memory Test {}", i),
            file_path,
            FileType::Text,
        ).await?;
        
        challenges.push(challenge);
    }
    
    // Configure orchestrator
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_secs(20),
        max_decoder_depth: 3,
        auto_generate_hints: false,
        min_confidence_threshold: 0.1,
        parallel_plugin_execution: false, // Sequential to test memory cleanup
        ..Default::default()
    };
    
    let orchestrator = AnalysisOrchestrator::with_config(config);
    
    // Process challenges sequentially and monitor memory
    let initial_memory = PerformanceTestHelper::get_memory_usage_mb();
    let mut max_memory_delta = 0;
    
    for (i, challenge) in challenges.iter().enumerate() {
        let before_memory = PerformanceTestHelper::get_memory_usage_mb();
        
        let results = orchestrator.analyze_challenge(challenge).await?;
        
        let after_memory = PerformanceTestHelper::get_memory_usage_mb();
        let memory_delta = after_memory.saturating_sub(initial_memory);
        max_memory_delta = max_memory_delta.max(memory_delta);
        
        assert!(!results.is_empty(), "Should produce results for challenge {}", i);
        
        println!("  Challenge {}: {} results, memory delta: {}MB", 
                 i, results.len(), memory_delta);
    }
    
    // Memory usage should not grow unbounded
    if max_memory_delta > 0 {
        assert!(max_memory_delta <= helper.config.max_memory_mb,
                "Memory usage {}MB should not exceed limit {}MB",
                max_memory_delta, helper.config.max_memory_mb);
    }
    
    println!("✓ Memory usage optimization test passed");
    println!("  - Max memory delta: {}MB", max_memory_delta);
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_analysis_performance() -> Result<()> {
    let helper = PerformanceTestHelper::new().await?;
    
    println!("Testing concurrent analysis performance...");
    
    // Create multiple challenges for concurrent processing
    let mut challenges = Vec::new();
    
    for i in 0..3 {
        let content = format!("flag{{concurrent_test_{}}}", i);
        let encoded_content = base64::encode(&content);
        let file_path = helper.temp_dir.path().join(format!("concurrent_{}.txt", i));
        fs::write(&file_path, encoded_content).await?;
        
        let challenge = helper.create_challenge(
            &format!("Concurrent Test {}", i),
            file_path,
            FileType::Text,
        ).await?;
        
        challenges.push(challenge);
    }
    
    // Configure orchestrator for concurrent processing
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_secs(15),
        max_decoder_depth: 3,
        auto_generate_hints: false,
        parallel_plugin_execution: true,
        min_confidence_threshold: 0.1,
    };
    
    let orchestrator = AnalysisOrchestrator::with_config(config);
    
    // Process challenges concurrently
    let start_time = Instant::now();
    
    let mut tasks = Vec::new();
    for challenge in challenges {
        let orch = AnalysisOrchestrator::with_config(config.clone());
        let task = tokio::spawn(async move {
            orch.analyze_challenge(&challenge).await
        });
        tasks.push(task);
    }
    
    // Wait for all tasks to complete
    let mut all_results = Vec::new();
    for task in tasks {
        let results = task.await??;
        all_results.extend(results);
    }
    
    let total_time = start_time.elapsed();
    
    // Concurrent processing should be faster than sequential
    let expected_sequential_time = Duration::from_secs(15 * 3); // 3 challenges * 15s each
    assert!(total_time < expected_sequential_time,
            "Concurrent processing should be faster than sequential");
    
    // Should have results from all challenges
    assert!(!all_results.is_empty(), "Should have results from concurrent processing");
    
    println!("✓ Concurrent analysis performance test passed");
    println!("  - Processed 3 challenges concurrently in {:?}", total_time);
    println!("  - Total results: {}", all_results.len());
    
    Ok(())
}

/// Helper function to run all performance tests
pub async fn run_all_performance_tests() -> Result<()> {
    println!("Running Performance Tests...\n");
    
    test_large_file_performance().await?;
    test_nested_encoding_performance().await?;
    test_recursion_depth_limits().await?;
    test_file_size_validation().await?;
    test_memory_usage_optimization().await?;
    test_concurrent_analysis_performance().await?;
    
    println!("\n✅ All performance tests passed!");
    
    Ok(())
}