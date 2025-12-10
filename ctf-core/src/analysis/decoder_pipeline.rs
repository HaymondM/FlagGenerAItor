//! Decoder pipeline for automated transformations

use crate::core::models::{TransformationResult, TransformationType, MAX_TRANSFORMATION_DEPTH};
use anyhow::Result;
use base64::prelude::*;
use std::collections::HashSet;

pub struct DecoderPipeline {
    /// Track attempted transformations to avoid infinite loops
    attempted_transformations: HashSet<String>,
}

#[derive(Debug, Clone)]
struct TransformationChain {
    transformations: Vec<TransformationType>,
    confidence_score: f32,
    final_output: String,
}

impl DecoderPipeline {
    pub fn new() -> Self {
        Self {
            attempted_transformations: HashSet::new(),
        }
    }
    
    /// Apply all transformations to input data
    pub async fn process(&self, data: &[u8]) -> Result<Vec<TransformationResult>> {
        self.apply_all_transformations(data, 0).await
    }
    
    /// Apply recursive transformations up to max depth
    pub async fn process_recursive(&self, data: &[u8], max_depth: u8) -> Result<Vec<TransformationResult>> {
        let max_depth = std::cmp::min(max_depth, MAX_TRANSFORMATION_DEPTH);
        let mut all_results = Vec::new();
        let mut transformation_chains = Vec::new();
        let mut work_queue = vec![(data.to_vec(), 0u8, Vec::<TransformationType>::new())];
        
        // Process iteratively to avoid async recursion issues
        while let Some((current_data, current_depth, current_chain)) = work_queue.pop() {
            if current_depth >= max_depth {
                continue;
            }
            
            // Apply all transformations at current depth
            let current_results = self.apply_all_transformations(&current_data, current_depth).await?;
            
            for result in current_results {
                all_results.push(result.clone());
                
                // If transformation was successful and meaningful, add to work queue
                if result.success && result.meaningful {
                    if let Ok(decoded_data) = self.parse_output_preview(&result.output_preview) {
                        // Create new chain with this transformation
                        let mut new_chain = current_chain.clone();
                        new_chain.push(result.transformation.clone());
                        
                        // Check if we've seen this transformation chain before to avoid loops
                        let chain_signature = self.create_chain_signature(&new_chain);
                        if !self.has_seen_chain(&chain_signature, &transformation_chains) {
                            // Record this transformation chain
                            transformation_chains.push(TransformationChain {
                                transformations: new_chain.clone(),
                                confidence_score: self.calculate_transformation_confidence(&result),
                                final_output: result.output_preview.clone(),
                            });
                            
                            // Add to work queue for next iteration
                            work_queue.push((decoded_data, current_depth + 1, new_chain));
                        }
                    }
                }
            }
        }
        
        // Sort results by confidence and depth for better presentation
        all_results.sort_by(|a, b| {
            // First by meaningfulness, then by depth (shallower first), then by confidence
            match (b.meaningful, a.meaningful) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => {
                    match a.chain_depth.cmp(&b.chain_depth) {
                        std::cmp::Ordering::Equal => {
                            // For same depth, prefer higher confidence transformations
                            let a_confidence = self.calculate_transformation_confidence(&a);
                            let b_confidence = self.calculate_transformation_confidence(&b);
                            b_confidence.partial_cmp(&a_confidence).unwrap_or(std::cmp::Ordering::Equal)
                        }
                        other => other,
                    }
                }
            }
        });
        
        Ok(all_results)
    }
    
    /// Calculate confidence score for a transformation result
    fn calculate_transformation_confidence(&self, result: &TransformationResult) -> f32 {
        let mut confidence = 0.0;
        
        // Base confidence for successful transformation
        if result.success {
            confidence += 0.3;
        }
        
        // Higher confidence for meaningful output
        if result.meaningful {
            confidence += 0.4;
        }
        
        // Bonus for certain transformation types that are commonly used
        match result.transformation {
            TransformationType::Base64Decode => confidence += 0.2,
            TransformationType::HexToAscii => confidence += 0.15,
            TransformationType::Rot13 => confidence += 0.1,
            TransformationType::GzipDecompress | TransformationType::ZlibDecompress => confidence += 0.25,
            _ => confidence += 0.05,
        }
        
        // Penalty for deeper chains (prefer simpler solutions)
        confidence -= result.chain_depth as f32 * 0.05;
        
        confidence.clamp(0.0, 1.0)
    }
    
    /// Create a signature for a transformation chain to detect loops
    fn create_chain_signature(&self, chain: &[TransformationType]) -> String {
        chain.iter()
            .map(|t| format!("{:?}", t))
            .collect::<Vec<_>>()
            .join("->")
    }
    
    /// Check if we've seen this transformation chain before
    fn has_seen_chain(&self, signature: &str, chains: &[TransformationChain]) -> bool {
        chains.iter().any(|chain| {
            self.create_chain_signature(&chain.transformations) == signature
        })
    }
    
    /// Apply all available transformations
    pub async fn apply_all_transformations(&self, data: &[u8], depth: u8) -> Result<Vec<TransformationResult>> {
        let mut results = Vec::new();
        
        // Apply base encoding transformations
        let base_results = self.apply_base_encodings(data, depth).await?;
        results.extend(base_results);
        
        // Apply cipher transformations
        let cipher_results = self.apply_cipher_transformations(data, depth).await?;
        results.extend(cipher_results);
        
        // Apply compression transformations
        let compression_results = self.apply_compression_transformations(data, depth).await?;
        results.extend(compression_results);
        
        Ok(results)
    }
    
    /// Apply base encoding transformations (Base64, Base32, Base58, Hex, Binary)
    async fn apply_base_encodings(&self, data: &[u8], depth: u8) -> Result<Vec<TransformationResult>> {
        let mut results = Vec::new();
        let input_str = String::from_utf8_lossy(data);
        let input_preview = self.create_preview(&input_str);
        
        // Base64 decoding
        if let Some(result) = self.try_base64_decode(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        // Base32 decoding
        if let Some(result) = self.try_base32_decode(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        // Base58 decoding
        if let Some(result) = self.try_base58_decode(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        // Hex to ASCII conversion
        if let Some(result) = self.try_hex_to_ascii(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        // Binary to text conversion
        if let Some(result) = self.try_binary_to_text(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Apply cipher transformations (ROT13, ROT47, Caesar, XOR)
    pub async fn apply_cipher_transformations(&self, data: &[u8], depth: u8) -> Result<Vec<TransformationResult>> {
        let mut results = Vec::new();
        let input_str = String::from_utf8_lossy(data);
        let input_preview = self.create_preview(&input_str);
        
        // ROT13 transformation
        if let Some(result) = self.try_rot13(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        // ROT47 transformation
        if let Some(result) = self.try_rot47(&input_str, &input_preview, depth).await {
            results.push(result);
        }
        
        // Caesar cipher with all possible shifts (1-25)
        for shift in 1..26 {
            if let Some(result) = self.try_caesar(&input_str, &input_preview, shift, depth).await {
                results.push(result);
            }
        }
        
        // XOR brute force with single-byte keys (1-255)
        for key in 1..=255 {
            if let Some(result) = self.try_xor_brute_force(data, &input_preview, key, depth).await {
                results.push(result);
            }
        }
        
        Ok(results)
    }
    
    /// Apply compression transformations (gzip, zlib)
    async fn apply_compression_transformations(&self, data: &[u8], depth: u8) -> Result<Vec<TransformationResult>> {
        let mut results = Vec::new();
        let input_preview = self.create_preview(&String::from_utf8_lossy(data));
        
        // Try gzip decompression
        if let Some(result) = self.try_gzip_decompress(data, &input_preview, depth).await {
            results.push(result);
        }
        
        // Try zlib decompression
        if let Some(result) = self.try_zlib_decompress(data, &input_preview, depth).await {
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Try gzip decompression
    async fn try_gzip_decompress(&self, input: &[u8], input_preview: &str, depth: u8) -> Option<TransformationResult> {
        use flate2::read::GzDecoder;
        use std::io::Read;
        
        // Check if data starts with gzip magic bytes (1f 8b)
        if input.len() < 2 || input[0] != 0x1f || input[1] != 0x8b {
            return None;
        }
        
        let mut decoder = GzDecoder::new(input);
        let mut decompressed = Vec::new();
        
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {
                let output_str = String::from_utf8_lossy(&decompressed);
                let output_preview = self.create_preview(&output_str);
                let meaningful = self.is_meaningful_output(&output_str);
                
                TransformationResult::new(
                    TransformationType::GzipDecompress,
                    input_preview.to_string(),
                    output_preview,
                    true,
                    meaningful,
                    depth,
                ).ok()
            }
            Err(e) => {
                TransformationResult::new(
                    TransformationType::GzipDecompress,
                    input_preview.to_string(),
                    format!("Gzip decompression failed: {}", e),
                    false,
                    false,
                    depth,
                ).ok()
            }
        }
    }
    
    /// Try zlib decompression
    async fn try_zlib_decompress(&self, input: &[u8], input_preview: &str, depth: u8) -> Option<TransformationResult> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        
        // Check if data starts with zlib magic bytes (78 01, 78 9c, 78 da, etc.)
        if input.len() < 2 || input[0] != 0x78 {
            return None;
        }
        
        let mut decoder = ZlibDecoder::new(input);
        let mut decompressed = Vec::new();
        
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {
                let output_str = String::from_utf8_lossy(&decompressed);
                let output_preview = self.create_preview(&output_str);
                let meaningful = self.is_meaningful_output(&output_str);
                
                TransformationResult::new(
                    TransformationType::ZlibDecompress,
                    input_preview.to_string(),
                    output_preview,
                    true,
                    meaningful,
                    depth,
                ).ok()
            }
            Err(e) => {
                TransformationResult::new(
                    TransformationType::ZlibDecompress,
                    input_preview.to_string(),
                    format!("Zlib decompression failed: {}", e),
                    false,
                    false,
                    depth,
                ).ok()
            }
        }
    }
    
    /// Try ROT13 transformation
    async fn try_rot13(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Only apply to text that contains letters
        if !input.chars().any(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        
        let output = self.apply_rot13(input);
        let output_preview = self.create_preview(&output);
        let meaningful = self.is_meaningful_output(&output);
        
        // Always return the result for ROT13, even if not meaningful (for testing)
        TransformationResult::new(
            TransformationType::Rot13,
            input_preview.to_string(),
            output_preview,
            true,
            meaningful,
            depth,
        ).ok()
    }
    
    /// Try ROT47 transformation
    async fn try_rot47(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Only apply to text that contains printable ASCII characters
        if !input.chars().any(|c| c.is_ascii_graphic()) {
            return None;
        }
        
        let output = self.apply_rot47(input);
        let output_preview = self.create_preview(&output);
        let meaningful = self.is_meaningful_output(&output);
        
        TransformationResult::new(
            TransformationType::Rot47,
            input_preview.to_string(),
            output_preview,
            true,
            meaningful,
            depth,
        ).ok()
    }
    
    /// Try Caesar cipher with specific shift
    async fn try_caesar(&self, input: &str, input_preview: &str, shift: u8, depth: u8) -> Option<TransformationResult> {
        // Only apply to text that contains letters
        if !input.chars().any(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        
        let output = self.apply_caesar(input, shift);
        let output_preview = self.create_preview(&output);
        let meaningful = self.is_meaningful_output(&output);
        
        // Only return meaningful results to avoid noise
        if !meaningful {
            return None;
        }
        
        TransformationResult::new(
            TransformationType::Caesar { shift },
            input_preview.to_string(),
            output_preview,
            true,
            meaningful,
            depth,
        ).ok()
    }
    
    /// Try XOR brute force with single-byte key
    async fn try_xor_brute_force(&self, input: &[u8], input_preview: &str, key: u8, depth: u8) -> Option<TransformationResult> {
        let output_bytes: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
        let output_str = String::from_utf8_lossy(&output_bytes);
        let output_preview = self.create_preview(&output_str);
        let meaningful = self.is_meaningful_output(&output_str);
        
        // Only return meaningful results to avoid noise
        if !meaningful {
            return None;
        }
        
        TransformationResult::new(
            TransformationType::XorBruteForce { key },
            input_preview.to_string(),
            output_preview,
            true,
            meaningful,
            depth,
        ).ok()
    }
    
    /// Apply ROT13 transformation
    fn apply_rot13(&self, input: &str) -> String {
        input.chars().map(|c| {
            match c {
                'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
                'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
                _ => c,
            }
        }).collect()
    }
    
    /// Apply ROT47 transformation
    fn apply_rot47(&self, input: &str) -> String {
        input.chars().map(|c| {
            if c.is_ascii_graphic() && c as u8 >= 33 && c as u8 <= 126 {
                let shifted = ((c as u8 - 33 + 47) % 94 + 33) as char;
                shifted
            } else {
                c
            }
        }).collect()
    }
    
    /// Apply Caesar cipher with specific shift
    fn apply_caesar(&self, input: &str, shift: u8) -> String {
        input.chars().map(|c| {
            match c {
                'a'..='z' => ((c as u8 - b'a' + shift) % 26 + b'a') as char,
                'A'..='Z' => ((c as u8 - b'A' + shift) % 26 + b'A') as char,
                _ => c,
            }
        }).collect()
    }
    
    /// Try Base64 decoding
    async fn try_base64_decode(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Check if input looks like Base64 (alphanumeric + / + = padding)
        if !self.looks_like_base64(input) {
            return None;
        }
        
        match base64::prelude::BASE64_STANDARD.decode(input.trim()) {
            Ok(decoded) => {
                let output_str = String::from_utf8_lossy(&decoded);
                let output_preview = self.create_preview(&output_str);
                let meaningful = self.is_meaningful_output(&output_str);
                
                TransformationResult::new(
                    TransformationType::Base64Decode,
                    input_preview.to_string(),
                    output_preview,
                    true,
                    meaningful,
                    depth,
                ).ok()
            }
            Err(_) => {
                TransformationResult::new(
                    TransformationType::Base64Decode,
                    input_preview.to_string(),
                    "Failed to decode".to_string(),
                    false,
                    false,
                    depth,
                ).ok()
            }
        }
    }
    
    /// Try Base32 decoding
    async fn try_base32_decode(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Check if input looks like Base32 (A-Z, 2-7, = padding)
        if !self.looks_like_base32(input) {
            return None;
        }
        
        match base32::decode(base32::Alphabet::RFC4648 { padding: true }, input.trim()) {
            Some(decoded) => {
                let output_str = String::from_utf8_lossy(&decoded);
                let output_preview = self.create_preview(&output_str);
                let meaningful = self.is_meaningful_output(&output_str);
                
                TransformationResult::new(
                    TransformationType::Base32Decode,
                    input_preview.to_string(),
                    output_preview,
                    true,
                    meaningful,
                    depth,
                ).ok()
            }
            None => {
                TransformationResult::new(
                    TransformationType::Base32Decode,
                    input_preview.to_string(),
                    "Failed to decode".to_string(),
                    false,
                    false,
                    depth,
                ).ok()
            }
        }
    }
    
    /// Try Base58 decoding
    async fn try_base58_decode(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Check if input looks like Base58 (no 0, O, I, l)
        if !self.looks_like_base58(input) {
            return None;
        }
        
        match bs58::decode(input.trim()).into_vec() {
            Ok(decoded) => {
                let output_str = String::from_utf8_lossy(&decoded);
                let output_preview = self.create_preview(&output_str);
                let meaningful = self.is_meaningful_output(&output_str);
                
                TransformationResult::new(
                    TransformationType::Base58Decode,
                    input_preview.to_string(),
                    output_preview,
                    true,
                    meaningful,
                    depth,
                ).ok()
            }
            Err(_) => {
                TransformationResult::new(
                    TransformationType::Base58Decode,
                    input_preview.to_string(),
                    "Failed to decode".to_string(),
                    false,
                    false,
                    depth,
                ).ok()
            }
        }
    }
    
    /// Try hex to ASCII conversion
    async fn try_hex_to_ascii(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Check if input looks like hex (only 0-9, a-f, A-F)
        if !self.looks_like_hex(input) {
            return None;
        }
        
        match hex::decode(input.trim()) {
            Ok(decoded) => {
                let output_str = String::from_utf8_lossy(&decoded);
                let output_preview = self.create_preview(&output_str);
                let meaningful = self.is_meaningful_output(&output_str);
                
                TransformationResult::new(
                    TransformationType::HexToAscii,
                    input_preview.to_string(),
                    output_preview,
                    true,
                    meaningful,
                    depth,
                ).ok()
            }
            Err(_) => {
                TransformationResult::new(
                    TransformationType::HexToAscii,
                    input_preview.to_string(),
                    "Failed to decode".to_string(),
                    false,
                    false,
                    depth,
                ).ok()
            }
        }
    }
    
    /// Try binary to text conversion
    async fn try_binary_to_text(&self, input: &str, input_preview: &str, depth: u8) -> Option<TransformationResult> {
        // Check if input looks like binary (only 0s and 1s, possibly with spaces)
        if !self.looks_like_binary(input) {
            return None;
        }
        
        let binary_str = input.replace(' ', "");
        
        // Must be multiple of 8 bits
        if binary_str.len() % 8 != 0 {
            return TransformationResult::new(
                TransformationType::BinaryToText,
                input_preview.to_string(),
                "Invalid binary length (not multiple of 8)".to_string(),
                false,
                false,
                depth,
            ).ok();
        }
        
        let mut decoded = Vec::new();
        for chunk in binary_str.as_bytes().chunks(8) {
            let byte_str = std::str::from_utf8(chunk).ok()?;
            match u8::from_str_radix(byte_str, 2) {
                Ok(byte) => decoded.push(byte),
                Err(_) => {
                    return TransformationResult::new(
                        TransformationType::BinaryToText,
                        input_preview.to_string(),
                        "Failed to parse binary".to_string(),
                        false,
                        false,
                        depth,
                    ).ok();
                }
            }
        }
        
        let output_str = String::from_utf8_lossy(&decoded);
        let output_preview = self.create_preview(&output_str);
        let meaningful = self.is_meaningful_output(&output_str);
        
        TransformationResult::new(
            TransformationType::BinaryToText,
            input_preview.to_string(),
            output_preview,
            true,
            meaningful,
            depth,
        ).ok()
    }
    
    /// Check if string looks like Base64
    fn looks_like_base64(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.len() < 4 {
            return false;
        }
        
        // Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
        let base64_chars = trimmed.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        });
        
        // Should be multiple of 4 characters (with padding)
        let proper_length = trimmed.len() % 4 == 0;
        
        // Should have reasonable ratio of padding
        let padding_count = trimmed.chars().filter(|&c| c == '=').count();
        let valid_padding = padding_count <= 2;
        
        base64_chars && proper_length && valid_padding
    }
    
    /// Check if string looks like Base32
    fn looks_like_base32(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.len() < 8 {
            return false;
        }
        
        // Base32 uses A-Z, 2-7, and = for padding
        let base32_chars = trimmed.chars().all(|c| {
            c.is_ascii_uppercase() || ('2'..='7').contains(&c) || c == '='
        });
        
        // Should be multiple of 8 characters (with padding)
        let proper_length = trimmed.len() % 8 == 0;
        
        base32_chars && proper_length
    }
    
    /// Check if string looks like Base58
    fn looks_like_base58(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.len() < 4 {
            return false;
        }
        
        // Base58 excludes 0, O, I, l to avoid confusion
        trimmed.chars().all(|c| {
            c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
        })
    }
    
    /// Check if string looks like hexadecimal
    fn looks_like_hex(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.len() < 2 || trimmed.len() % 2 != 0 {
            return false;
        }
        
        // Hex uses 0-9, a-f, A-F
        trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Check if string looks like binary
    fn looks_like_binary(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.len() < 8 {
            return false;
        }
        
        // Binary uses only 0, 1, and optional spaces
        let binary_chars = trimmed.chars().all(|c| c == '0' || c == '1' || c == ' ');
        
        // After removing spaces, should be multiple of 8
        let clean_binary = trimmed.replace(' ', "");
        let proper_length = clean_binary.len() % 8 == 0 && !clean_binary.is_empty();
        
        binary_chars && proper_length
    }
    
    /// Determine if output appears to be meaningful (human-readable or structured)
    fn is_meaningful_output(&self, output: &str) -> bool {
        if output.trim().is_empty() {
            return false;
        }
        
        // Check for common meaningful patterns
        let has_words = self.has_english_words(output);
        let has_structure = self.has_structured_data(output);
        let printable_ratio = self.calculate_printable_ratio(output);
        
        // Consider meaningful if:
        // - Contains English words
        // - Has structured data patterns
        // - High ratio of printable characters (>= 0.7)
        has_words || has_structure || printable_ratio >= 0.7
    }
    
    /// Check if text contains English words
    fn has_english_words(&self, text: &str) -> bool {
        let common_words = [
            "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use",
            "flag", "ctf", "user", "pass", "admin", "root", "key", "secret", "token", "auth", "login", "password"
        ];
        
        let lowercase_text = text.to_lowercase();
        let words: Vec<&str> = lowercase_text
            .split_whitespace()
            .collect();
        
        let word_count = words.len();
        if word_count == 0 {
            return false;
        }
        
        let common_word_count = words.iter()
            .filter(|word| common_words.contains(word))
            .count();
        
        // Consider meaningful if at least 20% are common words
        common_word_count as f32 / word_count as f32 >= 0.2
    }
    
    /// Check if text has structured data patterns
    fn has_structured_data(&self, text: &str) -> bool {
        // Look for common structured patterns
        text.contains('{') && text.contains('}') || // JSON-like
        text.contains('<') && text.contains('>') || // XML/HTML-like
        text.contains("://") || // URLs
        text.contains('@') && text.contains('.') || // Email-like
        text.contains("-----BEGIN") || // PEM format
        text.contains("=") && text.contains("&") // Query parameters
    }
    
    /// Calculate ratio of printable ASCII characters
    fn calculate_printable_ratio(&self, text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }
        
        let printable_count = text.chars()
            .filter(|c| c.is_ascii() && (c.is_ascii_graphic() || c.is_ascii_whitespace()))
            .count();
        
        printable_count as f32 / text.len() as f32
    }
    
    /// Create a preview string (truncated if too long)
    fn create_preview(&self, text: &str) -> String {
        const MAX_PREVIEW_LENGTH: usize = 200;
        if text.len() > MAX_PREVIEW_LENGTH {
            format!("{}...", &text[..MAX_PREVIEW_LENGTH])
        } else {
            text.to_string()
        }
    }
    
    /// Parse output preview back to bytes for recursive processing
    fn parse_output_preview(&self, preview: &str) -> Result<Vec<u8>> {
        // Remove "..." suffix if present
        let clean_preview = if preview.ends_with("...") {
            &preview[..preview.len() - 3]
        } else {
            preview
        };
        
        Ok(clean_preview.as_bytes().to_vec())
    }
}

impl Default for DecoderPipeline {
    fn default() -> Self {
        Self::new()
    }
}