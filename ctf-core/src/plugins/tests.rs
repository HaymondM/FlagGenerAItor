//! Tests for the plugin system

#[cfg(test)]
mod tests {
    use crate::plugins::{PluginManager, AnalysisContext};
    use crate::core::models::FileType;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_plugin_manager_creation() {
        let manager = PluginManager::new();
        assert_eq!(manager.plugin_count(), 0);
    }

    #[tokio::test]
    async fn test_builtin_plugins_loading() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        assert_eq!(manager.plugin_count(), 3);
        
        // Check that all expected plugins are loaded
        assert!(manager.has_plugin("cryptography"));
        assert!(manager.has_plugin("reverse-engineering"));
        assert!(manager.has_plugin("web-analysis"));
    }

    #[tokio::test]
    async fn test_plugin_capabilities() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        let capabilities = manager.get_capabilities();
        
        assert_eq!(capabilities.len(), 3);
        
        // Find cryptography plugin
        let crypto_plugin = capabilities.iter()
            .find(|c| c.name == "cryptography")
            .expect("Cryptography plugin should be present");
        
        assert_eq!(crypto_plugin.version, "1.0.0");
        assert!(crypto_plugin.supported_types.contains(&FileType::Text));
        assert!(crypto_plugin.supported_types.contains(&FileType::Binary));
    }

    #[tokio::test]
    async fn test_plugin_execution_for_text_file() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        
        let context = AnalysisContext::new(
            FileType::Text,
            "test.txt".to_string(),
            Uuid::new_v4(),
            100,
        );
        
        let test_data = b"This is some test data with potential patterns";
        let results = manager.execute_plugins(test_data, &context).await.unwrap();
        
        // Should have results from cryptography and web analysis plugins
        assert!(!results.is_empty());
        
        // Check that we have results from expected plugins
        let plugin_names: Vec<&String> = results.iter().map(|r| &r.analyzer).collect();
        assert!(plugin_names.contains(&&"cryptography".to_string()));
        assert!(plugin_names.contains(&&"web-analysis".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_execution_for_binary_file() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        
        let context = AnalysisContext::new(
            FileType::Binary,
            "test.bin".to_string(),
            Uuid::new_v4(),
            200,
        );
        
        // Create some binary data with strings
        let test_data = b"\x7fELF\x00\x00\x00\x00Hello World\x00flag{test}\x00password123\x00";
        let results = manager.execute_plugins(test_data, &context).await.unwrap();
        
        // Should have results from cryptography and reverse engineering plugins
        assert!(!results.is_empty());
        
        let plugin_names: Vec<&String> = results.iter().map(|r| &r.analyzer).collect();
        assert!(plugin_names.contains(&&"cryptography".to_string()));
        assert!(plugin_names.contains(&&"reverse-engineering".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_execution_stats() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        let stats = manager.get_execution_stats();
        
        assert_eq!(stats.total_plugins, 3);
        
        // Check that we have plugins for different file types
        assert!(stats.plugins_by_type.get(&FileType::Text).unwrap_or(&0) > &0);
        assert!(stats.plugins_by_type.get(&FileType::Binary).unwrap_or(&0) > &0);
    }

    #[tokio::test]
    async fn test_plugin_execution_by_name() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        
        let context = AnalysisContext::new(
            FileType::Text,
            "test.txt".to_string(),
            Uuid::new_v4(),
            50,
        );
        
        let test_data = b"Some test data";
        let result = manager.execute_plugin_by_name("cryptography", test_data, &context).await.unwrap();
        
        assert_eq!(result.analyzer, "cryptography");
    }

    #[tokio::test]
    async fn test_plugin_execution_unsupported_type() {
        let manager = PluginManager::with_builtin_plugins().await.unwrap();
        
        let context = AnalysisContext::new(
            FileType::Pcap, // Not supported by cryptography plugin
            "test.pcap".to_string(),
            Uuid::new_v4(),
            50,
        );
        
        let test_data = b"Some test data";
        let result = manager.execute_plugin_by_name("cryptography", test_data, &context).await;
        
        assert!(result.is_err());
    }
}