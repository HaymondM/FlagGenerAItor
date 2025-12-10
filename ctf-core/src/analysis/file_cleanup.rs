//! File cleanup and retention management system

use crate::Result;
use anyhow::anyhow;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// File retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Default retention period for uploaded files
    pub default_retention: Duration,
    /// Retention period for analysis results
    pub analysis_retention: Duration,
    /// Retention period for temporary files
    pub temp_file_retention: Duration,
    /// Maximum total storage size in bytes
    pub max_storage_size: u64,
    /// Whether to enable automatic cleanup
    pub auto_cleanup_enabled: bool,
    /// Cleanup interval in minutes
    pub cleanup_interval_minutes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            default_retention: Duration::days(7),
            analysis_retention: Duration::days(30),
            temp_file_retention: Duration::hours(1),
            max_storage_size: 10 * 1024 * 1024 * 1024, // 10GB
            auto_cleanup_enabled: true,
            cleanup_interval_minutes: 60, // 1 hour
        }
    }
}

/// Metadata for tracked files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Unique identifier for the file
    pub id: Uuid,
    /// Original filename
    pub original_name: String,
    /// File path on disk
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    pub last_accessed: DateTime<Utc>,
    /// File type/category
    pub file_type: FileType,
    /// Whether the file is marked for deletion
    pub marked_for_deletion: bool,
    /// Custom retention period (overrides default)
    pub custom_retention: Option<Duration>,
}

/// File type categories for different retention policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileType {
    /// User uploaded challenge files
    UploadedFile,
    /// Analysis result files
    AnalysisResult,
    /// Temporary processing files
    TemporaryFile,
    /// Cache files
    CacheFile,
    /// Log files
    LogFile,
}

/// File cleanup and retention manager
pub struct FileCleanupManager {
    /// Retention policy configuration
    policy: RetentionPolicy,
    /// Base directory for file storage
    base_dir: PathBuf,
    /// Tracked file metadata
    tracked_files: HashMap<Uuid, FileMetadata>,
    /// Metadata file path
    metadata_file: PathBuf,
}

impl FileCleanupManager {
    /// Create a new file cleanup manager
    pub fn new(base_dir: PathBuf, policy: RetentionPolicy) -> Result<Self> {
        let metadata_file = base_dir.join("file_metadata.json");
        
        let mut manager = Self {
            policy,
            base_dir,
            tracked_files: HashMap::new(),
            metadata_file,
        };

        // Load existing metadata
        manager.load_metadata()?;
        
        Ok(manager)
    }

    /// Create a new file cleanup manager with default policy
    pub fn with_default_policy(base_dir: PathBuf) -> Result<Self> {
        Self::new(base_dir, RetentionPolicy::default())
    }

    /// Track a new file for cleanup management
    pub fn track_file(
        &mut self,
        path: PathBuf,
        original_name: String,
        file_type: FileType,
        custom_retention: Option<Duration>,
    ) -> Result<Uuid> {
        let file_id = Uuid::new_v4();
        
        // Get file size
        let size = fs::metadata(&path)
            .map_err(|e| anyhow!("Failed to get file metadata: {}", e))?
            .len();

        let now = Utc::now();
        let metadata = FileMetadata {
            id: file_id,
            original_name,
            path,
            size,
            created_at: now,
            last_accessed: now,
            file_type,
            marked_for_deletion: false,
            custom_retention,
        };

        debug!("Tracking file {} with ID {}", metadata.path.display(), file_id);
        self.tracked_files.insert(file_id, metadata);
        self.save_metadata()?;
        Ok(file_id)
    }

    /// Update last access time for a file
    pub fn update_access_time(&mut self, file_id: &Uuid) -> Result<()> {
        if let Some(metadata) = self.tracked_files.get_mut(file_id) {
            metadata.last_accessed = Utc::now();
            self.save_metadata()?;
            debug!("Updated access time for file {}", file_id);
        }
        Ok(())
    }

    /// Mark a file for deletion
    pub fn mark_for_deletion(&mut self, file_id: &Uuid) -> Result<()> {
        if let Some(metadata) = self.tracked_files.get_mut(file_id) {
            metadata.marked_for_deletion = true;
            self.save_metadata()?;
            info!("Marked file {} for deletion", file_id);
        }
        Ok(())
    }

    /// Manually delete a file immediately
    pub fn delete_file_immediately(&mut self, file_id: &Uuid) -> Result<()> {
        if let Some(metadata) = self.tracked_files.remove(file_id) {
            if metadata.path.exists() {
                fs::remove_file(&metadata.path)
                    .map_err(|e| anyhow!("Failed to delete file {}: {}", metadata.path.display(), e))?;
                info!("Deleted file {} ({})", metadata.path.display(), file_id);
            }
            self.save_metadata()?;
        }
        Ok(())
    }

    /// Run cleanup process to remove expired files
    pub fn run_cleanup(&mut self) -> Result<CleanupReport> {
        let mut report = CleanupReport::new();
        let now = Utc::now();
        let mut files_to_remove = Vec::new();

        // Check each tracked file
        for (file_id, metadata) in &self.tracked_files {
            let should_delete = self.should_delete_file(metadata, now);
            
            if should_delete {
                files_to_remove.push(*file_id);
                report.files_to_delete.push(metadata.clone());
            }
        }

        // Delete expired files
        for file_id in files_to_remove {
            match self.delete_file_immediately(&file_id) {
                Ok(()) => {
                    report.deleted_files += 1;
                    if let Some(metadata) = self.tracked_files.get(&file_id) {
                        report.freed_space += metadata.size;
                    }
                }
                Err(e) => {
                    error!("Failed to delete file {}: {}", file_id, e);
                    report.errors.push(format!("Failed to delete {}: {}", file_id, e));
                }
            }
        }

        // Check storage size limits
        let total_size = self.calculate_total_storage_size();
        if total_size > self.policy.max_storage_size {
            let excess = total_size - self.policy.max_storage_size;
            warn!("Storage size {} exceeds limit {}, excess: {} bytes", 
                  total_size, self.policy.max_storage_size, excess);
            
            // Delete oldest files to free space
            let freed = self.cleanup_by_size(excess)?;
            report.freed_space += freed;
            report.size_limit_exceeded = true;
        }

        // Clean up orphaned files (files on disk not in metadata)
        let orphaned_count = self.cleanup_orphaned_files()?;
        report.orphaned_files_cleaned = orphaned_count;

        info!("Cleanup completed: {} files deleted, {} bytes freed", 
              report.deleted_files, report.freed_space);

        Ok(report)
    }

    /// Start automatic cleanup scheduler
    pub async fn start_auto_cleanup(&mut self) -> Result<()> {
        if !self.policy.auto_cleanup_enabled {
            debug!("Auto cleanup is disabled");
            return Ok(());
        }

        let interval_duration = TokioDuration::from_secs(self.policy.cleanup_interval_minutes * 60);
        let mut cleanup_interval = interval(interval_duration);

        info!("Starting auto cleanup with interval of {} minutes", 
              self.policy.cleanup_interval_minutes);

        loop {
            cleanup_interval.tick().await;
            
            match self.run_cleanup() {
                Ok(report) => {
                    if report.deleted_files > 0 || report.orphaned_files_cleaned > 0 {
                        info!("Auto cleanup: {} files deleted, {} orphaned files cleaned, {} bytes freed",
                              report.deleted_files, report.orphaned_files_cleaned, report.freed_space);
                    }
                }
                Err(e) => {
                    error!("Auto cleanup failed: {}", e);
                }
            }
        }
    }

    /// Get cleanup statistics
    pub fn get_statistics(&self) -> CleanupStatistics {
        let now = Utc::now();
        let mut stats = CleanupStatistics::new();

        for metadata in self.tracked_files.values() {
            stats.total_files += 1;
            stats.total_size += metadata.size;

            match metadata.file_type {
                FileType::UploadedFile => stats.uploaded_files += 1,
                FileType::AnalysisResult => stats.analysis_files += 1,
                FileType::TemporaryFile => stats.temp_files += 1,
                FileType::CacheFile => stats.cache_files += 1,
                FileType::LogFile => stats.log_files += 1,
            }

            if self.should_delete_file(metadata, now) {
                stats.files_pending_deletion += 1;
            }

            if metadata.marked_for_deletion {
                stats.files_marked_for_deletion += 1;
            }
        }

        stats
    }

    /// Get list of files that will be deleted in next cleanup
    pub fn get_files_pending_deletion(&self) -> Vec<FileMetadata> {
        let now = Utc::now();
        self.tracked_files
            .values()
            .filter(|metadata| self.should_delete_file(metadata, now))
            .cloned()
            .collect()
    }

    /// Update retention policy
    pub fn update_policy(&mut self, new_policy: RetentionPolicy) -> Result<()> {
        self.policy = new_policy;
        info!("Updated retention policy");
        Ok(())
    }

    /// Check if a file should be deleted based on retention policy
    fn should_delete_file(&self, metadata: &FileMetadata, now: DateTime<Utc>) -> bool {
        // Check if manually marked for deletion
        if metadata.marked_for_deletion {
            return true;
        }

        // Check if file still exists on disk
        if !metadata.path.exists() {
            return true; // Remove from tracking if file doesn't exist
        }

        // Determine retention period
        let retention_period = metadata.custom_retention.unwrap_or_else(|| {
            match metadata.file_type {
                FileType::UploadedFile => self.policy.default_retention,
                FileType::AnalysisResult => self.policy.analysis_retention,
                FileType::TemporaryFile => self.policy.temp_file_retention,
                FileType::CacheFile => self.policy.temp_file_retention,
                FileType::LogFile => self.policy.analysis_retention,
            }
        });

        // Check if file has expired
        let expiry_time = metadata.created_at + retention_period;
        now > expiry_time
    }

    /// Calculate total storage size of tracked files
    fn calculate_total_storage_size(&self) -> u64 {
        self.tracked_files
            .values()
            .filter(|metadata| metadata.path.exists())
            .map(|metadata| metadata.size)
            .sum()
    }

    /// Clean up files by size to free specified amount of space
    fn cleanup_by_size(&mut self, target_free_space: u64) -> Result<u64> {
        let mut files_by_age: Vec<_> = self.tracked_files
            .iter()
            .filter(|(_, metadata)| metadata.path.exists() && !metadata.marked_for_deletion)
            .collect();

        // Sort by last access time (oldest first)
        files_by_age.sort_by_key(|(_, metadata)| metadata.last_accessed);

        let mut freed_space = 0u64;
        let mut files_to_delete = Vec::new();

        for (file_id, metadata) in files_by_age {
            if freed_space >= target_free_space {
                break;
            }

            files_to_delete.push(*file_id);
            freed_space += metadata.size;
        }

        // Delete the selected files
        for file_id in files_to_delete {
            self.delete_file_immediately(&file_id)?;
        }

        Ok(freed_space)
    }

    /// Clean up orphaned files (files on disk not tracked in metadata)
    fn cleanup_orphaned_files(&self) -> Result<usize> {
        let mut orphaned_count = 0;

        if !self.base_dir.exists() {
            return Ok(0);
        }

        // Get all files in base directory
        let entries = fs::read_dir(&self.base_dir)
            .map_err(|e| anyhow!("Failed to read base directory: {}", e))?;

        for entry in entries {
            let entry = entry.map_err(|e| anyhow!("Failed to read directory entry: {}", e))?;
            let path = entry.path();

            if path.is_file() && path != self.metadata_file {
                // Check if this file is tracked
                let is_tracked = self.tracked_files
                    .values()
                    .any(|metadata| metadata.path == path);

                if !is_tracked {
                    // This is an orphaned file
                    match fs::remove_file(&path) {
                        Ok(()) => {
                            orphaned_count += 1;
                            debug!("Removed orphaned file: {}", path.display());
                        }
                        Err(e) => {
                            warn!("Failed to remove orphaned file {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(orphaned_count)
    }

    /// Load metadata from disk
    fn load_metadata(&mut self) -> Result<()> {
        if !self.metadata_file.exists() {
            debug!("No existing metadata file found");
            return Ok(());
        }

        let content = fs::read_to_string(&self.metadata_file)
            .map_err(|e| anyhow!("Failed to read metadata file: {}", e))?;

        self.tracked_files = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse metadata file: {}", e))?;

        debug!("Loaded metadata for {} files", self.tracked_files.len());
        Ok(())
    }

    /// Save metadata to disk
    fn save_metadata(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.tracked_files)
            .map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;

        fs::write(&self.metadata_file, content)
            .map_err(|e| anyhow!("Failed to write metadata file: {}", e))?;

        Ok(())
    }
}

/// Report generated after cleanup operation
#[derive(Debug, Clone)]
pub struct CleanupReport {
    /// Number of files deleted
    pub deleted_files: usize,
    /// Amount of space freed in bytes
    pub freed_space: u64,
    /// Number of orphaned files cleaned
    pub orphaned_files_cleaned: usize,
    /// Whether storage size limit was exceeded
    pub size_limit_exceeded: bool,
    /// Files that were scheduled for deletion
    pub files_to_delete: Vec<FileMetadata>,
    /// Errors encountered during cleanup
    pub errors: Vec<String>,
}

impl CleanupReport {
    fn new() -> Self {
        Self {
            deleted_files: 0,
            freed_space: 0,
            orphaned_files_cleaned: 0,
            size_limit_exceeded: false,
            files_to_delete: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Statistics about tracked files
#[derive(Debug, Clone)]
pub struct CleanupStatistics {
    /// Total number of tracked files
    pub total_files: usize,
    /// Total size of tracked files in bytes
    pub total_size: u64,
    /// Number of uploaded files
    pub uploaded_files: usize,
    /// Number of analysis result files
    pub analysis_files: usize,
    /// Number of temporary files
    pub temp_files: usize,
    /// Number of cache files
    pub cache_files: usize,
    /// Number of log files
    pub log_files: usize,
    /// Number of files pending deletion
    pub files_pending_deletion: usize,
    /// Number of files marked for deletion
    pub files_marked_for_deletion: usize,
}

impl CleanupStatistics {
    fn new() -> Self {
        Self {
            total_files: 0,
            total_size: 0,
            uploaded_files: 0,
            analysis_files: 0,
            temp_files: 0,
            cache_files: 0,
            log_files: 0,
            files_pending_deletion: 0,
            files_marked_for_deletion: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn create_test_manager() -> (FileCleanupManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let policy = RetentionPolicy {
            default_retention: Duration::minutes(1),
            analysis_retention: Duration::minutes(2),
            temp_file_retention: Duration::seconds(30),
            max_storage_size: 1024 * 1024, // 1MB
            auto_cleanup_enabled: false,
            cleanup_interval_minutes: 1,
        };
        
        let manager = FileCleanupManager::new(temp_dir.path().to_path_buf(), policy).unwrap();
        (manager, temp_dir)
    }

    #[test]
    fn test_file_tracking() {
        let (mut manager, temp_dir) = create_test_manager();
        
        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").unwrap();
        
        // Track the file
        let file_id = manager.track_file(
            test_file.clone(),
            "test.txt".to_string(),
            FileType::UploadedFile,
            None,
        ).unwrap();
        
        assert!(manager.tracked_files.contains_key(&file_id));
        assert_eq!(manager.tracked_files.len(), 1);
    }

    #[test]
    fn test_file_deletion() {
        let (mut manager, temp_dir) = create_test_manager();
        
        // Create and track a test file
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").unwrap();
        
        let file_id = manager.track_file(
            test_file.clone(),
            "test.txt".to_string(),
            FileType::UploadedFile,
            None,
        ).unwrap();
        
        // Delete the file
        manager.delete_file_immediately(&file_id).unwrap();
        
        assert!(!manager.tracked_files.contains_key(&file_id));
        assert!(!test_file.exists());
    }

    #[test]
    fn test_mark_for_deletion() {
        let (mut manager, temp_dir) = create_test_manager();
        
        // Create and track a test file
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").unwrap();
        
        let file_id = manager.track_file(
            test_file.clone(),
            "test.txt".to_string(),
            FileType::UploadedFile,
            None,
        ).unwrap();
        
        // Mark for deletion
        manager.mark_for_deletion(&file_id).unwrap();
        
        let metadata = manager.tracked_files.get(&file_id).unwrap();
        assert!(metadata.marked_for_deletion);
    }

    #[test]
    fn test_cleanup_statistics() {
        let (mut manager, temp_dir) = create_test_manager();
        
        // Create and track multiple test files
        for i in 0..3 {
            let test_file = temp_dir.path().join(format!("test{}.txt", i));
            fs::write(&test_file, format!("test content {}", i)).unwrap();
            
            let file_type = match i {
                0 => FileType::UploadedFile,
                1 => FileType::AnalysisResult,
                _ => FileType::TemporaryFile,
            };
            
            manager.track_file(
                test_file,
                format!("test{}.txt", i),
                file_type,
                None,
            ).unwrap();
        }
        
        let stats = manager.get_statistics();
        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.uploaded_files, 1);
        assert_eq!(stats.analysis_files, 1);
        assert_eq!(stats.temp_files, 1);
    }

    #[test]
    fn test_retention_policy() {
        let (manager, temp_dir) = create_test_manager();
        
        let now = Utc::now();
        
        // Create actual files for testing
        let old_file = temp_dir.path().join("old.txt");
        let new_file = temp_dir.path().join("new.txt");
        fs::write(&old_file, "old content").unwrap();
        fs::write(&new_file, "new content").unwrap();
        
        // Create metadata for an old file
        let old_metadata = FileMetadata {
            id: Uuid::new_v4(),
            original_name: "old.txt".to_string(),
            path: old_file,
            size: 100,
            created_at: now - Duration::minutes(5), // Older than retention period
            last_accessed: now - Duration::minutes(5),
            file_type: FileType::UploadedFile,
            marked_for_deletion: false,
            custom_retention: None,
        };
        
        // Create metadata for a new file
        let new_metadata = FileMetadata {
            id: Uuid::new_v4(),
            original_name: "new.txt".to_string(),
            path: new_file,
            size: 100,
            created_at: now,
            last_accessed: now,
            file_type: FileType::UploadedFile,
            marked_for_deletion: false,
            custom_retention: None,
        };
        
        assert!(manager.should_delete_file(&old_metadata, now));
        assert!(!manager.should_delete_file(&new_metadata, now));
    }

    #[test]
    fn test_metadata_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let policy = RetentionPolicy::default();
        
        // Create manager and track a file
        {
            let mut manager = FileCleanupManager::new(temp_dir.path().to_path_buf(), policy.clone()).unwrap();
            
            let test_file = temp_dir.path().join("test.txt");
            fs::write(&test_file, "test content").unwrap();
            
            manager.track_file(
                test_file,
                "test.txt".to_string(),
                FileType::UploadedFile,
                None,
            ).unwrap();
            
            assert_eq!(manager.tracked_files.len(), 1);
        }
        
        // Create new manager and verify metadata was loaded
        {
            let manager = FileCleanupManager::new(temp_dir.path().to_path_buf(), policy).unwrap();
            assert_eq!(manager.tracked_files.len(), 1);
        }
    }
}