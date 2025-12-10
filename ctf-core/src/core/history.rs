//! Challenge history management system

use crate::core::models::{Challenge, ChallengeStatistics, FileType, HintExchange};
use crate::core::storage::{SqliteStorage, ChallengeStorage};
use crate::Result;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Filter criteria for challenge history queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFilter {
    /// Filter by date range
    pub date_range: Option<DateRange>,
    /// Filter by file types
    pub file_types: Option<Vec<FileType>>,
    /// Filter by challenge name (partial match)
    pub name_contains: Option<String>,
    /// Filter by context content (partial match)
    pub context_contains: Option<String>,
    /// Maximum number of results to return
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
    /// Sort order
    pub sort_order: SortOrder,
}

/// Date range for filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Sort order for history results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    /// Most recent first (default)
    NewestFirst,
    /// Oldest first
    OldestFirst,
    /// Alphabetical by name
    NameAscending,
    /// Reverse alphabetical by name
    NameDescending,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::NewestFirst
    }
}

impl Default for HistoryFilter {
    fn default() -> Self {
        Self {
            date_range: None,
            file_types: None,
            name_contains: None,
            context_contains: None,
            limit: Some(50),
            offset: None,
            sort_order: SortOrder::NewestFirst,
        }
    }
}

/// History session data for tracking user interactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySession {
    pub session_id: Uuid,
    pub challenge_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub hint_exchanges: Vec<HintExchange>,
    pub analysis_duration: Option<std::time::Duration>,
    pub user_notes: Option<String>,
}

impl HistorySession {
    /// Create a new history session
    pub fn new(challenge_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            session_id: Uuid::new_v4(),
            challenge_id,
            started_at: now,
            last_activity: now,
            hint_exchanges: Vec::new(),
            analysis_duration: None,
            user_notes: None,
        }
    }

    /// Add a hint exchange to the session
    pub fn add_hint_exchange(&mut self, exchange: HintExchange) {
        self.hint_exchanges.push(exchange);
        self.last_activity = Utc::now();
    }

    /// Update session activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Calculate session duration
    pub fn session_duration(&self) -> Duration {
        self.last_activity - self.started_at
    }

    /// Check if session is recent (within last hour)
    pub fn is_recent(&self) -> bool {
        let one_hour_ago = Utc::now() - Duration::hours(1);
        self.last_activity > one_hour_ago
    }
}

/// Challenge history manager
pub struct ChallengeHistoryManager {
    storage: SqliteStorage,
}

impl ChallengeHistoryManager {
    /// Create a new history manager
    pub fn new(storage: SqliteStorage) -> Self {
        Self { storage }
    }

    /// Get challenge history with filtering
    pub async fn get_history(&self, filter: &HistoryFilter) -> Result<Vec<Challenge>> {
        debug!("Retrieving challenge history with filter: {:?}", filter);

        let challenges = if let Some(date_range) = &filter.date_range {
            // Filter by date range
            self.storage.list_challenges_by_date_range(
                date_range.start,
                date_range.end,
                filter.limit,
            ).await?
        } else if let Some(name_query) = &filter.name_contains {
            // Search by name
            self.storage.search_challenges(name_query, filter.limit).await?
        } else if let Some(context_query) = &filter.context_contains {
            // Search by context
            self.storage.search_challenges(context_query, filter.limit).await?
        } else {
            // Get all challenges with pagination
            self.storage.list_challenges_filtered(filter.limit, filter.offset).await?
        };

        // Apply file type filtering if specified
        let mut filtered_challenges = if let Some(file_types) = &filter.file_types {
            challenges.into_iter()
                .filter(|challenge| {
                    challenge.files.iter().any(|file| file_types.contains(&file.file_type))
                })
                .collect()
        } else {
            challenges
        };

        // Apply sorting
        match filter.sort_order {
            SortOrder::NewestFirst => {
                filtered_challenges.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            }
            SortOrder::OldestFirst => {
                filtered_challenges.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            }
            SortOrder::NameAscending => {
                filtered_challenges.sort_by(|a, b| a.name.cmp(&b.name));
            }
            SortOrder::NameDescending => {
                filtered_challenges.sort_by(|a, b| b.name.cmp(&a.name));
            }
        }

        info!("Retrieved {} challenges from history", filtered_challenges.len());
        Ok(filtered_challenges)
    }

    /// Get challenges from the last N days
    pub async fn get_recent_challenges(&self, days: u32, limit: Option<u32>) -> Result<Vec<Challenge>> {
        let start_date = Utc::now() - Duration::days(days as i64);
        let end_date = Utc::now();

        let filter = HistoryFilter {
            date_range: Some(DateRange { start: start_date, end: end_date }),
            limit,
            ..Default::default()
        };

        self.get_history(&filter).await
    }

    /// Get challenges by file type
    pub async fn get_challenges_by_type(&self, file_type: FileType, limit: Option<u32>) -> Result<Vec<Challenge>> {
        debug!("Getting challenges with file type: {:?}", file_type);
        Ok(self.storage.list_challenges_by_file_type(&file_type, limit).await?)
    }

    /// Get challenge statistics
    pub async fn get_statistics(&self) -> Result<ChallengeStatistics> {
        debug!("Calculating challenge statistics");
        Ok(self.storage.get_challenge_statistics().await?)
    }

    /// Get detailed history for a specific challenge
    pub async fn get_challenge_details(&self, challenge_id: Uuid) -> Result<Option<Challenge>> {
        debug!("Getting detailed history for challenge: {}", challenge_id);
        Ok(self.storage.get_challenge(challenge_id).await?)
    }

    /// Get hint history for a challenge
    pub async fn get_hint_history(&self, challenge_id: Uuid) -> Result<Vec<HintExchange>> {
        debug!("Getting hint history for challenge: {}", challenge_id);
        Ok(self.storage.get_hint_history(challenge_id).await?)
    }

    /// Delete challenge from history
    pub async fn delete_challenge(&self, challenge_id: Uuid) -> Result<()> {
        info!("Deleting challenge from history: {}", challenge_id);
        Ok(self.storage.delete_challenge(challenge_id).await?)
    }

    /// Create a history summary report
    pub async fn create_summary_report(&self, days: Option<u32>) -> Result<HistorySummaryReport> {
        let days = days.unwrap_or(30);
        debug!("Creating history summary report for last {} days", days);

        let recent_challenges = self.get_recent_challenges(days, None).await?;
        let statistics = self.get_statistics().await?;

        // Calculate additional metrics
        let total_files_analyzed = recent_challenges.iter()
            .map(|c| c.files.len())
            .sum::<usize>() as u32;

        let total_analysis_results = recent_challenges.iter()
            .map(|c| c.analysis_results.len())
            .sum::<usize>() as u32;

        let file_type_distribution = self.calculate_file_type_distribution(&recent_challenges);
        let analysis_success_rate = self.calculate_analysis_success_rate(&recent_challenges);

        Ok(HistorySummaryReport {
            period_days: days,
            total_challenges: recent_challenges.len() as u32,
            total_files_analyzed,
            total_analysis_results,
            file_type_distribution,
            analysis_success_rate,
            most_active_day: self.find_most_active_day(&recent_challenges),
            average_files_per_challenge: if recent_challenges.is_empty() {
                0.0
            } else {
                total_files_analyzed as f32 / recent_challenges.len() as f32
            },
            statistics,
        })
    }

    /// Calculate file type distribution
    fn calculate_file_type_distribution(&self, challenges: &[Challenge]) -> HashMap<FileType, u32> {
        let mut distribution = HashMap::new();
        
        for challenge in challenges {
            for file in &challenge.files {
                *distribution.entry(file.file_type.clone()).or_insert(0) += 1;
            }
        }

        distribution
    }

    /// Calculate analysis success rate (challenges with meaningful results)
    fn calculate_analysis_success_rate(&self, challenges: &[Challenge]) -> f32 {
        if challenges.is_empty() {
            return 0.0;
        }

        let successful_analyses = challenges.iter()
            .filter(|c| c.analysis_results.iter().any(|r| r.has_meaningful_results()))
            .count();

        successful_analyses as f32 / challenges.len() as f32
    }

    /// Find the most active day in the given challenges
    fn find_most_active_day(&self, challenges: &[Challenge]) -> Option<String> {
        let mut day_counts: HashMap<String, u32> = HashMap::new();

        for challenge in challenges {
            let day = challenge.created_at.format("%Y-%m-%d").to_string();
            *day_counts.entry(day).or_insert(0) += 1;
        }

        day_counts.into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(day, _)| day)
    }

    /// Export challenge history to JSON
    pub async fn export_history(&self, filter: &HistoryFilter) -> Result<String> {
        debug!("Exporting challenge history");
        
        let challenges = self.get_history(filter).await?;
        let export_data = HistoryExport {
            exported_at: Utc::now(),
            filter: filter.clone(),
            challenges,
        };

        serde_json::to_string_pretty(&export_data)
            .map_err(|e| anyhow::anyhow!("Failed to serialize history export: {}", e).into())
    }

    /// Get paginated history
    pub async fn get_paginated_history(
        &self,
        page: u32,
        page_size: u32,
        filter: Option<HistoryFilter>,
    ) -> Result<PaginatedHistory> {
        let mut filter = filter.unwrap_or_default();
        filter.limit = Some(page_size);
        filter.offset = Some(page * page_size);

        let challenges = self.get_history(&filter).await?;
        let statistics = self.get_statistics().await?;
        
        let total_challenges = statistics.total_challenges;
        let total_pages = (total_challenges + page_size - 1) / page_size;

        Ok(PaginatedHistory {
            challenges,
            current_page: page,
            page_size,
            total_challenges,
            total_pages,
            has_next: total_pages > 0 && page < total_pages - 1,
            has_previous: page > 0,
        })
    }

    /// Clean up old history entries
    pub async fn cleanup_old_history(&self, retention_days: u32) -> Result<u32> {
        info!("Cleaning up history older than {} days", retention_days);
        
        let cutoff_date = Utc::now() - Duration::days(retention_days as i64);
        let filter = HistoryFilter {
            date_range: Some(DateRange {
                start: DateTime::from_timestamp(0, 0).unwrap_or_default(),
                end: cutoff_date,
            }),
            ..Default::default()
        };

        let old_challenges = self.get_history(&filter).await?;
        let mut deleted_count = 0;

        for challenge in old_challenges {
            match self.delete_challenge(challenge.id).await {
                Ok(()) => {
                    deleted_count += 1;
                    debug!("Deleted old challenge: {}", challenge.name);
                }
                Err(e) => {
                    warn!("Failed to delete challenge {}: {}", challenge.name, e);
                }
            }
        }

        info!("Cleaned up {} old challenge entries", deleted_count);
        Ok(deleted_count)
    }
}

/// History summary report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySummaryReport {
    pub period_days: u32,
    pub total_challenges: u32,
    pub total_files_analyzed: u32,
    pub total_analysis_results: u32,
    pub file_type_distribution: HashMap<FileType, u32>,
    pub analysis_success_rate: f32,
    pub most_active_day: Option<String>,
    pub average_files_per_challenge: f32,
    pub statistics: ChallengeStatistics,
}

/// History export data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryExport {
    pub exported_at: DateTime<Utc>,
    pub filter: HistoryFilter,
    pub challenges: Vec<Challenge>,
}

/// Paginated history results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedHistory {
    pub challenges: Vec<Challenge>,
    pub current_page: u32,
    pub page_size: u32,
    pub total_challenges: u32,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_previous: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{Challenge, FileType};
    use tempfile::tempdir;

    async fn create_test_storage() -> SqliteStorage {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let file_storage_path = temp_dir.path().join("files");
        
        SqliteStorage::new(
            db_path.to_str().unwrap(),
            file_storage_path.to_str().unwrap(),
        ).await.unwrap()
    }

    #[tokio::test]
    async fn test_history_filter_default() {
        let filter = HistoryFilter::default();
        assert_eq!(filter.limit, Some(50));
        assert!(matches!(filter.sort_order, SortOrder::NewestFirst));
    }

    #[tokio::test]
    async fn test_history_session_creation() {
        let challenge_id = Uuid::new_v4();
        let session = HistorySession::new(challenge_id);
        
        assert_eq!(session.challenge_id, challenge_id);
        assert!(session.is_recent());
        assert_eq!(session.hint_exchanges.len(), 0);
    }

    #[tokio::test]
    async fn test_get_recent_challenges() {
        let storage = create_test_storage().await;
        let history_manager = ChallengeHistoryManager::new(storage);
        
        let result = history_manager.get_recent_challenges(7, Some(10)).await;
        assert!(result.is_ok());
        
        let challenges = result.unwrap();
        assert!(challenges.len() <= 10);
    }

    #[tokio::test]
    async fn test_get_statistics() {
        let storage = create_test_storage().await;
        let history_manager = ChallengeHistoryManager::new(storage);
        
        let result = history_manager.get_statistics().await;
        assert!(result.is_ok());
        
        let stats = result.unwrap();
        assert_eq!(stats.total_challenges, 0); // Empty database
    }

    #[tokio::test]
    async fn test_create_summary_report() {
        let storage = create_test_storage().await;
        let history_manager = ChallengeHistoryManager::new(storage);
        
        let result = history_manager.create_summary_report(Some(30)).await;
        assert!(result.is_ok());
        
        let report = result.unwrap();
        assert_eq!(report.period_days, 30);
        assert_eq!(report.total_challenges, 0);
    }

    #[tokio::test]
    async fn test_paginated_history() {
        let storage = create_test_storage().await;
        let history_manager = ChallengeHistoryManager::new(storage);
        
        let result = history_manager.get_paginated_history(0, 10, None).await;
        assert!(result.is_ok());
        
        let paginated = result.unwrap();
        assert_eq!(paginated.current_page, 0);
        assert_eq!(paginated.page_size, 10);
        assert!(!paginated.has_previous);
    }

    #[tokio::test]
    async fn test_export_history() {
        let storage = create_test_storage().await;
        let history_manager = ChallengeHistoryManager::new(storage);
        
        let filter = HistoryFilter::default();
        let result = history_manager.export_history(&filter).await;
        assert!(result.is_ok());
        
        let json = result.unwrap();
        assert!(json.contains("exported_at"));
        assert!(json.contains("challenges"));
    }
}