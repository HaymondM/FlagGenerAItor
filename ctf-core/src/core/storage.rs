//! Storage utilities and database interfaces

use crate::core::models::*;
use crate::analysis::file_analyzer::FileAnalyzer;
use crate::analysis::file_security::FileSecurityValidator;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json;
use sha2::{Sha256, Digest};
use sqlx::{SqlitePool, Row, sqlite::SqliteConnectOptions};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::fs;
use tracing::{info, warn, error};
use uuid::Uuid;

/// Trait for challenge storage operations
#[async_trait]
pub trait ChallengeStorage {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<()>;
    async fn get_challenge(&self, id: Uuid) -> Result<Option<Challenge>>;
    async fn list_challenges(&self) -> Result<Vec<Challenge>>;
    async fn delete_challenge(&self, id: Uuid) -> Result<()>;
}

/// Trait for file storage operations
#[async_trait]
pub trait FileStorage {
    async fn store_file(&self, file_data: &[u8], original_name: &str) -> Result<ChallengeFile>;
    async fn get_file(&self, id: Uuid) -> Result<Option<Vec<u8>>>;
    async fn delete_file(&self, id: Uuid) -> Result<()>;
}

/// SQLite-based storage implementation
pub struct SqliteStorage {
    pool: SqlitePool,
    file_storage_path: PathBuf,
    file_analyzer: FileAnalyzer,
    security_validator: FileSecurityValidator,
}

impl SqliteStorage {
    /// Create a new SQLite storage instance
    pub async fn new(database_path: &str, file_storage_path: &str) -> Result<Self> {
        // Ensure the database directory exists
        if let Some(parent) = Path::new(database_path).parent() {
            fs::create_dir_all(parent).await?;
        }

        // Ensure the file storage directory exists
        fs::create_dir_all(file_storage_path).await?;

        // Configure SQLite connection options
        let options = SqliteConnectOptions::from_str(database_path)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(30));

        // Create connection pool
        let pool = SqlitePool::connect_with(options).await?;

        let storage = SqliteStorage {
            pool,
            file_storage_path: PathBuf::from(file_storage_path),
            file_analyzer: FileAnalyzer::new(),
            security_validator: FileSecurityValidator::new(),
        };

        // Run migrations
        storage.migrate().await?;

        info!("SQLite storage initialized at {}", database_path);
        Ok(storage)
    }

    /// Run database migrations
    async fn migrate(&self) -> Result<()> {
        info!("Running database migrations");

        // Create challenges table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                context TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create files table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                challenge_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                hash TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                metadata TEXT NOT NULL,
                FOREIGN KEY (challenge_id) REFERENCES challenges (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create analysis_results table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                analyzer TEXT NOT NULL,
                confidence REAL NOT NULL,
                execution_time_ms INTEGER NOT NULL,
                transformations TEXT NOT NULL,
                findings TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (challenge_id) REFERENCES challenges (id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create hint_history table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS hint_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT NOT NULL,
                request TEXT NOT NULL,
                response TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (challenge_id) REFERENCES challenges (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for better performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_challenges_created_at ON challenges (created_at)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_challenge_id ON files (challenge_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_analysis_results_challenge_id ON analysis_results (challenge_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_hint_history_challenge_id ON hint_history (challenge_id)")
            .execute(&self.pool)
            .await?;

        info!("Database migrations completed successfully");
        Ok(())
    }

    /// Calculate SHA-256 hash of file data
    fn calculate_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Generate secure file storage path
    fn generate_file_path(&self, original_name: &str) -> Result<PathBuf> {
        Ok(self.security_validator.generate_secure_path(&self.file_storage_path, original_name)?)
    }

    /// Store hint exchange in history
    pub async fn store_hint_exchange(&self, challenge_id: Uuid, exchange: &HintExchange) -> Result<()> {
        let response_json = serde_json::to_string(&exchange.response)?;
        
        sqlx::query(
            "INSERT INTO hint_history (challenge_id, request, response, timestamp) VALUES (?, ?, ?, ?)"
        )
        .bind(challenge_id.to_string())
        .bind(&exchange.request)
        .bind(response_json)
        .bind(exchange.timestamp.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get hint history for a challenge
    pub async fn get_hint_history(&self, challenge_id: Uuid) -> Result<Vec<HintExchange>> {
        let rows = sqlx::query(
            "SELECT request, response, timestamp FROM hint_history WHERE challenge_id = ? ORDER BY timestamp ASC"
        )
        .bind(challenge_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut exchanges = Vec::new();
        for row in rows {
            let request: String = row.get("request");
            let response_json: String = row.get("response");
            let timestamp_str: String = row.get("timestamp");

            let response: HintResponse = serde_json::from_str(&response_json)?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)?.with_timezone(&Utc);

            exchanges.push(HintExchange {
                request,
                response,
                timestamp,
            });
        }

        Ok(exchanges)
    }

    /// Get challenges with optional filtering
    pub async fn list_challenges_filtered(&self, limit: Option<u32>, offset: Option<u32>) -> Result<Vec<Challenge>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let rows = sqlx::query(
            "SELECT id, name, context, created_at FROM challenges ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut challenges = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)?;
            
            let mut challenge = Challenge {
                id,
                name: row.get("name"),
                context: row.get("context"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                files: Vec::new(),
                analysis_results: Vec::new(),
            };

            // Load associated files
            challenge.files = self.get_challenge_files(id).await?;
            
            // Load analysis results
            challenge.analysis_results = self.get_challenge_analysis_results(id).await?;

            challenges.push(challenge);
        }

        Ok(challenges)
    }

    /// Get challenges filtered by date range
    pub async fn list_challenges_by_date_range(
        &self, 
        start_date: DateTime<Utc>, 
        end_date: DateTime<Utc>,
        limit: Option<u32>
    ) -> Result<Vec<Challenge>> {
        let limit = limit.unwrap_or(100);

        let rows = sqlx::query(
            "SELECT id, name, context, created_at FROM challenges 
             WHERE created_at >= ? AND created_at <= ? 
             ORDER BY created_at DESC LIMIT ?"
        )
        .bind(start_date.to_rfc3339())
        .bind(end_date.to_rfc3339())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut challenges = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)?;
            
            let mut challenge = Challenge {
                id,
                name: row.get("name"),
                context: row.get("context"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                files: Vec::new(),
                analysis_results: Vec::new(),
            };

            // Load associated files
            challenge.files = self.get_challenge_files(id).await?;
            
            // Load analysis results
            challenge.analysis_results = self.get_challenge_analysis_results(id).await?;

            challenges.push(challenge);
        }

        Ok(challenges)
    }

    /// Get challenges filtered by file type
    pub async fn list_challenges_by_file_type(&self, file_type: &FileType, limit: Option<u32>) -> Result<Vec<Challenge>> {
        let limit = limit.unwrap_or(100);
        let file_type_str = match file_type {
            FileType::Image => "Image",
            FileType::Binary => "Binary",
            FileType::Pcap => "Pcap",
            FileType::Pdf => "Pdf",
            FileType::Zip => "Zip",
            FileType::Javascript => "Javascript",
            FileType::Html => "Html",
            FileType::Text => "Text",
            FileType::Unknown => "Unknown",
        };

        let rows = sqlx::query(
            "SELECT DISTINCT c.id, c.name, c.context, c.created_at 
             FROM challenges c 
             JOIN files f ON c.id = f.challenge_id 
             WHERE f.file_type = ? 
             ORDER BY c.created_at DESC LIMIT ?"
        )
        .bind(file_type_str)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut challenges = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)?;
            
            let mut challenge = Challenge {
                id,
                name: row.get("name"),
                context: row.get("context"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                files: Vec::new(),
                analysis_results: Vec::new(),
            };

            // Load associated files
            challenge.files = self.get_challenge_files(id).await?;
            
            // Load analysis results
            challenge.analysis_results = self.get_challenge_analysis_results(id).await?;

            challenges.push(challenge);
        }

        Ok(challenges)
    }

    /// Get challenge statistics
    pub async fn get_challenge_statistics(&self) -> Result<ChallengeStatistics> {
        // Get total challenge count
        let total_challenges_row = sqlx::query("SELECT COUNT(*) as count FROM challenges")
            .fetch_one(&self.pool)
            .await?;
        let total_challenges: i64 = total_challenges_row.get("count");

        // Get total files count
        let total_files_row = sqlx::query("SELECT COUNT(*) as count FROM files")
            .fetch_one(&self.pool)
            .await?;
        let total_files: i64 = total_files_row.get("count");

        // Get challenges by file type
        let file_type_rows = sqlx::query(
            "SELECT f.file_type, COUNT(DISTINCT c.id) as count 
             FROM challenges c 
             JOIN files f ON c.id = f.challenge_id 
             GROUP BY f.file_type"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut challenges_by_type = HashMap::new();
        for row in file_type_rows {
            let file_type_str: String = row.get("file_type");
            let count: i64 = row.get("count");
            
            let file_type = match file_type_str.as_str() {
                "Image" => FileType::Image,
                "Binary" => FileType::Binary,
                "Pcap" => FileType::Pcap,
                "Pdf" => FileType::Pdf,
                "Zip" => FileType::Zip,
                "Javascript" => FileType::Javascript,
                "Html" => FileType::Html,
                "Text" => FileType::Text,
                "Unknown" | _ => FileType::Unknown,
            };
            challenges_by_type.insert(file_type, count as u32);
        }

        // Get recent activity (challenges in last 30 days)
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        let recent_activity_row = sqlx::query(
            "SELECT COUNT(*) as count FROM challenges WHERE created_at >= ?"
        )
        .bind(thirty_days_ago.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;
        let recent_activity: i64 = recent_activity_row.get("count");

        // Get average analysis results per challenge
        let avg_results_row = sqlx::query(
            "SELECT AVG(result_count) as avg_count FROM (
                SELECT COUNT(*) as result_count 
                FROM analysis_results 
                GROUP BY challenge_id
             ) subquery"
        )
        .fetch_optional(&self.pool)
        .await?;
        
        let avg_analysis_results = avg_results_row
            .and_then(|row| row.get::<Option<f64>, _>("avg_count"))
            .unwrap_or(0.0);

        Ok(ChallengeStatistics {
            total_challenges: total_challenges as u32,
            total_files: total_files as u32,
            challenges_by_type,
            recent_activity: recent_activity as u32,
            avg_analysis_results_per_challenge: avg_analysis_results as f32,
        })
    }

    /// Search challenges by name or context
    pub async fn search_challenges(&self, query: &str, limit: Option<u32>) -> Result<Vec<Challenge>> {
        let limit = limit.unwrap_or(100);
        let search_pattern = format!("%{}%", query);

        let rows = sqlx::query(
            "SELECT id, name, context, created_at FROM challenges 
             WHERE name LIKE ? OR context LIKE ? 
             ORDER BY created_at DESC LIMIT ?"
        )
        .bind(&search_pattern)
        .bind(&search_pattern)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut challenges = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)?;
            
            let mut challenge = Challenge {
                id,
                name: row.get("name"),
                context: row.get("context"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                files: Vec::new(),
                analysis_results: Vec::new(),
            };

            // Load associated files
            challenge.files = self.get_challenge_files(id).await?;
            
            // Load analysis results
            challenge.analysis_results = self.get_challenge_analysis_results(id).await?;

            challenges.push(challenge);
        }

        Ok(challenges)
    }

    /// Get files for a specific challenge
    async fn get_challenge_files(&self, challenge_id: Uuid) -> Result<Vec<ChallengeFile>> {
        let rows = sqlx::query(
            "SELECT id, original_name, file_type, size, hash, storage_path, metadata FROM files WHERE challenge_id = ?"
        )
        .bind(challenge_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut files = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)?;
            
            let file_type_str: String = row.get("file_type");
            let file_type = match file_type_str.as_str() {
                "Image" => FileType::Image,
                "Binary" => FileType::Binary,
                "Pcap" => FileType::Pcap,
                "Pdf" => FileType::Pdf,
                "Zip" => FileType::Zip,
                "Javascript" => FileType::Javascript,
                "Html" => FileType::Html,
                "Text" => FileType::Text,
                "Unknown" | _ => FileType::Unknown,
            };
            
            let metadata_json: String = row.get("metadata");
            let metadata: FileMetadata = serde_json::from_str(&metadata_json)?;

            files.push(ChallengeFile {
                id,
                original_name: row.get("original_name"),
                file_type,
                size: row.get::<i64, _>("size") as u64,
                hash: row.get("hash"),
                storage_path: PathBuf::from(row.get::<String, _>("storage_path")),
                metadata,
            });
        }

        Ok(files)
    }

    /// Get analysis results for a specific challenge
    async fn get_challenge_analysis_results(&self, challenge_id: Uuid) -> Result<Vec<AnalysisResult>> {
        let rows = sqlx::query(
            "SELECT file_id, analyzer, confidence, execution_time_ms, transformations, findings FROM analysis_results WHERE challenge_id = ?"
        )
        .bind(challenge_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let file_id_str: String = row.get("file_id");
            let file_id = Uuid::parse_str(&file_id_str)?;
            
            let transformations_json: String = row.get("transformations");
            let transformations: Vec<TransformationResult> = serde_json::from_str(&transformations_json)?;
            
            let findings_json: String = row.get("findings");
            let findings: Vec<Finding> = serde_json::from_str(&findings_json)?;
            
            let execution_time_ms: i64 = row.get("execution_time_ms");
            let execution_time = Duration::from_millis(execution_time_ms as u64);

            results.push(AnalysisResult {
                analyzer: row.get("analyzer"),
                file_id,
                transformations,
                findings,
                confidence: row.get("confidence"),
                execution_time,
            });
        }

        Ok(results)
    }
}

#[async_trait]
impl ChallengeStorage for SqliteStorage {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<()> {
        // Validate challenge before storing
        challenge.validate()?;

        // Start a transaction
        let mut tx = self.pool.begin().await?;

        // Insert challenge
        sqlx::query(
            "INSERT OR REPLACE INTO challenges (id, name, context, created_at) VALUES (?, ?, ?, ?)"
        )
        .bind(challenge.id.to_string())
        .bind(&challenge.name)
        .bind(&challenge.context)
        .bind(challenge.created_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;

        // Insert files
        for file in &challenge.files {
            // Store file type as simple string instead of JSON to avoid serialization issues
            let file_type_str = match file.file_type {
                FileType::Image => "Image",
                FileType::Binary => "Binary",
                FileType::Pcap => "Pcap",
                FileType::Pdf => "Pdf",
                FileType::Zip => "Zip",
                FileType::Javascript => "Javascript",
                FileType::Html => "Html",
                FileType::Text => "Text",
                FileType::Unknown => "Unknown",
            };
            let metadata_json = serde_json::to_string(&file.metadata)?;

            sqlx::query(
                "INSERT OR REPLACE INTO files (id, challenge_id, original_name, file_type, size, hash, storage_path, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(file.id.to_string())
            .bind(challenge.id.to_string())
            .bind(&file.original_name)
            .bind(file_type_str)
            .bind(file.size as i64)
            .bind(&file.hash)
            .bind(file.storage_path.to_string_lossy().to_string())
            .bind(metadata_json)
            .execute(&mut *tx)
            .await?;
        }

        // Insert analysis results
        for result in &challenge.analysis_results {
            result.validate()?;
            
            let transformations_json = serde_json::to_string(&result.transformations)?;
            let findings_json = serde_json::to_string(&result.findings)?;

            sqlx::query(
                "INSERT INTO analysis_results (challenge_id, file_id, analyzer, confidence, execution_time_ms, transformations, findings, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(challenge.id.to_string())
            .bind(result.file_id.to_string())
            .bind(&result.analyzer)
            .bind(result.confidence)
            .bind(result.execution_time.as_millis() as i64)
            .bind(transformations_json)
            .bind(findings_json)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // Commit transaction
        tx.commit().await?;

        info!("Stored challenge: {} ({})", challenge.name, challenge.id);
        Ok(())
    }

    async fn get_challenge(&self, id: Uuid) -> Result<Option<Challenge>> {
        let row = sqlx::query(
            "SELECT id, name, context, created_at FROM challenges WHERE id = ?"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let mut challenge = Challenge {
                id,
                name: row.get("name"),
                context: row.get("context"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                files: Vec::new(),
                analysis_results: Vec::new(),
            };

            // Load associated files
            challenge.files = self.get_challenge_files(id).await?;
            
            // Load analysis results
            challenge.analysis_results = self.get_challenge_analysis_results(id).await?;

            Ok(Some(challenge))
        } else {
            Ok(None)
        }
    }

    async fn list_challenges(&self) -> Result<Vec<Challenge>> {
        self.list_challenges_filtered(None, None).await
    }

    async fn delete_challenge(&self, id: Uuid) -> Result<()> {
        // Start a transaction
        let mut tx = self.pool.begin().await?;

        // Get files to delete from filesystem
        let files = self.get_challenge_files(id).await?;

        // Delete challenge (cascades to files and analysis_results due to foreign keys)
        let result = sqlx::query("DELETE FROM challenges WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("Challenge not found: {}", id));
        }

        // Commit transaction
        tx.commit().await?;

        // Delete files from filesystem
        for file in files {
            if let Err(e) = fs::remove_file(&file.storage_path).await {
                warn!("Failed to delete file {}: {}", file.storage_path.display(), e);
            }
        }

        info!("Deleted challenge: {}", id);
        Ok(())
    }
}

#[async_trait]
impl FileStorage for SqliteStorage {
    async fn store_file(&self, file_data: &[u8], original_name: &str) -> Result<ChallengeFile> {
        // Validate file size
        self.security_validator.validate_file_size(file_data)?;
        
        // Validate file content for basic security
        self.security_validator.validate_file_content(file_data, original_name)?;
        
        // Check if file type is allowed
        if !self.security_validator.is_file_type_allowed(file_data) {
            return Err(anyhow!("File type not allowed for security reasons"));
        }

        let file_id = Uuid::new_v4();
        let hash = Self::calculate_hash(file_data);
        let storage_path = self.generate_file_path(original_name)?;

        // Validate the generated path is secure
        self.security_validator.validate_path(&storage_path, &self.file_storage_path)?;

        // Write file to storage
        fs::write(&storage_path, file_data).await?;

        // Detect file type using file analyzer
        let file_type = self.file_analyzer.detect_file_type(file_data);
        
        // Extract metadata using file analyzer
        let metadata = self.file_analyzer.extract_metadata(file_data, &file_type)?;

        let challenge_file = ChallengeFile {
            id: file_id,
            original_name: original_name.to_string(),
            file_type: file_type.clone(),
            size: file_data.len() as u64,
            hash,
            storage_path,
            metadata,
        };

        info!("Stored file: {} ({}) - Type: {}", original_name, file_id, file_type);
        Ok(challenge_file)
    }

    async fn get_file(&self, id: Uuid) -> Result<Option<Vec<u8>>> {
        // Get file info from database
        let row = sqlx::query(
            "SELECT storage_path FROM files WHERE id = ?"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let storage_path: String = row.get("storage_path");
            let path = PathBuf::from(storage_path);

            match fs::read(&path).await {
                Ok(data) => Ok(Some(data)),
                Err(e) => {
                    error!("Failed to read file {}: {}", path.display(), e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    async fn delete_file(&self, id: Uuid) -> Result<()> {
        // Get file info from database
        let row = sqlx::query(
            "SELECT storage_path FROM files WHERE id = ?"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let storage_path: String = row.get("storage_path");
            let path = PathBuf::from(storage_path);

            // Delete from database
            sqlx::query("DELETE FROM files WHERE id = ?")
                .bind(id.to_string())
                .execute(&self.pool)
                .await?;

            // Delete from filesystem
            if let Err(e) = fs::remove_file(&path).await {
                warn!("Failed to delete file {}: {}", path.display(), e);
            }

            info!("Deleted file: {}", id);
            Ok(())
        } else {
            Err(anyhow!("File not found: {}", id))
        }
    }
}