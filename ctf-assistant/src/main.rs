use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tracing::{info, Level};
use tracing_subscriber;

mod cli;
mod web;
mod output;

#[derive(Parser)]
#[command(name = "ctf-assistant")]
#[command(about = "A CTF AI Assistant for analyzing challenges and providing hints")]
#[command(long_about = "
The CTF AI Assistant helps analyze Capture The Flag challenges by automatically applying
common decoding techniques, steganography detection, and providing educational hints.

EXAMPLES:
    # Analyze a single file with description
    ctf-assistant analyze -f challenge.jpg -d \"Hidden message in image\"
    
    # Analyze with verbose output and JSON format
    ctf-assistant analyze --file data.txt --description \"Encoded text\" --verbose --format json
    
    # Start web interface on custom port
    ctf-assistant web --port 8080
    
    # Show challenge history
    ctf-assistant history --limit 10
")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose output with detailed processing steps
    #[arg(short, long, global = true, help = "Show detailed processing information")]
    verbose: bool,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum OutputFormat {
    /// Human-readable text output with colors
    Text,
    /// Structured JSON output
    Json,
    /// Compact single-line format
    Compact,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a file or challenge via command line
    #[command(alias = "a")]
    Analyze {
        /// Path to the file to analyze
        #[arg(short, long, help = "Path to the challenge file to analyze")]
        file: String,
        
        /// Challenge description or context
        #[arg(short, long, help = "Description or context about the challenge")]
        description: Option<String>,
        
        /// Output format for analysis results
        #[arg(long, value_enum, default_value = "text", help = "Format for displaying results")]
        format: OutputFormat,
        
        /// Skip AI hint generation
        #[arg(long, help = "Skip AI-powered hint generation")]
        no_hints: bool,
        
        /// Maximum analysis depth for recursive decoding
        #[arg(long, default_value = "5", help = "Maximum depth for recursive decoding (1-10)")]
        max_depth: u8,
    },
    
    /// Start the web interface
    #[command(alias = "w")]
    Web {
        /// Port to bind the web server to
        #[arg(short, long, default_value = "3000", help = "Port number for the web server")]
        port: u16,
        
        /// Host address to bind to
        #[arg(long, default_value = "127.0.0.1", help = "Host address to bind the server")]
        host: String,
    },
    
    /// Show challenge analysis history
    #[command(alias = "h")]
    History {
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20", help = "Number of recent entries to display")]
        limit: usize,
        
        /// Filter by challenge type
        #[arg(short, long, help = "Filter by file type (e.g., image, binary, web)")]
        filter: Option<String>,
        
        /// Output format for history display
        #[arg(long, value_enum, default_value = "text", help = "Format for displaying history")]
        format: OutputFormat,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize tracing with appropriate level
    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
    
    if cli.verbose {
        info!("Starting CTF Assistant in verbose mode");
    }
    
    match cli.command {
        Commands::Analyze { 
            file, 
            description, 
            format, 
            no_hints, 
            max_depth 
        } => {
            // Validate max_depth parameter
            if max_depth == 0 || max_depth > 10 {
                eprintln!("Error: max-depth must be between 1 and 10");
                std::process::exit(1);
            }
            
            cli::analyze_command(file, description, format, no_hints, max_depth, cli.verbose).await
        }
        Commands::Web { port, host } => {
            web::start_server(host, port).await
        }
        Commands::History { limit, filter, format } => {
            cli::history_command(limit, filter, format, cli.verbose).await
        }
    }
}