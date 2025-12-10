use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber;

mod cli;
mod web;

#[derive(Parser)]
#[command(name = "ctf-assistant")]
#[command(about = "A CTF AI Assistant for analyzing challenges and providing hints")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a file or challenge via command line
    Analyze {
        /// Path to the file to analyze
        #[arg(short, long)]
        file: String,
        
        /// Challenge description or context
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Start the web interface
    Web {
        /// Port to bind the web server to
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize tracing
    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();
    
    info!("Starting CTF Assistant");
    
    match cli.command {
        Commands::Analyze { file, description } => {
            cli::analyze_command(file, description).await
        }
        Commands::Web { port } => {
            web::start_server(port).await
        }
    }
}