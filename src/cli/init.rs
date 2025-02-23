use std::io;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use log::{info, error};

const CONFIG_FILE: &str = "rush.toml";

pub fn init(project_name: Option<String>) -> io::Result<()> {
    if Path::new(CONFIG_FILE).exists() {
        error!("{} already exists in this project", CONFIG_FILE);
        return Ok(());
    }
    let project_name = match project_name {
        Some(name) => name,
        None => {
            match std::env::current_dir() {
                Ok(dir) => dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("my-project")
                    .to_string(),
                Err(_) => "my-project".to_string(),
            }
        }
    };
    let mut file = File::create(CONFIG_FILE)?;
    let default_content = format!(
        "[package]\nname = \"{}\"\nversion = \"0.1.0\"\n\n[dependencies]\n",
        project_name
    );
    file.write_all(default_content.as_bytes())?;
    
    info!("Initialized package manager file in {}", CONFIG_FILE);
    Ok(())
}
