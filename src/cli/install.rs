use std::{env, fs};
use std::time::Duration;
use std::path::Path;
use std::error::Error;
use std::sync::Arc;

use reqwest::Client;
use urlencoding::encode;
use indicatif::{ProgressBar, ProgressStyle};
use futures::future::join_all;
use colored::Colorize;

use tokio::fs as async_fs;
use tokio::sync::mpsc;
use tokio::task;

use log::{info, error};
use crate::auth::Authenticator;

#[derive(Debug)]
enum ProgressUpdate {
    Increment, Finish,
    Message(String),
    Total(u64),
}
const FIREBASE_BUCKET: &str = "rpm-id.firebasestorage.app";

pub async fn install(package: &str) -> Result<(), Box<dyn Error>> {
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let manifest_path = current_dir.join("rush.toml");
    if !manifest_path.exists() {
        error!("rush.toml not found in the current directory! Please initialize Rush first.");
        std::process::exit(1);
    }
    let auth = Authenticator::new(Duration::from_secs(300))?;
    let access_token = match auth.get_token().await {
        Ok(token) => Arc::new(token),
        Err(e) => {
            error!("Authentication failed: {}", e);
            return Err(Box::new(e));
        }
    };
    let parts: Vec<&str> = package.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid package format. Try using: creator/package".into());
    }
    let (creator, module_name) = (parts[0], parts[1]);
    let storage_folder_path = format!("{}/{}/", creator, module_name).trim_end_matches('/').to_string() + "/";
    let encoded_storage_path = encode(&storage_folder_path);

    let list_files_url = format!(
        "https://firebasestorage.googleapis.com/v0/b/{}/o?prefix={}&alt=json",
        FIREBASE_BUCKET, encoded_storage_path
    );
    info!("{} {}", "Fetching".bright_green(), "dependencies");

    let client = Client::new();
    let response = client
        .get(&list_files_url)
        .bearer_auth(&access_token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_message = response.text().await?; //Handle error here
        return Err(format!("Failed to fetch file list. Status: {}, Message: {}", status, error_message).into());
    }
    let response_text = response.text().await?;
    let response_json: serde_json::Value = serde_json::from_str(&response_text)?;
    let items = response_json["items"].as_array().ok_or("Failed to parse Firebase response")?;

    if items.is_empty() {
        error!("Package \"{}\" not found!", package);
        return Err("Cannot install user-created package.".into());
    }
    let local_module_path = format!("Packages/{}", module_name);
    if !Path::new(&local_module_path).exists() { fs::create_dir_all(&local_module_path)?; }

    let (tx, mut rx) = mpsc::channel(32);
    let pb_handle = task::spawn(async move {
        let pb = ProgressBar::new(0);
        let style_result = ProgressStyle::default_bar()
            .template("    {spinner:.bright_green} [ {bar:40.cyan/blue} ] {pos}/{len}: {msg}")
            .and_then(|style| Ok(style.progress_chars("=-")))
            .and_then(|style| Ok(style.tick_chars("⠋⠙⠚⠞⠖⠦⠤")));

        match style_result {
            Ok(style) => pb.set_style(style),
            Err(e) => error!("Error setting progress bar style: {}", e),
        }
        let mut _elapsed_time = 0.0;
        while let Some(update) = rx.recv().await {
            match update {
                ProgressUpdate::Increment => pb.inc(1),
                ProgressUpdate::Message(msg) => pb.set_message(msg),
                ProgressUpdate::Total(total) => pb.set_length(total),
                ProgressUpdate::Finish => pb.finish_and_clear(),
            }
        }
        _elapsed_time = pb.elapsed().as_secs_f64();
        _elapsed_time
    });
    let pb_len = items.len() as u64;
    tx.send(ProgressUpdate::Total(pb_len)).await?;
    tx.send(ProgressUpdate::Message(String::from("Starting download"))).await?;

    let download_futures: Vec<_> = items
        .iter()
        .enumerate()
        .map(|(_i, item)| {
            let file_path = item["name"].as_str().unwrap();
            let file_name = file_path.split('/').last().unwrap_or("unknown").to_string();
            let relative_path = file_path.strip_prefix(&storage_folder_path).unwrap_or(file_path);
            let local_file_path = Path::new(&local_module_path).join(relative_path);

            if let Some(parent) = local_file_path.parent() {
                if !parent.exists() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        error!("Failed to create directory {}: {}", parent.display(), e);
                    }
                }
            }
            let download_url = format!(
                "https://firebasestorage.googleapis.com/v0/b/{}/o/{}?alt=media",
                FIREBASE_BUCKET, encode(file_path)
            );
            let access_token_clone = access_token.clone();
            let tx_clone = tx.clone();
            let client_clone = client.clone();

            task::spawn(async move {
                let response_result = client_clone
                    .get(&download_url)
                    .bearer_auth(&access_token_clone)
                    .send().await;
                
                match response_result {
                    Ok(response) => {
                        let res_result = response.bytes().await;
                        match res_result {
                            Ok(bytes) => {
                                let _ = async_fs::write(&local_file_path, bytes).await;
                                let _ = tx_clone.send(ProgressUpdate::Increment).await; // send update
                                let _ = tx_clone.send(ProgressUpdate::Message(file_name)).await; // send message
                                Ok::<_, Box<dyn Error + Send>>(())
                            }
                            Err(e) => {
                                error!("{}", format!("Failed to read bytes from response {}: {}", file_name, e).as_str());
                                Err(Box::new(e) as Box<dyn Error + Send>)
                            }
                        }
                    }
                    Err(e) => {
                        error!("{}", format!("Request error: {}", e).as_str());
                        Err(Box::new(e) as Box<dyn Error + Send>)
                    }
                }
            })
        })
        .collect();

    let results = join_all(download_futures).await;
    let _ = tx.send(ProgressUpdate::Finish).await;
    drop(tx); // close the sender to signal completion to the pb task
    let elapsed_seconds = pb_handle.await?;

    let failures = results.iter().filter(|r| r.is_err()).count();
    if failures > 0 {
        return Err(format!(
            "{} files was failed to download!", 
            failures.to_string().bold()
        ).into());
    }
    info!(
        "{} {}", "Done".bright_green(),
        format!("adding \"{}\" in {:.3}s", package, elapsed_seconds)
    );
    Ok(())
}