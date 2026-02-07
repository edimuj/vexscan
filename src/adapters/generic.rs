//! Generic adapter for scanning arbitrary directories.

use super::{ComponentType, DiscoveredComponent, PlatformAdapter};
use crate::types::Platform;
use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Generic adapter that scans any directory.
pub struct GenericAdapter {
    /// File extensions to scan.
    extensions: Vec<&'static str>,
}

impl GenericAdapter {
    pub fn new() -> Self {
        Self {
            extensions: vec![
                "js", "ts", "mjs", "cjs", // JavaScript/TypeScript
                "py",  // Python
                "json", "yaml", "yml", "toml", // Config
                "md", "txt", // Documentation/prompts
                "sh", "bash", "zsh", // Shell scripts
                "ps1", "psm1", "psd1", // PowerShell
                "bat", "cmd", // Windows batch
            ],
        }
    }

    fn get_component_type(ext: &str) -> ComponentType {
        match ext {
            "js" | "ts" | "mjs" | "cjs" | "py" => ComponentType::Plugin,
            "json" | "yaml" | "yml" | "toml" => ComponentType::Config,
            "md" | "txt" => ComponentType::Prompt,
            "sh" | "bash" | "zsh" | "ps1" | "psm1" | "psd1" | "bat" | "cmd" => ComponentType::Hook,
            _ => ComponentType::Other,
        }
    }
}

impl Default for GenericAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformAdapter for GenericAdapter {
    fn platform(&self) -> Platform {
        Platform::Generic
    }

    fn is_present(&self) -> bool {
        true // Generic adapter is always available
    }

    fn default_paths(&self) -> Vec<PathBuf> {
        vec![PathBuf::from(".")] // Current directory
    }

    fn discover(&self) -> Result<Vec<DiscoveredComponent>> {
        self.discover_at(&PathBuf::from("."))
    }

    fn discover_at(&self, path: &Path) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if self.extensions.contains(&ext) {
                components.push(DiscoveredComponent {
                    path: path.to_path_buf(),
                    component_type: Self::get_component_type(ext),
                    name: path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                });
            }
            return Ok(components);
        }

        // Walk directory
        for entry in WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_entry(|e| {
                // Skip common directories we don't want to scan
                let name = e.file_name().to_str().unwrap_or("");
                !matches!(
                    name,
                    "node_modules"
                        | ".git"
                        | ".svn"
                        | "target"
                        | "dist"
                        | "build"
                        | "__pycache__"
                        | ".venv"
                        | "venv"
                )
            })
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            if entry_path.is_file() {
                let ext = entry_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                if self.extensions.contains(&ext) {
                    components.push(DiscoveredComponent {
                        path: entry_path.to_path_buf(),
                        component_type: Self::get_component_type(ext),
                        name: entry_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string(),
                    });
                }
            }
        }

        Ok(components)
    }
}
