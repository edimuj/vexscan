//! Claude Code adapter for discovering plugins, skills, MCPs, hooks, and config files.

use super::{ComponentType, DiscoveredComponent, PlatformAdapter};
use crate::types::Platform;
use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Adapter for Claude Code.
pub struct ClaudeCodeAdapter {
    home_dir: PathBuf,
}

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self { home_dir }
    }

    fn claude_dir(&self) -> PathBuf {
        self.home_dir.join(".claude")
    }

    fn claude_json(&self) -> PathBuf {
        self.home_dir.join(".claude.json")
    }

    /// Scan for plugins in the plugins directory.
    fn discover_plugins(&self) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();
        let plugins_dir = self.claude_dir().join("plugins");

        if !plugins_dir.exists() {
            return Ok(components);
        }

        for entry in WalkDir::new(&plugins_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let component_type = match ext {
                        "js" | "ts" | "mjs" | "cjs" => ComponentType::Plugin,
                        "json" => ComponentType::Config,
                        "md" => ComponentType::Prompt,
                        _ => continue,
                    };

                    components.push(DiscoveredComponent {
                        path: path.to_path_buf(),
                        component_type,
                        name: path
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

    /// Scan for hooks.
    fn discover_hooks(&self) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        // Check settings.json for hooks configuration
        let settings_path = self.claude_dir().join("settings.json");
        if settings_path.exists() {
            components.push(DiscoveredComponent {
                path: settings_path,
                component_type: ComponentType::Config,
                name: "settings.json".to_string(),
            });
        }

        // Check for hook scripts in hooks directory
        let hooks_dir = self.claude_dir().join("hooks");
        if hooks_dir.exists() {
            for entry in WalkDir::new(&hooks_dir)
                .max_depth(2)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() {
                    components.push(DiscoveredComponent {
                        path: path.to_path_buf(),
                        component_type: ComponentType::Hook,
                        name: path
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

    /// Scan for MCP server configurations.
    fn discover_mcp_servers(&self) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        // Global MCP config in settings.json
        let settings_path = self.claude_dir().join("settings.json");
        if settings_path.exists() {
            // Already added in hooks discovery, but mark for MCP scanning
            components.push(DiscoveredComponent {
                path: settings_path,
                component_type: ComponentType::McpServer,
                name: "settings.json (MCP)".to_string(),
            });
        }

        // Project-level .claude.json
        if self.claude_json().exists() {
            components.push(DiscoveredComponent {
                path: self.claude_json(),
                component_type: ComponentType::McpServer,
                name: ".claude.json".to_string(),
            });
        }

        Ok(components)
    }

    /// Scan for CLAUDE.md files.
    fn discover_claude_md(&self) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        // Global CLAUDE.md
        let global_claude_md = self.claude_dir().join("CLAUDE.md");
        if global_claude_md.exists() {
            components.push(DiscoveredComponent {
                path: global_claude_md,
                component_type: ComponentType::Prompt,
                name: "CLAUDE.md (global)".to_string(),
            });
        }

        // Also check home directory
        let home_claude_md = self.home_dir.join("CLAUDE.md");
        if home_claude_md.exists() {
            components.push(DiscoveredComponent {
                path: home_claude_md,
                component_type: ComponentType::Prompt,
                name: "CLAUDE.md (home)".to_string(),
            });
        }

        Ok(components)
    }

    /// Scan for skills (slash commands) in both legacy and new locations.
    ///
    /// Legacy: ~/.claude/commands/review.md
    /// New:    ~/.claude/skills/review/SKILL.md (with supporting files)
    fn discover_skills(&self) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        // Legacy location: ~/.claude/commands/
        let commands_dir = self.claude_dir().join("commands");
        if commands_dir.exists() {
            components.extend(self.scan_skill_directory(&commands_dir, "command")?);
        }

        // New location: ~/.claude/skills/
        let skills_dir = self.claude_dir().join("skills");
        if skills_dir.exists() {
            components.extend(self.scan_skill_directory(&skills_dir, "skill")?);
        }

        Ok(components)
    }

    /// Scan a directory for skill files and supporting content.
    fn scan_skill_directory(
        &self,
        dir: &std::path::Path,
        label: &str,
    ) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        for entry in WalkDir::new(dir)
            .max_depth(4) // skills/name/subdir/file
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    // Determine component type based on file extension
                    let component_type = match ext {
                        "md" => ComponentType::Prompt, // SKILL.md or command.md
                        "js" | "ts" | "mjs" | "cjs" | "py" => ComponentType::Plugin,
                        "sh" | "bash" | "zsh" => ComponentType::Hook,
                        "json" | "yaml" | "yml" => ComponentType::Config,
                        _ => continue,
                    };

                    // Get skill name from path
                    // For skills/review/SKILL.md -> "review"
                    // For commands/review.md -> "review"
                    let skill_name = if path.file_name().map(|n| n == "SKILL.md").unwrap_or(false) {
                        // New format: get parent directory name
                        path.parent()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                    } else {
                        // Legacy format or supporting file: use file stem
                        path.file_stem()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                    };

                    components.push(DiscoveredComponent {
                        path: path.to_path_buf(),
                        component_type,
                        name: format!("{}: {}", label, skill_name),
                    });
                }
            }
        }

        Ok(components)
    }
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformAdapter for ClaudeCodeAdapter {
    fn platform(&self) -> Platform {
        Platform::ClaudeCode
    }

    fn is_present(&self) -> bool {
        self.claude_dir().exists()
    }

    fn default_paths(&self) -> Vec<PathBuf> {
        vec![
            self.claude_dir(),
            self.claude_json(),
            self.home_dir.join("CLAUDE.md"),
        ]
    }

    fn discover(&self) -> Result<Vec<DiscoveredComponent>> {
        let mut all_components = Vec::new();

        all_components.extend(self.discover_plugins()?);
        all_components.extend(self.discover_hooks()?);
        all_components.extend(self.discover_mcp_servers()?);
        all_components.extend(self.discover_claude_md()?);
        all_components.extend(self.discover_skills()?);

        // Deduplicate by path, preferring specific types over generic Config
        all_components.sort_by(|a, b| {
            a.path.cmp(&b.path).then_with(|| {
                let priority = |ct: &ComponentType| match ct {
                    ComponentType::McpServer | ComponentType::Plugin | ComponentType::Hook => 0,
                    _ => 1,
                };
                priority(&a.component_type).cmp(&priority(&b.component_type))
            })
        });
        all_components.dedup_by(|a, b| a.path == b.path);

        Ok(all_components)
    }

    fn discover_at(&self, path: &Path) -> Result<Vec<DiscoveredComponent>> {
        let mut components = Vec::new();

        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let component_type = match ext {
                "js" | "ts" | "mjs" | "cjs" | "py" => ComponentType::Plugin,
                "json" | "yaml" | "yml" | "toml" => ComponentType::Config,
                "md" => ComponentType::Prompt,
                "sh" | "bash" | "zsh" | "ps1" | "psm1" | "psd1" | "bat" | "cmd" => {
                    ComponentType::Hook
                }
                _ => ComponentType::Other,
            };

            components.push(DiscoveredComponent {
                path: path.to_path_buf(),
                component_type,
                name: path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
            });
        } else if path.is_dir() {
            for entry in WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    let ext = entry_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    let component_type = match ext {
                        "js" | "ts" | "mjs" | "cjs" | "py" => ComponentType::Plugin,
                        "json" | "yaml" | "yml" | "toml" => ComponentType::Config,
                        "md" => ComponentType::Prompt,
                        "sh" | "bash" | "zsh" | "ps1" | "psm1" | "psd1" | "bat" | "cmd" => {
                            ComponentType::Hook
                        }
                        _ => continue, // Skip unknown file types
                    };

                    components.push(DiscoveredComponent {
                        path: entry_path.to_path_buf(),
                        component_type,
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

// Add dirs crate to Cargo.toml
