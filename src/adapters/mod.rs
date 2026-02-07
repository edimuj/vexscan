//! Platform adapters for discovering and scanning AI agent components.

pub mod claude_code;
pub mod generic;

use crate::types::Platform;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// A discovered component to scan.
#[derive(Debug, Clone)]
pub struct DiscoveredComponent {
    /// Path to the component.
    pub path: PathBuf,
    /// Type of component.
    pub component_type: ComponentType,
    /// Human-readable name.
    pub name: String,
}

/// Types of components that can be discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentType {
    /// Plugin/skill code file.
    Plugin,
    /// Configuration file.
    Config,
    /// Hook script.
    Hook,
    /// Prompt/instruction file.
    Prompt,
    /// MCP server configuration.
    McpServer,
    /// Memory/context file.
    Memory,
    /// Other file type.
    Other,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentType::Plugin => write!(f, "plugin"),
            ComponentType::Config => write!(f, "config"),
            ComponentType::Hook => write!(f, "hook"),
            ComponentType::Prompt => write!(f, "prompt"),
            ComponentType::McpServer => write!(f, "mcp-server"),
            ComponentType::Memory => write!(f, "memory"),
            ComponentType::Other => write!(f, "other"),
        }
    }
}

/// Trait for platform-specific adapters.
pub trait PlatformAdapter {
    /// Get the platform this adapter handles.
    fn platform(&self) -> Platform;

    /// Check if this platform is installed/present on the system.
    fn is_present(&self) -> bool;

    /// Get the default paths to scan for this platform.
    fn default_paths(&self) -> Vec<PathBuf>;

    /// Discover all components for this platform.
    fn discover(&self) -> Result<Vec<DiscoveredComponent>>;

    /// Discover components at a specific path.
    fn discover_at(&self, path: &Path) -> Result<Vec<DiscoveredComponent>>;
}

/// Create an adapter for the specified platform.
pub fn create_adapter(platform: Platform) -> Box<dyn PlatformAdapter> {
    match platform {
        Platform::ClaudeCode => Box::new(claude_code::ClaudeCodeAdapter::new()),
        Platform::Generic => Box::new(generic::GenericAdapter::new()),
        // Other platforms use generic adapter for now
        _ => Box::new(generic::GenericAdapter::new()),
    }
}

/// Try to auto-detect which platform is present.
pub fn detect_platform() -> Option<Platform> {
    // Check for Claude Code first
    if claude_code::ClaudeCodeAdapter::new().is_present() {
        return Some(Platform::ClaudeCode);
    }

    // TODO: Add detection for other platforms
    // - OpenClaw
    // - Cursor
    // - Codex

    None
}
