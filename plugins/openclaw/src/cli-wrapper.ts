import { spawn } from "child_process";
import { existsSync } from "fs";
import { homedir, platform, arch } from "os";
import { join } from "path";
import type { ExecResult } from "./types.js";

const REPO = "edimuj/vetryx";
const INSTALL_DIR = join(homedir(), ".local", "bin");

/**
 * Common locations to search for the vetryx binary
 */
const SEARCH_PATHS = [
  join(INSTALL_DIR, "vetryx"),
  join(homedir(), ".cargo", "bin", "vetryx"),
  "/usr/local/bin/vetryx",
  "/opt/homebrew/bin/vetryx",
];

/**
 * Find vetryx binary in common locations
 */
export async function findVetryx(): Promise<string | null> {
  // Check if in PATH
  const inPath = await checkInPath("vetryx");
  if (inPath) return "vetryx";

  // Check common locations
  for (const path of SEARCH_PATHS) {
    if (existsSync(path)) {
      return path;
    }
  }

  return null;
}

/**
 * Check if a command exists in PATH
 */
async function checkInPath(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn("which", [cmd], { stdio: "pipe" });
    proc.on("close", (code) => resolve(code === 0));
    proc.on("error", () => resolve(false));
  });
}

/**
 * Install vetryx from GitHub releases
 */
export async function installVetryx(): Promise<string | null> {
  const os = platform();
  const cpu = arch();

  // Determine asset name
  let osName: string;
  switch (os) {
    case "darwin":
      osName = "macos";
      break;
    case "linux":
      osName = "linux";
      break;
    default:
      return null; // Windows not supported via this method
  }

  let archName: string;
  switch (cpu) {
    case "x64":
      archName = "x86_64";
      break;
    case "arm64":
      archName = "aarch64";
      break;
    default:
      return null;
  }

  const assetName = `vetryx-${osName}-${archName}`;

  try {
    // Get latest version
    const response = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`);
    if (!response.ok) return null;

    const release = (await response.json()) as { tag_name: string };
    const version = release.tag_name;

    const downloadUrl = `https://github.com/${REPO}/releases/download/${version}/${assetName}`;

    // Download binary
    const binaryResponse = await fetch(downloadUrl);
    if (!binaryResponse.ok) return null;

    const binary = await binaryResponse.arrayBuffer();

    // Write to install dir
    const { mkdir, writeFile, chmod } = await import("fs/promises");
    await mkdir(INSTALL_DIR, { recursive: true });

    const binaryPath = join(INSTALL_DIR, "vetryx");
    await writeFile(binaryPath, Buffer.from(binary));
    await chmod(binaryPath, 0o755);

    return binaryPath;
  } catch {
    return null;
  }
}

/**
 * Execute vetryx CLI with arguments
 */
export async function execVetryx(cliPath: string, args: string[]): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cliPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 0,
      });
    });

    proc.on("error", (err) => {
      reject(err);
    });
  });
}
