import { Type, type Static } from "@sinclair/typebox";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { execCommand, execVexscan, findVexscan, installVexscan } from "./src/cli-wrapper.js";
import type { ScanResult, VetResult } from "./src/types.js";

// --- Config schema (TypeBox) ---

const ConfigSchema = Type.Object({
  enabled: Type.Boolean({ default: true }),
  scanOnInstall: Type.Boolean({ default: true }),
  minSeverity: Type.Union(
    [
      Type.Literal("info"),
      Type.Literal("low"),
      Type.Literal("medium"),
      Type.Literal("high"),
      Type.Literal("critical"),
    ],
    { default: "medium" },
  ),
  thirdPartyOnly: Type.Boolean({ default: true }),
  skipDeps: Type.Boolean({ default: true }),
  ast: Type.Boolean({ default: true }),
  deps: Type.Boolean({ default: true }),
  cliPath: Type.Optional(Type.String()),
});

type Config = Static<typeof ConfigSchema>;

// --- Tool parameter schema ---

const VexscanToolSchema = Type.Union([
  Type.Object({
    action: Type.Literal("scan"),
    path: Type.Optional(Type.String({ description: "Path to scan (defaults to extensions dir)" })),
    thirdPartyOnly: Type.Optional(Type.Boolean({ description: "Only scan third-party extensions" })),
  }),
  Type.Object({
    action: Type.Literal("vet"),
    source: Type.String({ description: "GitHub URL or local path to vet" }),
    branch: Type.Optional(Type.String({ description: "Git branch to check" })),
  }),
  Type.Object({
    action: Type.Literal("install"),
    source: Type.String({ description: "npm spec, local path, or GitHub URL to vet and install" }),
    branch: Type.Optional(Type.String({ description: "Git branch to check" })),
    force: Type.Optional(Type.Boolean({ description: "Allow medium severity findings" })),
    allowHigh: Type.Optional(Type.Boolean({ description: "Allow high severity findings (dangerous)" })),
    link: Type.Optional(Type.Boolean({ description: "Symlink instead of copy (for development)" })),
  }),
  Type.Object({
    action: Type.Literal("status"),
  }),
]);

// --- Helpers ---

function parseConfig(value: unknown): Config {
  const raw = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  return {
    enabled: raw.enabled !== false,
    scanOnInstall: raw.scanOnInstall !== false,
    minSeverity: (raw.minSeverity as Config["minSeverity"]) || "medium",
    thirdPartyOnly: raw.thirdPartyOnly !== false,
    skipDeps: raw.skipDeps !== false,
    ast: raw.ast !== false,
    deps: raw.deps !== false,
    cliPath: typeof raw.cliPath === "string" ? raw.cliPath : undefined,
  };
}

function getVerdict(findings: number, maxSeverity: string | null): string {
  if (!findings) return "clean";
  if (maxSeverity === "critical") return "dangerous";
  if (maxSeverity === "high") return "high_risk";
  return "warnings";
}

function getVerdictMessage(verdict: string, findings: number, maxSeverity: string | null): string {
  switch (verdict) {
    case "clean":
      return "No security issues found. Safe to use.";
    case "warnings":
      return `Found ${findings} issue(s), max severity: ${maxSeverity}. Review recommended before use.`;
    case "high_risk":
      return `Found ${findings} issue(s) including HIGH severity. Careful review required before use.`;
    case "dangerous":
      return `Found ${findings} issue(s) including CRITICAL severity. Do NOT use without thorough review.`;
    default:
      return `Found ${findings} issue(s).`;
  }
}

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function checkInstallGate(
  maxSeverity: string | null | undefined,
  force: boolean,
  allowHigh: boolean,
): { allowed: boolean; reason?: string } {
  const rank = SEVERITY_RANK[maxSeverity ?? ""] ?? -1;

  if (rank >= SEVERITY_RANK.critical) {
    return { allowed: false, reason: "CRITICAL severity findings — installation blocked. Cannot override." };
  }
  if (rank >= SEVERITY_RANK.high && !allowHigh) {
    return { allowed: false, reason: "HIGH severity findings — installation blocked. Use allowHigh/--allow-high to override." };
  }
  if (rank >= SEVERITY_RANK.medium && !force) {
    return { allowed: false, reason: "MEDIUM severity findings — installation blocked. Use force/--force to override." };
  }
  return { allowed: true };
}

// --- Plugin ---

const vexscanPlugin = {
  id: "openclaw-vexscan",
  name: "Vexscan Security Scanner",
  description: "Security scanner for OpenClaw extensions, skills, and configurations",
  kind: "tool" as const,
  configSchema: ConfigSchema,

  register(api: OpenClawPluginApi) {
    const config = parseConfig(api.pluginConfig);
    let cliPath: string | null = null;

    const ensureCli = async (): Promise<string> => {
      if (cliPath) return cliPath;

      if (config.cliPath) {
        cliPath = config.cliPath;
        return cliPath;
      }

      const found = await findVexscan();
      if (found) {
        cliPath = found;
        return cliPath;
      }

      api.logger.info("[vexscan] CLI not found, attempting auto-install...");
      const installed = await installVexscan();
      if (installed) {
        cliPath = installed;
        api.logger.info(`[vexscan] CLI installed to ${cliPath}`);
        return cliPath;
      }

      throw new Error(
        "Vexscan CLI not found. Install with: curl -fsSL https://raw.githubusercontent.com/edimuj/vexscan/main/install.sh | bash",
      );
    };

    // Register the security scanner tool
    api.registerTool({
      name: "vexscan",
      description:
        "Scan extensions and code for security threats including prompt injection, malicious code, obfuscation, and data exfiltration.",
      parameters: VexscanToolSchema,

      async execute(_toolCallId: string, params: Record<string, unknown>) {
        const json = (payload: unknown) => ({
          content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
          details: payload,
        });

        try {
          if (!config.enabled) {
            return json({ ok: false, error: "Vexscan is disabled in plugin config" });
          }

          const cli = await ensureCli();

          if (params.action === "status") {
            return json({
              ok: true,
              enabled: config.enabled,
              cliPath: cli,
              config: {
                minSeverity: config.minSeverity,
                thirdPartyOnly: config.thirdPartyOnly,
                skipDeps: config.skipDeps,
                ast: config.ast,
                deps: config.deps,
                scanOnInstall: config.scanOnInstall,
              },
            });
          }

          if (params.action === "scan") {
            const scanPath = (params.path as string) || "~/.openclaw/extensions";
            const args = ["scan", scanPath, "-f", "json", "--min-severity", config.minSeverity];

            if (config.ast) args.push("--ast");
            if (config.deps) args.push("--deps");
            if (config.skipDeps) args.push("--skip-deps");
            if ((params.thirdPartyOnly as boolean | undefined) ?? config.thirdPartyOnly) {
              args.push("--third-party-only");
            }

            const result = await execVexscan(cli, args);
            const parsed = JSON.parse(result.stdout) as ScanResult;

            return json({
              ok: true,
              findings: parsed.total_findings || 0,
              maxSeverity: parsed.max_severity || null,
              summary: parsed.findings_by_severity || {},
              scanTime: parsed.total_time_ms,
            });
          }

          if (params.action === "vet") {
            const args = ["vet", params.source as string, "-f", "json"];
            if (config.ast) args.push("--ast");
            if (config.deps) args.push("--deps");
            if (config.skipDeps) args.push("--skip-deps");
            if (params.branch) {
              args.push("--branch", params.branch as string);
            }

            const result = await execVexscan(cli, args);
            const parsed = JSON.parse(result.stdout) as VetResult;
            const findings = parsed.total_findings || 0;
            const maxSeverity = parsed.max_severity || null;
            const verdict = getVerdict(findings, maxSeverity);

            const response: Record<string, unknown> = {
              ok: true,
              verdict,
              findings,
              message: getVerdictMessage(verdict, findings, maxSeverity),
            };
            if (findings > 0) response.maxSeverity = maxSeverity;

            return json(response);
          }

          if (params.action === "install") {
            // Step 1: Vet the source
            const vetArgs = ["vet", params.source as string, "-f", "json"];
            if (config.ast) vetArgs.push("--ast");
            if (config.deps) vetArgs.push("--deps");
            if (config.skipDeps) vetArgs.push("--skip-deps");
            if (params.branch) vetArgs.push("--branch", params.branch as string);

            const vetResult = await execVexscan(cli, vetArgs);
            const parsed = JSON.parse(vetResult.stdout) as VetResult;
            const findings = parsed.total_findings || 0;
            const maxSeverity = parsed.max_severity || null;
            const verdict = getVerdict(findings, maxSeverity);

            // Step 2: Check severity gate
            const gate = checkInstallGate(
              maxSeverity,
              (params.force as boolean) || false,
              (params.allowHigh as boolean) || false,
            );

            if (!gate.allowed) {
              return json({
                ok: false,
                action: "install_blocked",
                verdict,
                findings,
                maxSeverity,
                reason: gate.reason,
                message: getVerdictMessage(verdict, findings, maxSeverity),
              });
            }

            // Step 3: Install via openclaw
            const installArgs = ["plugins", "install"];
            if (params.link) installArgs.push("-l");
            installArgs.push(params.source as string);

            const installResult = await execCommand("openclaw", installArgs);
            if (installResult.exitCode !== 0) {
              return json({
                ok: false,
                error: `Installation failed: ${installResult.stderr || installResult.stdout}`.trim(),
              });
            }

            return json({
              ok: true,
              action: "installed",
              source: params.source,
              findings,
              message: findings
                ? `Installed with ${findings} finding(s) (max: ${maxSeverity}). Review recommended.`
                : "Installed. No security issues found.",
            });
          }

          return json({ ok: false, error: "Unknown action" });
        } catch (err) {
          return json({
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      },
    });

    // Register CLI commands
    api.registerCli(
      ({ program }) => {
        const vexscan = program.command("vexscan").description("Security scanner for extensions");

        vexscan
          .command("scan [path]")
          .description("Scan extensions for security issues")
          .option("-f, --format <format>", "Output format (cli, json, sarif, markdown)", "cli")
          .option("--third-party-only", "Only scan third-party extensions")
          .option("--min-severity <level>", "Minimum severity to report", config.minSeverity)
          .action(async (path: string | undefined, opts: any) => {
            try {
              const cli = await ensureCli();
              const scanPath = path || "~/.openclaw/extensions";
              const args = ["scan", scanPath, "-f", opts.format, "--min-severity", opts.minSeverity];
              if (config.ast) args.push("--ast");
              if (config.deps) args.push("--deps");
              if (config.skipDeps) args.push("--skip-deps");
              if (opts.thirdPartyOnly) args.push("--third-party-only");

              const result = await execVexscan(cli, args);
              console.log(result.stdout);
              if (result.stderr) console.error(result.stderr);
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });

        vexscan
          .command("vet <source>")
          .description("Vet an extension before installing")
          .option("-f, --format <format>", "Output format (cli, json)", "cli")
          .option("--branch <branch>", "Git branch to check")
          .option("--keep", "Keep cloned repo after scan")
          .action(async (source: string, opts: any) => {
            try {
              const cli = await ensureCli();
              const args = ["vet", source, "-f", opts.format];
              if (config.ast) args.push("--ast");
              if (config.deps) args.push("--deps");
              if (config.skipDeps) args.push("--skip-deps");
              if (opts.branch) args.push("--branch", opts.branch);
              if (opts.keep) args.push("--keep");

              const result = await execVexscan(cli, args);
              console.log(result.stdout);
              if (result.stderr) console.error(result.stderr);
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });

        vexscan
          .command("install <source>")
          .description("Vet an extension and install if it passes")
          .option("-f, --format <format>", "Output format for vet report (cli, json)", "cli")
          .option("--branch <branch>", "Git branch to check")
          .option("-l, --link", "Symlink instead of copy (for development)")
          .option("--force", "Allow medium severity findings")
          .option("--allow-high", "Allow high severity findings (dangerous)")
          .option("--dry-run", "Vet only, show what would be installed")
          .action(async (source: string, opts: any) => {
            try {
              const cli = await ensureCli();

              // Step 1: Vet
              console.log(`Vetting ${source}...`);
              const vetArgs = ["vet", source, "-f", "json"];
              if (config.ast) vetArgs.push("--ast");
              if (config.deps) vetArgs.push("--deps");
              if (config.skipDeps) vetArgs.push("--skip-deps");
              if (opts.branch) vetArgs.push("--branch", opts.branch);

              const vetResult = await execVexscan(cli, vetArgs);
              const parsed = JSON.parse(vetResult.stdout) as VetResult;

              // Show vet report in requested format
              if (opts.format !== "json") {
                const reportArgs = ["vet", source, "-f", opts.format];
                if (config.ast) reportArgs.push("--ast");
                if (config.deps) reportArgs.push("--deps");
                if (config.skipDeps) reportArgs.push("--skip-deps");
                if (opts.branch) reportArgs.push("--branch", opts.branch);
                const report = await execVexscan(cli, reportArgs);
                console.log(report.stdout);
              } else {
                console.log(vetResult.stdout);
              }

              // Step 2: Check severity gate
              const gate = checkInstallGate(parsed.max_severity, opts.force, opts.allowHigh);
              if (!gate.allowed) {
                console.error(`\nInstallation blocked: ${gate.reason}`);
                process.exit(1);
              }

              if (opts.dryRun) {
                console.log("\n[dry-run] Would install:", source);
                return;
              }

              // Step 3: Install
              console.log("\nSecurity check passed. Installing...");
              const installArgs = ["plugins", "install"];
              if (opts.link) installArgs.push("-l");
              installArgs.push(source);

              const installResult = await execCommand("openclaw", installArgs);
              if (installResult.exitCode !== 0) {
                console.error("Installation failed:", installResult.stderr || installResult.stdout);
                process.exit(1);
              }
              console.log(installResult.stdout.trim());
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });

        vexscan
          .command("rules")
          .description("List detection rules")
          .option("--json", "Output as JSON")
          .option("--rule <id>", "Show specific rule")
          .action(async (opts: any) => {
            try {
              const cli = await ensureCli();
              const args = ["rules"];
              if (opts.json) args.push("--json");
              if (opts.rule) args.push("--rule", opts.rule);

              const result = await execVexscan(cli, args);
              console.log(result.stdout);
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });
      },
      { commands: ["vexscan"] },
    );

    // Register startup service for initial scan
    if (config.scanOnInstall) {
      api.registerService({
        id: "vexscan-startup",
        start: async () => {
          if (!config.enabled) return;

          try {
            const cli = await ensureCli();
            api.logger.info("[vexscan] Running startup security scan...");

            const args = ["scan", "~/.openclaw/extensions", "-f", "json", "--min-severity", "high"];
            if (config.ast) args.push("--ast");
            if (config.deps) args.push("--deps");
            if (config.skipDeps) args.push("--skip-deps");
            if (config.thirdPartyOnly) args.push("--third-party-only");

            const result = await execVexscan(cli, args);
            const parsed = JSON.parse(result.stdout) as ScanResult;

            if (parsed.total_findings && parsed.total_findings > 0) {
              api.logger.warn(
                `[vexscan] Security scan found ${parsed.total_findings} issue(s) with max severity: ${parsed.max_severity}`,
              );
            } else {
              api.logger.info("[vexscan] Security scan complete - no issues found");
            }
          } catch (err) {
            api.logger.error(
              `[vexscan] Startup scan failed: ${err instanceof Error ? err.message : err}`,
            );
          }
        },
        stop: async () => {},
      });
    }
  },
};

export default vexscanPlugin;
