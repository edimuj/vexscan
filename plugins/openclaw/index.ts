import { Type } from "@sinclair/typebox";
import { execVetryx, findVetryx, installVetryx } from "./src/cli-wrapper.js";
import type { VetryxConfig, ScanResult, VetResult } from "./src/types.js";

const VetryxToolSchema = Type.Union([
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
    action: Type.Literal("status"),
  }),
]);

interface PluginConfig {
  enabled?: boolean;
  scanOnInstall?: boolean;
  minSeverity?: string;
  thirdPartyOnly?: boolean;
  cliPath?: string;
}

const vetryxPlugin = {
  id: "vetryx",
  name: "Vetryx Security Scanner",
  description: "Security scanner for OpenClaw extensions and skills",

  configSchema: {
    parse(value: unknown): VetryxConfig {
      const raw = (value && typeof value === "object" ? value : {}) as PluginConfig;
      return {
        enabled: raw.enabled !== false,
        scanOnInstall: raw.scanOnInstall !== false,
        minSeverity: raw.minSeverity || "medium",
        thirdPartyOnly: raw.thirdPartyOnly !== false,
        cliPath: raw.cliPath,
      };
    },
    uiHints: {
      enabled: { label: "Enable Vetryx", help: "Enable automatic security scanning" },
      scanOnInstall: { label: "Scan on Install", help: "Scan new extensions when installed" },
      minSeverity: { label: "Minimum Severity", help: "Minimum severity level to report" },
      thirdPartyOnly: { label: "Third-party Only", help: "Only scan non-official extensions" },
      cliPath: { label: "CLI Path", help: "Path to vetryx binary (auto-detected if empty)" },
    },
  },

  register(api: any) {
    const config = this.configSchema.parse(api.pluginConfig);
    let cliPath: string | null = null;

    const ensureCli = async (): Promise<string> => {
      if (cliPath) return cliPath;

      // Try configured path first
      if (config.cliPath) {
        cliPath = config.cliPath;
        return cliPath;
      }

      // Find in common locations
      const found = await findVetryx();
      if (found) {
        cliPath = found;
        return cliPath;
      }

      // Try auto-install
      api.logger.info("[vetryx] CLI not found, attempting auto-install...");
      const installed = await installVetryx();
      if (installed) {
        cliPath = installed;
        api.logger.info(`[vetryx] CLI installed to ${cliPath}`);
        return cliPath;
      }

      throw new Error(
        "Vetryx CLI not found. Install with: curl -fsSL https://raw.githubusercontent.com/edimuj/vetryx/main/install.sh | bash"
      );
    };

    // Register the security scanner tool
    api.registerTool({
      name: "vetryx",
      label: "Security Scanner",
      description:
        "Scan extensions and code for security threats including prompt injection, malicious code, obfuscation, and data exfiltration.",
      parameters: VetryxToolSchema,

      async execute(_toolCallId: string, params: any) {
        const json = (payload: unknown) => ({
          content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
          details: payload,
        });

        try {
          if (!config.enabled) {
            return json({ ok: false, error: "Vetryx is disabled in plugin config" });
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
                scanOnInstall: config.scanOnInstall,
              },
            });
          }

          if (params.action === "scan") {
            const scanPath = params.path || "~/.openclaw/extensions";
            const args = ["scan", scanPath, "-f", "json", "--min-severity", config.minSeverity];

            if (params.thirdPartyOnly ?? config.thirdPartyOnly) {
              args.push("--third-party-only");
            }

            const result = await execVetryx(cli, args);
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
            const args = ["vet", params.source, "-f", "json"];
            if (params.branch) {
              args.push("--branch", params.branch);
            }

            const result = await execVetryx(cli, args);
            const parsed = JSON.parse(result.stdout) as VetResult;

            // Determine verdict
            let verdict: string;
            if (parsed.total_findings === 0) {
              verdict = "clean";
            } else if (parsed.max_severity === "critical") {
              verdict = "dangerous";
            } else if (parsed.max_severity === "high") {
              verdict = "high_risk";
            } else {
              verdict = "warnings";
            }

            return json({
              ok: true,
              verdict,
              findings: parsed.total_findings || 0,
              maxSeverity: parsed.max_severity || null,
              message: getVerdictMessage(verdict, parsed.total_findings || 0, parsed.max_severity),
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
      ({ program }: any) => {
        const vetryx = program.command("vetryx").description("Security scanner for extensions");

        vetryx
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
              if (opts.thirdPartyOnly) args.push("--third-party-only");

              const result = await execVetryx(cli, args);
              console.log(result.stdout);
              if (result.stderr) console.error(result.stderr);
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });

        vetryx
          .command("vet <source>")
          .description("Vet an extension before installing")
          .option("-f, --format <format>", "Output format (cli, json)", "cli")
          .option("--branch <branch>", "Git branch to check")
          .option("--keep", "Keep cloned repo after scan")
          .action(async (source: string, opts: any) => {
            try {
              const cli = await ensureCli();
              const args = ["vet", source, "-f", opts.format];
              if (opts.branch) args.push("--branch", opts.branch);
              if (opts.keep) args.push("--keep");

              const result = await execVetryx(cli, args);
              console.log(result.stdout);
              if (result.stderr) console.error(result.stderr);
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });

        vetryx
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

              const result = await execVetryx(cli, args);
              console.log(result.stdout);
            } catch (err) {
              console.error("Error:", err instanceof Error ? err.message : err);
              process.exit(1);
            }
          });
      },
      { commands: ["vetryx"] }
    );

    // Register startup service for initial scan
    if (config.scanOnInstall) {
      api.registerService({
        id: "vetryx-startup",
        start: async () => {
          if (!config.enabled) return;

          try {
            const cli = await ensureCli();
            api.logger.info("[vetryx] Running startup security scan...");

            const args = ["scan", "~/.openclaw/extensions", "-f", "json", "--min-severity", "high"];
            if (config.thirdPartyOnly) args.push("--third-party-only");

            const result = await execVetryx(cli, args);
            const parsed = JSON.parse(result.stdout) as ScanResult;

            if (parsed.total_findings && parsed.total_findings > 0) {
              api.logger.warn(
                `[vetryx] Security scan found ${parsed.total_findings} issue(s) with max severity: ${parsed.max_severity}`
              );
            } else {
              api.logger.info("[vetryx] Security scan complete - no issues found");
            }
          } catch (err) {
            api.logger.error(
              `[vetryx] Startup scan failed: ${err instanceof Error ? err.message : err}`
            );
          }
        },
        stop: async () => {},
      });
    }
  },
};

function getVerdictMessage(verdict: string, findings: number, maxSeverity: string | null): string {
  switch (verdict) {
    case "clean":
      return "No security issues found";
    case "warnings":
      return `Found ${findings} issue(s) with max severity: ${maxSeverity}. Review recommended.`;
    case "high_risk":
      return `Found ${findings} HIGH severity issue(s). Review carefully before installing.`;
    case "dangerous":
      return `Found ${findings} CRITICAL issue(s). Do NOT install without thorough review.`;
    default:
      return `Found ${findings} issue(s)`;
  }
}

export default vetryxPlugin;
