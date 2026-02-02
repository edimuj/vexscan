export interface VexscanConfig {
  enabled: boolean;
  scanOnInstall: boolean;
  minSeverity: string;
  thirdPartyOnly: boolean;
  cliPath?: string;
}

export interface ScanResult {
  scan_root: string;
  platform?: string;
  total_findings?: number;
  max_severity?: string;
  findings_by_severity?: Record<string, number>;
  total_time_ms: number;
  results: FileResult[];
}

export interface FileResult {
  path: string;
  findings: Finding[];
}

export interface Finding {
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  location: Location;
  snippet: string;
  remediation?: string;
}

export interface Location {
  file: string;
  start_line: number;
  end_line: number;
  start_column: number;
  end_column: number;
}

export interface VetResult extends ScanResult {
  source: string;
  branch?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
