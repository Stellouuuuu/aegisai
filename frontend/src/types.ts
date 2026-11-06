export type Severity = "critical" | "high" | "medium" | "low";
export type AssessmentStatus = "pending" | "running" | "completed" | "failed";

export interface Project {
  id: number;
  name: string;
  description: string;
  app_type: string;
  created_at: string;
}

export interface TargetConfig {
  url: string;
  tool_calls_path: string | null;
  response_path: string;
}

export interface Assessment {
  id: number;
  project_id: number;
  config: TargetConfig;
  modules: string[];
  depth: "quick" | "standard" | "deep";
  status: AssessmentStatus;
  progress: number;
  security_score: number | null;
  requests_sent: number;
  duration_seconds: number | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface FindingData {
  id: string;
  category: string;
  owasp: string;
  atlas: string | null;
  severity: Severity;
  confidence: "confirmed" | "needs_review" | "rejected";
  scenario: string;
  request: string;
  response: string;
  evidence: string;
  safety_rule_violated: string;
  recommendation: string;
  reproducible: boolean;
  exploitability: number | null;
  risk_score: number | null;
}

export interface FindingRow {
  id: number;
  assessment_id: number;
  scenario_id: string;
  data: FindingData;
  status: "open" | "resolved";
  retested_at: string | null;
}

export interface NewScanBody {
  target: Record<string, unknown>;
  modules: string[];
  depth: string;
  confirm_authorized: boolean;
}
