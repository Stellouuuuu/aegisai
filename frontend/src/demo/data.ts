import type { Assessment, FindingData, FindingRow, Project } from "../types";
import patchedReport from "./patched.json";
import vulnerableReport from "./vulnerable.json";

/** The two reports in docs/examples, shaped like the API answers, so the dashboard runs without a backend. */
interface Report {
  generated_at: string;
  modules: string[];
  depth: string;
  duration_seconds: number;
  requests_sent: number;
  security_score: number;
  findings: Array<FindingData & { extra?: unknown }>;
}

const samples: Array<{ project: Project; target: string; report: Report }> = [
  {
    project: {
      id: 1,
      name: "Acme Support Bot (vulnerable)",
      description: "The deliberately vulnerable chatbot bundled with AegisAI, a rule-based simulator.",
      app_type: "chatbot",
      created_at: vulnerableReport.generated_at,
    },
    target: "demo:vulnerable-chatbot",
    report: vulnerableReport as unknown as Report,
  },
  {
    project: {
      id: 2,
      name: "Acme Support Bot (hardened)",
      description: "The same chatbot with its flaws fixed.",
      app_type: "chatbot",
      created_at: patchedReport.generated_at,
    },
    target: "demo:patched-chatbot",
    report: patchedReport as unknown as Report,
  },
];

export const projects: Project[] = samples.map((s) => s.project);

export const assessments: Assessment[] = samples.map(({ project, target, report }) => ({
  id: project.id,
  project_id: project.id,
  config: { url: target, tool_calls_path: null, response_path: "$.reply" },
  modules: report.modules,
  depth: report.depth as Assessment["depth"],
  status: "completed",
  progress: 100,
  security_score: report.security_score,
  requests_sent: report.requests_sent,
  duration_seconds: report.duration_seconds,
  error: null,
  created_at: report.generated_at,
  finished_at: report.generated_at,
}));

export const findings: FindingRow[] = samples.flatMap(({ project, report }, sampleIndex) =>
  report.findings.map((finding, index) => {
    const { extra: _extra, ...data } = finding;
    return {
      id: sampleIndex * 1000 + index + 1,
      assessment_id: project.id,
      scenario_id: data.id,
      data,
      status: "open" as const,
      retested_at: null,
    };
  }),
);

export const reports: Record<number, unknown> = {
  1: vulnerableReport,
  2: patchedReport,
};
