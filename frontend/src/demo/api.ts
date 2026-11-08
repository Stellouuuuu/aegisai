import { ApiError } from "../api";
import { assessments, findings, projects, reports } from "./data";

export const READ_ONLY =
  "This is a read-only demo built from sample reports. To scan your own application, run AegisAI locally (see the README).";

const refuse = async (): Promise<never> => {
  throw new ApiError(READ_ONLY, 403);
};

function find<T extends { id: number }>(rows: T[], id: number, what: string): Promise<T> {
  const row = rows.find((r) => r.id === id);
  return row ? Promise.resolve(row) : Promise.reject(new ApiError(`${what} not found`, 404));
}

/** The same shape as the real client in api.ts: reads come from the bundled reports, writes are refused. */
export const demoApi = {
  register: refuse,
  login: async () => ({ access_token: "demo" }),
  logout: async () => new Response(null),
  projects: async () => projects,
  project: (id: number) => find(projects, id, "Target"),
  createProject: refuse,
  history: async (projectId: number) => assessments.filter((a) => a.project_id === projectId),
  startScan: refuse,
  assessment: (id: number) => find(assessments, id, "Scan"),
  profile: refuse,
  cancel: refuse,
  findings: async (id: number) => findings.filter((f) => f.assessment_id === id),
  retest: refuse,
  reportJson: async (id: number) => reports[id] ?? Promise.reject(new ApiError("Report not found", 404)),
  reportPdf: async (id: number): Promise<Blob> => {
    if (id !== 1) throw new ApiError("There is no PDF for this sample. Use the JSON export.", 404);
    const res = await fetch(`${import.meta.env.BASE_URL}demo/demo-vulnerable.pdf`);
    if (!res.ok) throw new ApiError("The sample PDF could not be loaded.", res.status);
    return res.blob();
  },
};
