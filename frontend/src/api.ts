import { parseApiError } from "./lib";
import { demoApi } from "./demo/api";
import type { Assessment, FindingRow, NewScanBody, Profile, Project } from "./types";

/** Set at build time (npm run build:demo): the dashboard then runs on bundled sample reports, with no backend. */
export const DEMO = import.meta.env.VITE_DEMO === "1";

const BASE = "/api";
const KEY = "aegis.token";
const EMAIL_KEY = "aegis.email";

export const session = {
  token: (): string | null => {
    if (DEMO) return "demo";
    try {
      return localStorage.getItem(KEY);
    } catch {
      return null;
    }
  },
  email: (): string => {
    if (DEMO) return "demo@aegisai.dev";
    try {
      return localStorage.getItem(EMAIL_KEY) ?? "";
    } catch {
      return "";
    }
  },
  set: (token: string, email: string) => {
    try {
      localStorage.setItem(KEY, token);
      localStorage.setItem(EMAIL_KEY, email);
    } catch {
      /* storage unavailable: the session lasts until reload */
    }
  },
  clear: () => {
    try {
      localStorage.removeItem(KEY);
      localStorage.removeItem(EMAIL_KEY);
    } catch {
      /* ignore */
    }
  },
};

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

export const authEvents = new EventTarget();

async function raw(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = session.token();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  let res: Response;
  try {
    res = await fetch(BASE + path, { ...init, headers });
  } catch {
    throw new ApiError("Cannot reach the AegisAI API. Is the backend running?", 0);
  }
  if (res.status === 401 && token) {
    session.clear();
    authEvents.dispatchEvent(new Event("expired"));
  }
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non JSON error */
    }
    throw new ApiError(parseApiError(body, `Request failed (${res.status})`), res.status);
  }
  return res;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await raw(path, init)).json() as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  json<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

const liveApi = {
  register: (email: string, password: string) => post("/auth/register", { email, password }),
  login: (email: string, password: string) =>
    post<{ access_token: string }>("/auth/login", { email, password }),
  logout: () => raw("/auth/logout", { method: "POST" }),
  projects: () => json<Project[]>("/projects"),
  project: (id: number) => json<Project>(`/projects/${id}`),
  createProject: (name: string, description: string, app_type: string) =>
    post<Project>("/projects", { name, description, app_type }),
  history: (projectId: number) => json<Assessment[]>(`/projects/${projectId}/assessments`),
  startScan: (projectId: number, body: NewScanBody) =>
    post<Assessment>(`/projects/${projectId}/assessments`, body),
  assessment: (id: number) => json<Assessment>(`/assessments/${id}`),
  profile: (projectId: number, target: Record<string, unknown>) =>
    post<Profile>(`/projects/${projectId}/profile`, { target, confirm_authorized: true }),
  cancel: (id: number) => post<Assessment>(`/assessments/${id}/cancel`),
  findings: (id: number) => json<FindingRow[]>(`/assessments/${id}/findings`),
  retest: (findingId: number) =>
    post<{ finding_id: number; status: string }>(`/findings/${findingId}/retest`),
  reportJson: (id: number) => json<unknown>(`/assessments/${id}/report`),
  reportPdf: async (id: number): Promise<Blob> => (await raw(`/assessments/${id}/report.pdf`)).blob(),
};

export const api: typeof liveApi = DEMO ? (demoApi as unknown as typeof liveApi) : liveApi;

export function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
