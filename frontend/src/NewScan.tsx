import { useState } from "react";
import { api } from "./api";
import { go, useLoad } from "./hooks";
import { DEPTHS, MODULES } from "./lib";
import { ErrorNote } from "./ui";

export function NewScan({ projectId }: { projectId: number }) {
  const project = useLoad(() => api.project(projectId), [projectId]);
  const [url, setUrl] = useState("");
  const [template, setTemplate] = useState('{"message": "{{PROMPT}}"}');
  const [responsePath, setResponsePath] = useState("$.reply");
  const [toolPath, setToolPath] = useState("");
  const [authType, setAuthType] = useState("none");
  const [authRef, setAuthRef] = useState("");
  const [headerName, setHeaderName] = useState("X-API-Key");
  const [modules, setModules] = useState<string[]>(Object.keys(MODULES));
  const [depth, setDepth] = useState("standard");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const toggle = (m: string) =>
    setModules((cur) => (cur.includes(m) ? cur.filter((x) => x !== m) : [...cur, m]));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    let request_template: unknown;
    try {
      request_template = JSON.parse(template);
    } catch {
      setError("The request template is not valid JSON.");
      return;
    }
    if (!template.includes("{{PROMPT}}")) {
      setError("The request template must contain {{PROMPT}}, where the attack text is inserted.");
      return;
    }
    if (modules.length === 0) {
      setError("Select at least one test family.");
      return;
    }
    const auth =
      authType === "none"
        ? { type: "none" }
        : { type: authType, token: authRef, ...(authType === "api_key" ? { header_name: headerName } : {}) };
    setBusy(true);
    try {
      const a = await api.startScan(projectId, {
        target: {
          url,
          request_template,
          response_path: responsePath,
          tool_calls_path: toolPath || null,
          auth,
        },
        modules,
        depth,
        confirm_authorized: confirmed,
      });
      go(`/assessments/${a.id}`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <p className="eyebrow">{project.data?.name ?? "Target"}</p>
          <h1>Configure a scan</h1>
        </div>
      </header>

      <form className="stack" onSubmit={submit}>
        <section className="card form-card">
          <h2>1. Where the application listens</h2>
          <label>
            Chat endpoint URL
            <input
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://my-app.example.com/api/chat"
            />
          </label>
          <div className="grid-2">
            <label>
              Request body
              <textarea rows={3} value={template} onChange={(e) => setTemplate(e.target.value)} spellCheck={false} />
              <small>{"{{PROMPT}}"} marks where each attack is inserted.</small>
            </label>
            <div className="stack-sm">
              <label>
                Reply location (JSONPath)
                <input value={responsePath} onChange={(e) => setResponsePath(e.target.value)} />
              </label>
              <label>
                Tool calls location <small>(agents, optional)</small>
                <input value={toolPath} onChange={(e) => setToolPath(e.target.value)} placeholder="$.tool_calls" />
              </label>
            </div>
          </div>
          <div className="grid-2">
            <label>
              Authentication
              <select value={authType} onChange={(e) => setAuthType(e.target.value)}>
                <option value="none">None</option>
                <option value="bearer">Bearer token</option>
                <option value="api_key">API key header</option>
              </select>
            </label>
            {authType !== "none" && (
              <label>
                Secret, as an environment reference
                <input value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="${MY_APP_TOKEN}" required />
                <small>Literal secrets are refused and never stored. Export the variable where the API runs.</small>
              </label>
            )}
            {authType === "api_key" && (
              <label>
                Header name
                <input value={headerName} onChange={(e) => setHeaderName(e.target.value)} />
              </label>
            )}
          </div>
        </section>

        <section className="card form-card">
          <h2>2. What to test</h2>
          <div className="choice-grid">
            {Object.entries(MODULES).map(([id, m]) => (
              <label key={id} className={modules.includes(id) ? "choice on" : "choice"}>
                <input type="checkbox" checked={modules.includes(id)} onChange={() => toggle(id)} />
                <strong>{m.label}</strong>
                <span>{m.blurb}</span>
                <code>{m.owasp}</code>
              </label>
            ))}
          </div>
          <div className="depth" role="radiogroup" aria-label="Depth">
            {DEPTHS.map((d) => (
              <label key={d.id} className={depth === d.id ? "depth-opt on" : "depth-opt"}>
                <input type="radio" name="depth" checked={depth === d.id} onChange={() => setDepth(d.id)} />
                <strong>{d.label}</strong>
                <span>{d.note}</span>
              </label>
            ))}
          </div>
        </section>

        <section className="card form-card">
          <h2>3. Authorization</h2>
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            <span>
              I own this application or have written authorization to test it. I understand AegisAI sends
              real attack payloads to the endpoint above.
            </span>
          </label>
          {error && <ErrorNote message={error} />}
          <div className="actions">
            <button type="button" className="btn btn-ghost" onClick={() => go(`/projects/${projectId}`)}>
              Cancel
            </button>
            <button className="btn btn-primary" disabled={busy || !confirmed}>
              {busy ? "Starting..." : "Start scan"}
            </button>
          </div>
        </section>
      </form>
    </>
  );
}
