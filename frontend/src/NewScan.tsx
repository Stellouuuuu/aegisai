import { useState } from "react";
import { api } from "./api";
import { go, useLoad } from "./hooks";
import { DEPTHS, MODULES, OPENAI_PATHS, openaiTemplate } from "./lib";
import type { Profile } from "./types";
import { Chip, ErrorNote } from "./ui";

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
  const [format, setFormat] = useState<"custom" | "openai">("custom");
  const [model, setModel] = useState("");
  const [stream, setStream] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [profiling, setProfiling] = useState(false);

  function chooseFormat(f: "custom" | "openai") {
    setFormat(f);
    if (f === "openai") {
      setTemplate(openaiTemplate(model, stream));
      setResponsePath(OPENAI_PATHS.response);
      setToolPath(OPENAI_PATHS.tools);
      if (authType === "none") setAuthType("bearer");
    }
  }

  function changeOpenai(nextModel: string, nextStream: boolean) {
    setModel(nextModel);
    setStream(nextStream);
    setTemplate(openaiTemplate(nextModel, nextStream));
  }

  const toggle = (m: string) =>
    setModules((cur) => (cur.includes(m) ? cur.filter((x) => x !== m) : [...cur, m]));

  /** The target settings shared by "suggest tests" and "start scan". */
  function buildTarget(): Record<string, unknown> | string {
    let request_template: unknown;
    try {
      request_template = JSON.parse(template);
    } catch {
      return "The request template is not valid JSON.";
    }
    if (!template.includes("{{PROMPT}}")) {
      return "The request template must contain {{PROMPT}}, where the attack text is inserted.";
    }
    const auth =
      authType === "none"
        ? { type: "none" }
        : { type: authType, token: authRef, ...(authType === "api_key" ? { header_name: headerName } : {}) };
    return {
      url,
      request_template,
      response_path: responsePath,
      tool_calls_path: toolPath || null,
      auth,
      stream: format === "openai" && stream,
      timeout: 120,
    };
  }

  async function suggest() {
    setError(null);
    if (!url) return setError("Enter the endpoint URL first.");
    if (!confirmed) return setError("Tick the authorization box below first: profiling sends real requests.");
    const target = buildTarget();
    if (typeof target === "string") return setError(target);
    setProfiling(true);
    try {
      const p = await api.profile(projectId, target);
      setProfile(p);
      setModules(p.modules);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setProfiling(false);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const target = buildTarget();
    if (typeof target === "string") return setError(target);
    if (modules.length === 0) return setError("Select at least one test family.");
    setBusy(true);
    try {
      const a = await api.startScan(projectId, {
        target,
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
          <div className="depth" role="radiogroup" aria-label="API format">
            <label className={format === "custom" ? "depth-opt on" : "depth-opt"}>
              <input type="radio" name="format" checked={format === "custom"} onChange={() => chooseFormat("custom")} />
              <strong>Custom JSON API</strong>
              <span>You describe the request and reply shape.</span>
            </label>
            <label className={format === "openai" ? "depth-opt on" : "depth-opt"}>
              <input type="radio" name="format" checked={format === "openai"} onChange={() => chooseFormat("openai")} />
              <strong>OpenAI compatible</strong>
              <span>/v1/chat/completions: OpenAI, vLLM, LiteLLM, Ollama.</span>
            </label>
          </div>
          {format === "openai" && (
            <div className="grid-2">
              <label>
                Model name
                <input value={model} onChange={(e) => changeOpenai(e.target.value, stream)} placeholder="gpt-4o-mini" />
              </label>
              <label className="check">
                <input type="checkbox" checked={stream} onChange={(e) => changeOpenai(model, e.target.checked)} />
                <span>The endpoint streams its reply (server-sent events)</span>
              </label>
            </div>
          )}
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
          <div className="suggest">
            <button type="button" className="btn btn-ghost" disabled={profiling} onClick={suggest}>
              {profiling ? "Probing..." : "Detect application type"}
            </button>
            {profile && (
              <span className="muted">
                Looks like <Chip tone={profile.confidence === "low" ? "warn" : "ok"}>{profile.app_type}</Chip>{" "}
                ({profile.confidence} confidence). Test families were selected for you; you can change them.
              </span>
            )}
          </div>
          {profile && profile.signals.length > 0 && (
            <ul className="signals">
              {profile.signals.map((s) => (
                <li key={s.detail}>{s.detail}</li>
              ))}
            </ul>
          )}
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
