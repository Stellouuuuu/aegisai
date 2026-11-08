import { useState } from "react";
import { api } from "./api";
import { go, useLoad } from "./hooks";
import { countBySeverity, formatDate, grade, hostOf, SEVERITIES } from "./lib";
import type { Assessment, FindingRow, Project, Severity } from "./types";
import { Chip, Empty, ErrorNote, Gauge, Icon, SeverityBars, Sparkline } from "./ui";

interface Summary {
  project: Project;
  assessments: Assessment[];
  findings: FindingRow[];
}

async function loadSummaries(): Promise<Summary[]> {
  const projects = await api.projects();
  return Promise.all(
    projects.map(async (project) => {
      const assessments = await api.history(project.id);
      const latest = assessments.find((a) => a.status === "completed");
      const findings = latest ? await api.findings(latest.id) : [];
      return { project, assessments, findings };
    }),
  );
}

export function latestScore(s: Summary): number | null {
  return s.assessments.find((a) => a.status === "completed")?.security_score ?? null;
}

export function Overview({ openNew }: { openNew: boolean }) {
  const { data, error, loading, reload } = useLoad(loadSummaries, []);
  const [creating, setCreating] = useState(openNew);

  const scored = (data ?? []).map(latestScore).filter((s): s is number => s !== null);
  const posture = scored.length ? Math.round(scored.reduce((a, b) => a + b, 0) / scored.length) : null;
  const allFindings = (data ?? []).flatMap((s) => s.findings);
  const counts = countBySeverity(allFindings);
  const open = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  const scans = (data ?? []).reduce((n, s) => n + s.assessments.length, 0);
  const recent = (data ?? [])
    .flatMap((s) => s.assessments.map((a) => ({ a, p: s.project })))
    .sort((x, y) => y.a.id - x.a.id)
    .slice(0, 6);

  return (
    <>
      <header className="page-head">
        <div>
          <p className="eyebrow">Security posture</p>
          <h1>Overview</h1>
        </div>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>
          <Icon name="plus" /> New target
        </button>
      </header>

      {creating && <NewProject onClose={() => setCreating(false)} onCreated={(p) => go(`/projects/${p.id}/new`)} />}
      {error && <ErrorNote message={error} onRetry={reload} />}
      {loading && !data && <p className="muted">Loading...</p>}

      {data && data.length === 0 && !creating && (
        <Empty title="No target yet">
          Add the AI application you want to test. A target is one chatbot, agent or API, and every scan
          you run against it is kept in its history.
        </Empty>
      )}

      {data && data.length > 0 && (
        <>
          <section className="posture card">
            <Gauge score={posture} />
            <div className="posture-side">
              <dl className="ledger">
                <div>
                  <dt>Targets</dt>
                  <dd>{data.length}</dd>
                </div>
                <div>
                  <dt>Open findings</dt>
                  <dd>{open}</dd>
                </div>
                <div>
                  <dt>Scans run</dt>
                  <dd>{scans}</dd>
                </div>
              </dl>
              <h3 className="mini-title">Open findings by severity</h3>
              <SeverityBars counts={counts} />
            </div>
          </section>

          <section>
            <h2 className="section-title">Targets</h2>
            <div className="card table-card">
              <table className="table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Latest score</th>
                    <th>Trend</th>
                    <th>Open</th>
                    <th>Last scan</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((s) => {
                    const score = latestScore(s);
                    const g = grade(score);
                    const open = s.findings.filter((f) => f.status === "open").length;
                    const trend = [...s.assessments]
                      .reverse()
                      .filter((a) => a.security_score !== null)
                      .map((a) => a.security_score as number);
                    return (
                      <tr key={s.project.id} className="row-link" onClick={() => go(`/projects/${s.project.id}`)}>
                        <td>
                          <strong>{s.project.name}</strong>
                          <span className="sub">
                            {s.assessments[0] ? hostOf(s.assessments[0].config.url) : s.project.app_type}
                          </span>
                        </td>
                        <td>{score === null ? <span className="muted">not scanned</span> : <Chip tone={g.tone}>{score} - {g.label}</Chip>}</td>
                        <td>
                          <Sparkline values={trend} />
                        </td>
                        <td>{open}</td>
                        <td className="muted">{formatDate(s.assessments[0]?.created_at ?? null)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {recent.length > 0 && (
            <section>
              <h2 className="section-title">Recent scans</h2>
              <ol className="timeline">
                {recent.map(({ a, p }) => (
                  <li key={a.id}>
                    <a href={`#/assessments/${a.id}`}>
                      <span className={`pip pip-${a.status}`} />
                      <span>
                        <strong>{p.name}</strong> <span className="muted">scan #{a.id} - {a.status}</span>
                      </span>
                      <span className="muted">{formatDate(a.created_at)}</span>
                    </a>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </>
      )}
    </>
  );
}

function NewProject({ onClose, onCreated }: { onClose: () => void; onCreated: (p: Project) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [type, setType] = useState("chatbot");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      onCreated(await api.createProject(name, description, type));
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <form className="card form-card" onSubmit={submit}>
      <h2>New target</h2>
      <div className="grid-2">
        <label>
          Name
          <input required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} placeholder="Shop assistant" />
        </label>
        <label>
          Kind of application
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="chatbot">Chatbot</option>
            <option value="rag">RAG</option>
            <option value="agent">Agent</option>
            <option value="api">LLM API</option>
            <option value="other">Other</option>
          </select>
        </label>
      </div>
      <label>
        Description <small>(optional)</small>
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      {error && <ErrorNote message={error} />}
      <div className="actions">
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button className="btn btn-primary" disabled={busy}>
          Create and configure scan
        </button>
      </div>
    </form>
  );
}

export type { Severity };
