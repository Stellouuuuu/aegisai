import { useState } from "react";
import { api, download } from "./api";
import { FindingDrawer } from "./FindingDrawer";
import { go, useLoad, usePoll } from "./hooks";
import {
  countBySeverity,
  formatDate,
  formatDuration,
  hostOf,
  laneState,
  MODULES,
  sortFindings,
  statusTone,
} from "./lib";
import type { FindingRow } from "./types";
import { Chip, Empty, ErrorNote, Gauge, Icon, SevDot, SeverityBars } from "./ui";

export function AssessmentPage({ id }: { id: number }) {
  const a = useLoad(() => api.assessment(id), [id]);
  const status = a.data?.status;
  const live = status === "pending" || status === "running" || status === undefined;
  usePoll(a.reload, 1000, live && !a.error);

  const findings = useLoad(
    () => (status === "completed" ? api.findings(id) : Promise.resolve([] as FindingRow[])),
    [id, status],
  );
  const [openId, setOpenId] = useState<number | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const assessment = a.data;
  const rows = sortFindings(findings.data ?? []);
  const counts = countBySeverity(rows);
  const open = rows.filter((r) => r.status === "open");
  const selected = rows.find((r) => r.id === openId) ?? null;

  async function refresh() {
    a.reload();
    findings.reload();
  }

  async function exportReport(kind: "pdf" | "json") {
    setBusy(kind);
    setActionError(null);
    try {
      if (kind === "pdf") download(await api.reportPdf(id), `aegis-scan-${id}.pdf`);
      else
        download(
          new Blob([JSON.stringify(await api.reportJson(id), null, 2)], { type: "application/json" }),
          `aegis-scan-${id}.json`,
        );
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function retestAll() {
    setBusy("retest");
    setActionError(null);
    try {
      for (const r of open) await api.retest(r.id);
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(null);
      refresh();
    }
  }

  if (a.error && !assessment) return <ErrorNote message={a.error} onRetry={a.reload} />;
  if (!assessment) return <p className="muted">Loading...</p>;

  return (
    <>
      <header className="page-head">
        <div>
          <p className="eyebrow">
            <a href={`#/projects/${assessment.project_id}`}>Back to target</a> - scan #{assessment.id}
          </p>
          <h1>{hostOf(assessment.config.url)}</h1>
          <p className="muted">
            {formatDate(assessment.created_at)} - {assessment.depth} depth -{" "}
            <Chip tone={statusTone(assessment.status)}>{assessment.status}</Chip>
          </p>
        </div>
        {assessment.status === "completed" && (
          <div className="actions">
            <button className="btn btn-ghost" disabled={!!busy} onClick={() => exportReport("json")}>
              JSON
            </button>
            <button className="btn btn-ghost" disabled={!!busy} onClick={() => exportReport("pdf")}>
              <Icon name="file" /> {busy === "pdf" ? "Building..." : "PDF report"}
            </button>
            <button className="btn btn-primary" disabled={!!busy || open.length === 0} onClick={retestAll}>
              <Icon name="refresh" /> {busy === "retest" ? "Retesting..." : "Retest open findings"}
            </button>
          </div>
        )}
      </header>

      {actionError && <ErrorNote message={actionError} />}

      {assessment.status === "failed" && (
        <>
          <ErrorNote message={assessment.error ?? "The scan failed."} />
          <p className="muted">
            Fix the target settings and{" "}
            <a href={`#/projects/${assessment.project_id}/new`}>start a new scan</a>.
          </p>
        </>
      )}

      {(assessment.status === "pending" || assessment.status === "running") && (
        <section className="card lanes">
          <div className="lanes-head">
            <h2>Attack lanes</h2>
            <span className="muted">{assessment.progress}% complete</span>
          </div>
          <div className="bar">
            <span style={{ width: `${assessment.progress}%` }} />
          </div>
          <ul>
            {assessment.modules.map((m, i) => {
              const st = laneState(i, assessment.modules.length, assessment.progress, assessment.status);
              const meta = MODULES[m];
              return (
                <li key={m} className={`lane lane-${st}`}>
                  <span className="lane-state" />
                  <span>
                    <strong>{meta?.label ?? m}</strong>
                    <span className="sub">{meta?.blurb}</span>
                  </span>
                  <span className="lane-tag">{st === "done" ? "done" : st === "active" ? "probing" : "queued"}</span>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {assessment.status === "completed" && (
        <>
          <section className="card verdict">
            <Gauge score={assessment.security_score} />
            <div className="verdict-side">
              <dl className="ledger">
                <div>
                  <dt>Open findings</dt>
                  <dd>{open.length}</dd>
                </div>
                <div>
                  <dt>Resolved</dt>
                  <dd>{rows.length - open.length}</dd>
                </div>
                <div>
                  <dt>Requests sent</dt>
                  <dd>{assessment.requests_sent}</dd>
                </div>
                <div>
                  <dt>Duration</dt>
                  <dd>{formatDuration(assessment.duration_seconds)}</dd>
                </div>
              </dl>
              <SeverityBars counts={counts} />
            </div>
          </section>

          <h2 className="section-title">Findings</h2>
          {rows.length === 0 && !findings.loading && (
            <Empty title="Nothing proven">
              None of the executed scenarios produced evidence. This is not a guarantee of safety: only
              the selected scenarios were tried.
            </Empty>
          )}
          {findings.error && <ErrorNote message={findings.error} onRetry={findings.reload} />}
          <ul className="findings">
            {rows.map((r) => (
              <li key={r.id}>
                <button className={r.status === "resolved" ? "finding done" : "finding"} onClick={() => setOpenId(r.id)}>
                  <SevDot sev={r.data.severity} />
                  <code className="fid">{r.data.id}</code>
                  <span className="ftitle">
                    <strong>{r.data.scenario}</strong>
                    <span className="sub">
                      {r.data.owasp}
                      {r.data.atlas ? ` - ${r.data.atlas}` : ""}
                    </span>
                  </span>
                  <Chip tone={r.data.confidence === "confirmed" ? "ok" : "warn"}>
                    {r.data.confidence === "confirmed" ? "confirmed" : "needs review"}
                  </Chip>
                  <span className="frisk">{r.status === "resolved" ? "resolved" : `risk ${r.data.risk_score}`}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}

      {selected && (
        <FindingDrawer
          row={selected}
          onClose={() => setOpenId(null)}
          onChanged={refresh}
          onError={setActionError}
        />
      )}
    </>
  );
}

export { go };
