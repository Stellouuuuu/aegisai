import { api } from "./api";
import { go, useLoad } from "./hooks";
import { formatDate, formatDuration, grade, hostOf, statusTone } from "./lib";
import { Chip, Empty, ErrorNote, Icon, Sparkline } from "./ui";

export function ProjectPage({ id }: { id: number }) {
  const project = useLoad(() => api.project(id), [id]);
  const history = useLoad(() => api.history(id), [id]);
  const err = project.error ?? history.error;
  const list = history.data ?? [];
  const trend = [...list]
    .reverse()
    .filter((a) => a.security_score !== null)
    .map((a) => a.security_score as number);

  return (
    <>
      <header className="page-head">
        <div>
          <p className="eyebrow">Target - {project.data?.app_type ?? ""}</p>
          <h1>{project.data?.name ?? "..."}</h1>
          {project.data?.description && <p className="muted">{project.data.description}</p>}
        </div>
        <button className="btn btn-primary" onClick={() => go(`/projects/${id}/new`)}>
          <Icon name="target" /> Run a scan
        </button>
      </header>

      {err && <ErrorNote message={err} onRetry={() => (project.reload(), history.reload())} />}

      {list.length === 0 && !history.loading && (
        <Empty title="No scan yet">Run your first scan to get a score and a list of proven findings.</Empty>
      )}

      {list.length > 0 && (
        <>
          <section className="card trend">
            <div>
              <p className="eyebrow">Score over time</p>
              <Sparkline values={trend} width={320} height={64} />
            </div>
            <div className="trend-n">
              <strong>{list.length}</strong>
              <span>scans</span>
            </div>
          </section>

          <h2 className="section-title">History</h2>
          <div className="card table-card">
            <table className="table">
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Status</th>
                  <th>Score</th>
                  <th>Depth</th>
                  <th>Duration</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {list.map((a) => {
                  const g = grade(a.security_score);
                  return (
                    <tr key={a.id} className="row-link" onClick={() => go(`/assessments/${a.id}`)}>
                      <td>
                        <strong>#{a.id}</strong>
                        <span className="sub">{hostOf(a.config.url)}</span>
                      </td>
                      <td>
                        <Chip tone={statusTone(a.status)}>{a.status}</Chip>
                      </td>
                      <td>{a.security_score === null ? "-" : <Chip tone={g.tone}>{a.security_score}</Chip>}</td>
                      <td className="muted">{a.depth}</td>
                      <td className="muted">{formatDuration(a.duration_seconds)}</td>
                      <td className="muted">{formatDate(a.created_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
