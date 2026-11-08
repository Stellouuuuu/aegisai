import { useEffect, useState } from "react";
import { api, DEMO } from "./api";
import { READ_ONLY } from "./demo/api";
import { extractProofTokens, highlight } from "./lib";
import type { FindingRow } from "./types";
import { Chip, Icon, SevDot } from "./ui";

function Transcript({ label, text, needles }: { label: string; text: string; needles: string[] }) {
  return (
    <div className="bubble">
      <span className="bubble-label">{label}</span>
      <pre>
        {highlight(text, needles).map((s, i) =>
          s.hit ? (
            <mark key={i}>{s.text}</mark>
          ) : (
            <span key={i}>{s.text}</span>
          ),
        )}
      </pre>
    </div>
  );
}

export function FindingDrawer({
  row,
  onClose,
  onChanged,
  onError,
}: {
  row: FindingRow;
  onClose: () => void;
  onChanged: () => void;
  onError: (m: string | null) => void;
}) {
  const f = row.data;
  const [busy, setBusy] = useState(false);
  const [verdict, setVerdict] = useState<string | null>(null);
  const needles = extractProofTokens(f.evidence);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function retest() {
    if (DEMO) {
      setVerdict(READ_ONLY);
      return;
    }
    setBusy(true);
    onError(null);
    setVerdict(null);
    try {
      const r = await api.retest(row.id);
      setVerdict(
        r.status === "resolved"
          ? "The attack no longer succeeds. This finding is now resolved."
          : "The attack still succeeds. The finding stays open.",
      );
      onChanged();
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="scrim" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-label={f.scenario} onClick={(e) => e.stopPropagation()}>
        <header>
          <div>
            <p className="eyebrow">
              <SevDot sev={f.severity} /> {f.severity} - {f.id}
            </p>
            <h2>{f.scenario}</h2>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="close" />
          </button>
        </header>

        <div className="chips">
          <Chip tone={f.confidence === "confirmed" ? "ok" : "warn"}>{f.confidence.replace("_", " ")}</Chip>
          <Chip tone={f.reproducible ? "ok" : "warn"}>{f.reproducible ? "replayed identically" : "not stable"}</Chip>
          <Chip tone="idle">{f.owasp}</Chip>
          {f.atlas && <Chip tone="idle">{f.atlas}</Chip>}
          <Chip tone={row.status === "resolved" ? "ok" : "bad"}>{row.status}</Chip>
        </div>

        <h3>Proof</h3>
        <p>{f.evidence}</p>
        <div className="transcript">
          <Transcript label="Attack sent" text={f.request} needles={[]} />
          <Transcript label="Application replied" text={f.response} needles={needles} />
        </div>

        <h3>Rule violated</h3>
        <p>{f.safety_rule_violated}</p>

        <h3>How to fix it</h3>
        <p>{f.recommendation}</p>

        <dl className="ledger ledger-sm">
          <div>
            <dt>Risk</dt>
            <dd>{f.risk_score ?? "-"} / 10</dd>
          </div>
          <div>
            <dt>Exploitability</dt>
            <dd>{f.exploitability === null ? "-" : `${Math.round(f.exploitability * 100)}%`}</dd>
          </div>
        </dl>

        {verdict && <p className="note note-ok">{verdict}</p>}
        <button className="btn btn-primary" disabled={busy} onClick={retest}>
          <Icon name="refresh" /> {busy ? "Retesting..." : "Retest this finding"}
        </button>
      </aside>
    </div>
  );
}
