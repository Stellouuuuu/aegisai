import { useState } from "react";
import { api, session } from "./api";
import { ErrorNote, Icon } from "./ui";

export function Login({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "register") await api.register(email, password);
      const t = await api.login(email, password);
      session.set(t.access_token, email.trim().toLowerCase());
      onDone();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <section className="login-art" aria-hidden="true">
        <div className="login-mark">
          <Icon name="shield" size={34} />
        </div>
        <h1>
          Prove it, <em>don't guess.</em>
        </h1>
        <p>
          AegisAI attacks your AI application the way a real adversary would, and only reports what it
          can demonstrate: replayable, with the evidence attached.
        </p>
        <ul>
          <li>Black-box, works on any chat API</li>
          <li>OWASP LLM Top 10 and MITRE ATLAS mapped</li>
          <li>Canary-based proof, few false alarms</li>
        </ul>
      </section>

      <form className="login-card" onSubmit={submit}>
        <h2>{mode === "login" ? "Sign in" : "Create your account"}</h2>
        <label>
          Email
          <input
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
            minLength={10}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {mode === "register" && <small>At least 10 characters.</small>}
        </label>
        {error && <ErrorNote message={error} />}
        <button className="btn btn-primary" disabled={busy}>
          {busy ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}
        </button>
        <button
          type="button"
          className="link"
          onClick={() => {
            setMode(mode === "login" ? "register" : "login");
            setError(null);
          }}
        >
          {mode === "login" ? "No account yet? Create one" : "Already registered? Sign in"}
        </button>
        <p className="legal">
          AegisAI is an offensive security tool. Only test applications you own or are explicitly
          authorized to test.
        </p>
      </form>
    </div>
  );
}
