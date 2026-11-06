import type { ReactNode } from "react";
import { api, session } from "./api";
import { go } from "./hooks";
import { useLoad } from "./hooks";
import { Icon } from "./ui";

export function Shell({
  route,
  onSignOut,
  children,
}: {
  route: string;
  onSignOut: () => void;
  children: ReactNode;
}) {
  const projects = useLoad(() => api.projects(), [route.startsWith("/projects") ? route : "x"]);
  const activeProject = /^\/projects\/(\d+)/.exec(route)?.[1];

  async function signOut() {
    try {
      await api.logout();
    } catch {
      /* the session is dropped locally either way */
    }
    onSignOut();
  }

  return (
    <div className="shell">
      <aside className="rail">
        <a className="brand" href="#/">
          <span className="brand-mark">
            <Icon name="shield" size={18} />
          </span>
          <span>
            Aegis<b>AI</b>
          </span>
        </a>

        <nav>
          <a className={route === "/" ? "nav on" : "nav"} href="#/">
            <Icon name="grid" /> Overview
          </a>
        </nav>

        <div className="rail-head">
          <span>Targets</span>
          <button className="icon-btn" title="New target" onClick={() => go("/?new=1")}>
            <Icon name="plus" size={14} />
          </button>
        </div>
        <nav className="targets">
          {(projects.data ?? []).map((p) => (
            <a
              key={p.id}
              href={`#/projects/${p.id}`}
              className={String(p.id) === activeProject ? "nav on" : "nav"}
            >
              <Icon name="target" /> <span className="ellipsis">{p.name}</span>
            </a>
          ))}
          {projects.data?.length === 0 && <p className="rail-empty">No target yet</p>}
        </nav>

        <div className="rail-foot">
          <span className="ellipsis" title={session.email()}>
            {session.email()}
          </span>
          <button className="icon-btn" title="Sign out" onClick={signOut}>
            <Icon name="out" />
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
