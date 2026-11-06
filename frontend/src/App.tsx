import { useEffect, useState } from "react";
import { AssessmentPage } from "./AssessmentPage";
import { authEvents, session } from "./api";
import { useHashRoute } from "./hooks";
import { Login } from "./Login";
import { NewScan } from "./NewScan";
import { Overview } from "./Overview";
import { ProjectPage } from "./ProjectPage";
import { Shell } from "./Shell";

export function App() {
  const [authed, setAuthed] = useState(() => session.token() !== null);
  const route = useHashRoute();

  useEffect(() => {
    const expired = () => setAuthed(false);
    authEvents.addEventListener("expired", expired);
    return () => authEvents.removeEventListener("expired", expired);
  }, []);

  if (!authed) return <Login onDone={() => setAuthed(true)} />;

  const [path, query = ""] = route.split("?");
  let page = <Overview key="overview" openNew={new URLSearchParams(query).has("new")} />;
  let m: RegExpExecArray | null;
  if ((m = /^\/projects\/(\d+)\/new$/.exec(path))) page = <NewScan key={path} projectId={Number(m[1])} />;
  else if ((m = /^\/projects\/(\d+)$/.exec(path))) page = <ProjectPage key={path} id={Number(m[1])} />;
  else if ((m = /^\/assessments\/(\d+)$/.exec(path))) page = <AssessmentPage key={path} id={Number(m[1])} />;

  return (
    <Shell
      route={path}
      onSignOut={() => {
        session.clear();
        setAuthed(false);
      }}
    >
      {page}
    </Shell>
  );
}
