import { useState, useRef } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar } from "recharts";

const api = (p, o) => fetch(`/api${p}`, o).then(async (r) => {
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "Request failed.");
  return d;
});

export default function App() {
  const [jobId, setJobId] = useState(null);
  const [state, setState] = useState("idle"); // idle | working | done | error
  const [progress, setProgress] = useState(0);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const timer = useRef(null);

  const poll = (id) => {
    timer.current = setInterval(async () => {
      try {
        const s = await api(`/jobs/${id}`);
        setProgress(s.progress);
        if (s.status === "done") {
          clearInterval(timer.current);
          setReport(await api(`/jobs/${id}/report`));
          setState("done");
        } else if (s.status === "failed") throw new Error(s.error);
      } catch (e) { clearInterval(timer.current); setError(e.message); setState("error"); }
    }, 1000);
  };

  const start = async (call) => {
    clearInterval(timer.current);
    setState("working"); setReport(null); setError(""); setProgress(0);
    try { const { job_id } = await call(); setJobId(job_id); poll(job_id); }
    catch (e) { setError(e.message); setState("error"); }
  };

  const upload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData(); fd.append("file", file);
    start(() => api("/upload", { method: "POST", body: fd }));
  };

  return (
    <main>
      <h1>LogLens</h1>
      <p className="sub">Upload a web server log to see who attacked, how, and when.</p>
      <div className="bar">
        <label className="file"><input type="file" accept=".log,.txt" onChange={upload} />Upload log file</label>
        <button className="primary" onClick={() => start(() => api("/demo", { method: "POST" }))}>Load demo log</button>
        {state === "done" && <>
          <a href={`/api/jobs/${jobId}/export?format=json`}><button>Export JSON</button></a>
          <a href={`/api/jobs/${jobId}/export?format=csv`}><button>Export CSV</button></a></>}
      </div>

      {state === "working" && <p className="msg" role="status">Job {jobId || "…"} is processing. {progress.toLocaleString()} lines read.</p>}
      {state === "error" && <p className="msg err" role="alert">{error}</p>}
      {report && <Report r={report} />}
    </main>
  );
}

function Report({ r }) {
  const s = r.summary;
  return (<>
    <div className="stats">
      <div className="stat"><b>{s.lines.toLocaleString()}</b><span>Lines analyzed</span></div>
      <div className="stat"><b>{s.attacks.toLocaleString()}</b><span>Attack requests</span></div>
      <div className="stat"><b>{s.unique_attackers}</b><span>Attacking IPs</span></div>
      <div className="stat"><b>{s.malformed}</b><span>Unparseable lines</span></div>
    </div>
    <div className="grid">
      <section className="panel"><h2>Attacks per hour</h2>
        <ResponsiveContainer width="100%" height={260}><LineChart data={r.timeline}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
          <XAxis dataKey="hour" tickFormatter={(h) => h.slice(11, 16)} stroke="var(--muted)" />
          <YAxis stroke="var(--muted)" /><Tooltip />
          <Line dataKey="attacks" stroke="var(--high)" strokeWidth={2} dot={false} />
        </LineChart></ResponsiveContainer></section>
      <section className="panel"><h2>Attack types</h2>
        <ResponsiveContainer width="100%" height={260}><BarChart data={r.by_type} layout="vertical">
          <XAxis type="number" stroke="var(--muted)" /><YAxis type="category" dataKey="type" width={130} stroke="var(--muted)" />
          <Tooltip /><Bar dataKey="count" fill="var(--accent)" />
        </BarChart></ResponsiveContainer></section>
      <section className="panel"><h2>Attacks by country</h2>
        <ResponsiveContainer width="100%" height={260}><BarChart data={r.by_country}>
          <XAxis dataKey="country" stroke="var(--muted)" /><YAxis stroke="var(--muted)" />
          <Tooltip /><Bar dataKey="attacks" fill="var(--medium)" />
        </BarChart></ResponsiveContainer></section>
      <section className="panel wrap"><h2>Top attackers</h2>
        <table><thead><tr><th>IP</th><th>Country</th><th>Attacks</th><th>Severity</th><th>Types</th></tr></thead>
          <tbody>{r.top_attackers.map((a) => (
            <tr key={a.ip}><td>{a.ip}</td><td>{a.country}</td><td>{a.attacks}</td>
              <td className={`sev ${a.severity}`}>{a.severity}</td><td>{Object.keys(a.types).join(", ")}</td></tr>))}
          </tbody></table></section>
    </div>
    <section className="panel wrap"><h2>Sample flagged requests</h2>
      <table><thead><tr><th>Time</th><th>IP</th><th>Request</th><th>Type</th><th>Severity</th></tr></thead>
        <tbody>{r.events.slice(0, 50).map((e, i) => (
          <tr key={i}><td>{e.time}</td><td>{e.ip}</td><td>{e.method} {e.path}</td><td>{e.type}</td>
            <td className={`sev ${e.severity}`}>{e.severity}</td></tr>))}
        </tbody></table></section>
  </>);
}
