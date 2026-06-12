import { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import "@/App.css";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api/bb`;

const ALL_MODULES = ["recon", "scan", "vuln"];

function ModulePills({ value, onChange }) {
  const toggle = (m) => {
    if (value.includes(m)) {
      if (value.length === 1) return;
      onChange(value.filter((x) => x !== m));
    } else {
      onChange([...value, m]);
    }
  };
  return (
    <div className="module-pills" data-testid="module-pills">
      {ALL_MODULES.map((m) => (
        <button
          key={m}
          type="button"
          className={`pill ${value.includes(m) ? "active" : ""}`}
          onClick={() => toggle(m)}
          data-testid={`module-pill-${m}`}
        >
          {m}
        </button>
      ))}
    </div>
  );
}

function SummaryStats({ counts }) {
  const cats = ["critical", "high", "medium", "low", "info"];
  const total = cats.reduce((s, k) => s + (counts?.[k] || 0), 0);
  return (
    <div className="summary" data-testid="summary-stats">
      {cats.map((k) => (
        <div key={k} className={`stat ${k}`} data-testid={`stat-${k}`}>
          <div className="lbl">{k}</div>
          <div className="val">{counts?.[k] || 0}</div>
        </div>
      ))}
      <div className="stat total" data-testid="stat-total">
        <div className="lbl">total</div>
        <div className="val">{total}</div>
      </div>
    </div>
  );
}

function Console({ progress }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [progress]);
  if (!progress || progress.length === 0) {
    return (
      <div className="console" data-testid="console-empty">
        <div className="empty">No activity yet. Launch a scan to stream live progress here.</div>
      </div>
    );
  }
  return (
    <div className="console" ref={ref} data-testid="console">
      {progress.map((p, i) => {
        const isModule = p.msg?.startsWith("==");
        const ts = (p.ts || "").slice(11, 19);
        return (
          <div key={i} className={`line ${isModule ? "module" : ""}`}>
            <span className="ts">{ts}</span>
            <span className="msg">{p.msg}</span>
          </div>
        );
      })}
    </div>
  );
}

function Finding({ f }) {
  const sev = (f.severity || "unknown").toLowerCase();
  return (
    <div className={`finding ${sev}`} data-testid={`finding-${f.type || "n"}`}>
      <div className="title">
        <h4>{f.title}</h4>
        <span className={`sev-tag ${sev}`}>{sev}</span>
      </div>
      {f.description && <div className="desc">{f.description}</div>}
      {f.url && (
        <div className="meta-row">URL: <a href={f.url} target="_blank" rel="noreferrer">{f.url}</a></div>
      )}
      {f.evidence && <div className="meta-row">evidence: {f.evidence}</div>}
      {f.reference && (
        <div className="meta-row">
          reference: <a href={f.reference} target="_blank" rel="noreferrer">{f.reference}</a>
        </div>
      )}
    </div>
  );
}

function ReconView({ recon }) {
  if (!recon) return <div className="empty">Recon module was not run.</div>;
  return (
    <div data-testid="recon-view">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18, marginBottom: 20 }}>
        <div>
          <div className="lbl mono" style={{ color: "var(--fg-mute)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 4 }}>target ip</div>
          <div className="mono" style={{ fontSize: 14 }}>{recon.ip || "—"}</div>
        </div>
        <div>
          <div className="lbl mono" style={{ color: "var(--fg-mute)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 4 }}>base url</div>
          <div className="mono" style={{ fontSize: 14, wordBreak: "break-all" }}>{recon.base_url || "—"}</div>
        </div>
      </div>

      <h3 className="mono" style={{ fontSize: 12, color: "var(--fg-mute)", textTransform: "uppercase", letterSpacing: "0.14em" }}>
        Technologies ({recon.technologies?.length || 0})
      </h3>
      {recon.technologies?.length ? (
        <table className="table">
          <thead><tr><th>name</th><th>version</th><th>source</th></tr></thead>
          <tbody>
            {recon.technologies.map((t, i) => (
              <tr key={i}>
                <td>{t.name}</td>
                <td>{t.version || "—"}</td>
                <td>{t.source || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <div className="empty">No technologies detected.</div>}

      <h3 className="mono" style={{ fontSize: 12, color: "var(--fg-mute)", textTransform: "uppercase", letterSpacing: "0.14em", marginTop: 24 }}>
        Subdomains ({recon.subdomains?.length || 0})
      </h3>
      {recon.subdomains?.length ? (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {recon.subdomains.slice(0, 200).map((s, i) => (
            <span key={i} className="kbd">{s}</span>
          ))}
        </div>
      ) : <div className="empty">No subdomains found.</div>}

      <h3 className="mono" style={{ fontSize: 12, color: "var(--fg-mute)", textTransform: "uppercase", letterSpacing: "0.14em", marginTop: 24 }}>
        Directories ({recon.directories?.length || 0})
      </h3>
      {recon.directories?.length ? (
        <table className="table">
          <thead><tr><th>status</th><th>url</th><th>size</th></tr></thead>
          <tbody>
            {recon.directories.map((d, i) => (
              <tr key={i}>
                <td>{d.status_code}</td>
                <td style={{ wordBreak: "break-all" }}>{d.url}</td>
                <td>{d.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <div className="empty">No interesting paths found.</div>}

      <h3 className="mono" style={{ fontSize: 12, color: "var(--fg-mute)", textTransform: "uppercase", letterSpacing: "0.14em", marginTop: 24 }}>
        Forms / URL params
      </h3>
      <div className="mono" style={{ fontSize: 12, color: "var(--fg-dim)" }}>
        {recon.forms?.length || 0} forms · {recon.url_params?.length || 0} parameters
      </div>
    </div>
  );
}

function ScanView({ scan }) {
  if (!scan) return <div className="empty">Scan module was not run.</div>;
  return (
    <div data-testid="scan-view">
      <div className="mono" style={{ fontSize: 13, color: "var(--fg-dim)", marginBottom: 12 }}>
        target: {scan.target} → {scan.ip} · {scan.open_count} open port(s)
      </div>
      <table className="table">
        <thead><tr><th>port</th><th>state</th><th>server</th><th>technologies</th></tr></thead>
        <tbody>
          {scan.ports?.map((p) => (
            <tr key={p.port}>
              <td>{p.port}</td>
              <td style={{ color: p.open ? "var(--ok)" : "var(--fg-mute)" }}>
                {p.open ? "open" : "closed"}
              </td>
              <td>{p.server || "—"}</td>
              <td>
                {(p.technologies || []).map((t) => `${t.name} ${t.version || ""}`).join(", ") || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VulnView({ vuln }) {
  if (!vuln) return <div className="empty">Vuln module was not run.</div>;
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const sorted = [...(vuln.findings || [])].sort(
    (a, b) => (order[(a.severity || "unknown").toLowerCase()] ?? 5) - (order[(b.severity || "unknown").toLowerCase()] ?? 5)
  );
  if (!sorted.length) return <div className="empty">No findings.</div>;
  return (
    <div className="findings" data-testid="vuln-view">
      {sorted.map((f, i) => <Finding key={i} f={f} />)}
    </div>
  );
}

function ReportView({ jobId }) {
  const [fmt, setFmt] = useState("txt");
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const load = async () => {
    if (!jobId) return;
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${jobId}/report?fmt=${fmt}`);
      setContent(r.data.content || "");
    } catch (e) {
      setContent(`Could not load report: ${e?.response?.data?.detail || e.message}`);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, [jobId, fmt]); // eslint-disable-line

  const download = () => {
    const ext = fmt === "md" ? "md" : fmt;
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `report-${jobId}.${ext}`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div data-testid="report-view">
      <div className="report-actions">
        {["txt", "json", "md"].map((f) => (
          <button
            key={f}
            type="button"
            className={`pill ${fmt === f ? "active" : ""}`}
            onClick={() => setFmt(f)}
            data-testid={`report-fmt-${f}`}
          >{f}</button>
        ))}
        <button className="pill" type="button" onClick={download} data-testid="report-download">download</button>
      </div>
      <pre className="report-pre" data-testid="report-pre">
        {loading ? "loading…" : content || "report unavailable"}
      </pre>
    </div>
  );
}

function StatusDot({ status }) {
  return <span className={`dot ${status}`} title={status} />;
}

export default function App() {
  const [target, setTarget] = useState("example.com");
  const [modules, setModules] = useState(["recon", "scan", "vuln"]);
  const [timeout_, setTimeout_] = useState(10);
  const [delay, setDelay] = useState(0);
  const [ports, setPorts] = useState("");
  const [withWhois, setWithWhois] = useState(true);
  const [auth, setAuth] = useState(false);

  const [scans, setScans] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [activeJob, setActiveJob] = useState(null);
  const [tab, setTab] = useState("console");
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast] = useState(null);

  // Load scan history
  const loadHistory = async () => {
    try {
      const r = await axios.get(`${API}/scans?limit=30`);
      setScans(r.data || []);
    } catch (e) { /* ignore */ }
  };

  useEffect(() => {
    loadHistory();
    const i = setInterval(loadHistory, 4000);
    return () => clearInterval(i);
  }, []); // eslint-disable-line

  // Poll active job
  useEffect(() => {
    if (!activeId) { setActiveJob(null); return; }
    let stopped = false;
    const poll = async () => {
      try {
        const r = await axios.get(`${API}/scans/${activeId}`);
        if (!stopped) setActiveJob(r.data);
        if (!stopped && r.data?.status !== "completed" && r.data?.status !== "failed") {
          setTimeout(poll, 1500);
        }
      } catch (e) {
        if (!stopped) setTimeout(poll, 2500);
      }
    };
    poll();
    return () => { stopped = true; };
  }, [activeId]); // eslint-disable-line

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2800);
  };

  const submit = async (e) => {
    e?.preventDefault();
    if (!auth) {
      showToast("You must confirm authorization before scanning.");
      return;
    }
    if (!target.trim()) {
      showToast("Target is required.");
      return;
    }
    setSubmitting(true);
    try {
      const payload = {
        target: target.trim(),
        modules,
        timeout: Number(timeout_) || 10,
        delay: Number(delay) || 0,
        with_whois: withWhois,
        i_have_authorization: true,
      };
      const portList = ports
        .split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !isNaN(n));
      if (portList.length) payload.ports = portList;
      const r = await axios.post(`${API}/scans`, payload);
      setActiveId(r.data.id);
      setTab("console");
      showToast(`Scan queued: ${r.data.id.slice(0, 8)}`);
      loadHistory();
    } catch (e) {
      showToast(e?.response?.data?.detail || e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const counts = activeJob?.result?.vuln?.counts;
  const status = activeJob?.status || "idle";

  const headerStatus = useMemo(() => {
    if (!activeJob) return "Idle. Configure a scan on the left.";
    if (status === "running") return `Scanning ${activeJob.target}…`;
    if (status === "queued") return `Queued ${activeJob.target}`;
    if (status === "completed") return `Completed ${activeJob.target}`;
    if (status === "failed") return `Failed: ${activeJob.error || ""}`;
    return "";
  }, [activeJob, status]);

  return (
    <div className="app" data-testid="app-root">
      <div className="topbar">
        <div className="brand">
          <div className="brand-mark">BB</div>
          <div>
            <div className="brand-title">
              bug-bounty-toolkit <span className="dim">// v1.0</span>
            </div>
            <div className="mono" style={{ fontSize: 11, color: "var(--fg-mute)", letterSpacing: "0.08em" }}>
              {headerStatus}
            </div>
          </div>
        </div>
        <div className="legal-tag" data-testid="legal-tag">
          authorized targets only
        </div>
      </div>

      <div className="grid">
        {/* Left column: form + history */}
        <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
          <form className="panel" onSubmit={submit} data-testid="scan-form">
            <h2><span className="num">01</span>Launch scan</h2>

            <div className="field">
              <label>target (domain / ip)</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                data-testid="input-target"
              />
            </div>

            <div className="field">
              <label>modules</label>
              <ModulePills value={modules} onChange={setModules} />
            </div>

            <div className="row">
              <div className="field">
                <label>timeout (s)</label>
                <input type="number" min="1" value={timeout_}
                       onChange={(e) => setTimeout_(e.target.value)}
                       data-testid="input-timeout" />
              </div>
              <div className="field">
                <label>delay (s)</label>
                <input type="number" min="0" step="0.1" value={delay}
                       onChange={(e) => setDelay(e.target.value)}
                       data-testid="input-delay" />
              </div>
            </div>

            <div className="field">
              <label>ports (optional, comma separated)</label>
              <input type="text" value={ports}
                     onChange={(e) => setPorts(e.target.value)}
                     placeholder="80,443,8080"
                     data-testid="input-ports" />
            </div>

            <label className="checkbox-row">
              <input type="checkbox" checked={withWhois}
                     onChange={(e) => setWithWhois(e.target.checked)}
                     data-testid="input-whois" />
              run WHOIS lookup
            </label>

            <label className="checkbox-row">
              <input type="checkbox" checked={auth}
                     onChange={(e) => setAuth(e.target.checked)}
                     data-testid="input-authorization" />
              <span>
                I have <strong style={{ color: "var(--fg)" }}>explicit written authorization</strong> to test this target.
              </span>
            </label>

            <button
              type="submit"
              className="btn"
              disabled={submitting || !auth}
              data-testid="btn-launch"
            >
              {submitting ? "queueing…" : "▸ run scan"}
            </button>
          </form>

          <div className="panel" data-testid="history-panel">
            <h2><span className="num">02</span>History</h2>
            {scans.length === 0 ? (
              <div className="empty">No scans yet.</div>
            ) : (
              <div className="history">
                {scans.map((s) => (
                  <div
                    key={s.id}
                    className={`history-item ${activeId === s.id ? "active" : ""}`}
                    onClick={() => setActiveId(s.id)}
                    data-testid={`history-item-${s.id}`}
                  >
                    <div>
                      <StatusDot status={s.status} />
                      <span className="target">{s.target}</span>
                    </div>
                    <div className="meta">
                      {s.modules?.join(",")} · {new Date(s.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right column: results */}
        <div className="panel" data-testid="results-panel">
          <h2><span className="num">03</span>Results</h2>

          <SummaryStats counts={counts} />

          <div className="tabs" data-testid="tabs">
            {["console", "recon", "scan", "vuln", "report"].map((t) => (
              <button
                key={t}
                type="button"
                className={tab === t ? "active" : ""}
                onClick={() => setTab(t)}
                data-testid={`tab-${t}`}
              >{t}</button>
            ))}
          </div>

          {!activeJob && (
            <div className="empty" data-testid="no-active-job">
              Run a scan to see live results here.
            </div>
          )}

          {activeJob && tab === "console" && <Console progress={activeJob.progress || []} />}
          {activeJob && tab === "recon" && <ReconView recon={activeJob.result?.recon} />}
          {activeJob && tab === "scan" && <ScanView scan={activeJob.result?.scan} />}
          {activeJob && tab === "vuln" && <VulnView vuln={activeJob.result?.vuln} />}
          {activeJob && tab === "report" && (
            activeJob.status === "completed"
              ? <ReportView jobId={activeJob.id} />
              : <div className="empty">Report will be available once the scan completes.</div>
          )}
        </div>
      </div>

      {toast && <div className="toast" data-testid="toast">{toast}</div>}
    </div>
  );
}
