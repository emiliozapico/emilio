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

function Finding({ f, onReplay }) {
  const sev = (f.severity || "unknown").toLowerCase();
  return (
    <div className={`finding ${sev}`} data-testid={`finding-${f.type || "n"}`}>
      <div className="title">
        <h4>{f.title}</h4>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          {f.cvss && (
            <span className="kbd" title={f.cvss.vector} data-testid="finding-cvss">
              CVSS {f.cvss.score}
            </span>
          )}
          <span className={`sev-tag ${sev}`}>{sev}</span>
        </div>
      </div>
      {f.description && <div className="desc">{f.description}</div>}
      {f.cvss?.vector && (
        <div className="meta-row" style={{ color: "var(--fg-mute)" }}>vector: {f.cvss.vector}</div>
      )}
      {f.url && (
        <div className="meta-row">URL: <a href={f.url} target="_blank" rel="noreferrer">{f.url}</a></div>
      )}
      {f.evidence && <div className="meta-row">evidence: {f.evidence}</div>}
      {f.reference && (
        <div className="meta-row">
          reference: <a href={f.reference} target="_blank" rel="noreferrer">{f.reference}</a>
        </div>
      )}
      {f.curl && (
        <div className="meta-row" style={{ marginTop: 6 }}>
          <code style={{ color: "var(--accent)", wordBreak: "break-all" }}>{f.curl}</code>
        </div>
      )}
      {f.url && onReplay && (
        <div style={{ marginTop: 8, display: "flex", gap: 6 }}>
          <button
            type="button"
            className="pill"
            onClick={() => onReplay(f)}
            data-testid={`btn-replay-${f.type}`}
          >▸ replay in console</button>
          <button
            type="button"
            className="pill"
            onClick={() => navigator.clipboard?.writeText(f.curl || f.url)}
            data-testid={`btn-copy-${f.type}`}
          >copy curl</button>
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

function VulnView({ vuln, onReplay }) {
  if (!vuln) return <div className="empty">Vuln module was not run.</div>;
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const sorted = [...(vuln.findings || [])].sort(
    (a, b) => (order[(a.severity || "unknown").toLowerCase()] ?? 5) - (order[(b.severity || "unknown").toLowerCase()] ?? 5)
  );
  if (!sorted.length) return <div className="empty">No findings.</div>;
  return (
    <div className="findings" data-testid="vuln-view">
      {sorted.map((f, i) => <Finding key={i} f={f} onReplay={onReplay} />)}
    </div>
  );
}

function ReplayView({ initialUrl, initialCurl }) {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState(initialUrl || "");
  const [headersStr, setHeadersStr] = useState("");
  const [cookiesStr, setCookiesStr] = useState("");
  const [body, setBody] = useState("");
  const [followRedirects, setFollowRedirects] = useState(false);
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialUrl) setUrl(initialUrl);
    if (initialCurl) {
      const m = initialCurl.match(/-X\s+(\w+)/);
      if (m) setMethod(m[1]);
    }
  }, [initialUrl, initialCurl]);

  const send = async () => {
    setLoading(true);
    setResponse(null);
    const headers = {};
    headersStr.split("\n").forEach(l => {
      const i = l.indexOf(":");
      if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim();
    });
    const cookies = {};
    cookiesStr.split(";").forEach(p => {
      const i = p.indexOf("=");
      if (i > 0) cookies[p.slice(0, i).trim()] = p.slice(i + 1).trim();
    });
    try {
      const r = await axios.post(`${API}/replay`, {
        method, url,
        headers: Object.keys(headers).length ? headers : undefined,
        cookies: Object.keys(cookies).length ? cookies : undefined,
        body: body || undefined,
        follow_redirects: followRedirects,
        i_have_authorization: true,
      });
      setResponse(r.data);
    } catch (e) {
      setResponse({ error: e?.response?.data?.detail || e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div data-testid="replay-view">
      <div style={{ display: "grid", gridTemplateColumns: "100px 1fr auto", gap: 8, marginBottom: 10 }}>
        <select
          value={method} onChange={(e) => setMethod(e.target.value)}
          data-testid="replay-method"
          style={{
            background: "var(--bg)", color: "var(--fg)",
            border: "1px solid var(--border)", borderRadius: 6,
            padding: "10px 12px", fontFamily: "JetBrains Mono, monospace", fontSize: 13,
          }}
        >
          {["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <input
          type="text" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="http://target/path?param=value"
          data-testid="replay-url"
          style={{
            width: "100%", background: "var(--bg)", color: "var(--fg)",
            border: "1px solid var(--border)", borderRadius: 6,
            padding: "10px 12px", fontFamily: "JetBrains Mono, monospace", fontSize: 13,
          }}
        />
        <button
          className="btn" style={{ width: "auto", padding: "10px 20px" }}
          onClick={send} disabled={loading || !url}
          data-testid="btn-replay-send"
        >{loading ? "…" : "send"}</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
        <div>
          <label style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11, color: "var(--fg-mute)", textTransform: "uppercase" }}>headers (one per line)</label>
          <textarea
            rows={3} value={headersStr}
            onChange={(e) => setHeadersStr(e.target.value)}
            placeholder="X-Test: 1"
            data-testid="replay-headers"
            style={{
              width: "100%", background: "var(--bg)", color: "var(--fg)",
              border: "1px solid var(--border)", borderRadius: 6, padding: "8px",
              fontFamily: "JetBrains Mono, monospace", fontSize: 12, marginTop: 4,
            }}
          />
        </div>
        <div>
          <label style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11, color: "var(--fg-mute)", textTransform: "uppercase" }}>cookies (a=b; c=d)</label>
          <textarea
            rows={3} value={cookiesStr}
            onChange={(e) => setCookiesStr(e.target.value)}
            placeholder="PHPSESSID=abc"
            data-testid="replay-cookies"
            style={{
              width: "100%", background: "var(--bg)", color: "var(--fg)",
              border: "1px solid var(--border)", borderRadius: 6, padding: "8px",
              fontFamily: "JetBrains Mono, monospace", fontSize: 12, marginTop: 4,
            }}
          />
        </div>
      </div>

      <div className="field">
        <label>body (raw)</label>
        <textarea
          rows={3} value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="param1=value1&param2=value2"
          data-testid="replay-body"
        />
      </div>

      <label className="checkbox-row">
        <input type="checkbox" checked={followRedirects}
               onChange={(e) => setFollowRedirects(e.target.checked)}
               data-testid="replay-follow" />
        follow redirects
      </label>

      {response && (
        <div data-testid="replay-response" style={{ marginTop: 10 }}>
          <div className="mono" style={{ fontSize: 12, color: "var(--fg-dim)", marginBottom: 6 }}>
            {response.error
              ? <span style={{ color: "var(--danger)" }}>error: {response.error}</span>
              : <>HTTP <strong style={{ color: response.status_code < 400 ? "var(--ok)" : "var(--warn)" }}>{response.status_code}</strong> {response.reason} · {response.elapsed_ms}ms · {response.body_length} bytes</>}
          </div>
          {!response.error && (
            <>
              <div className="report-pre" style={{ maxHeight: 140 }}>
                {Object.entries(response.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}
              </div>
              <div style={{ height: 8 }} />
              <div className="report-pre" style={{ maxHeight: 320 }}>
                {response.body || "(empty body)"}
              </div>
            </>
          )}
        </div>
      )}
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

  // Advanced
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [cookieStr, setCookieStr] = useState("");
  const [headerStr, setHeaderStr] = useState("");
  const [crawlDepth, setCrawlDepth] = useState(2);
  const [crawlMaxPages, setCrawlMaxPages] = useState(30);
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUser, setLoginUser] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [exploitsList, setExploitsList] = useState([]);
  const [allExploits, setAllExploits] = useState([]);

  // Replay
  const [replayUrl, setReplayUrl] = useState("");
  const [replayCurl, setReplayCurl] = useState("");

  const sendToReplay = (f) => {
    setReplayUrl(f.url || "");
    setReplayCurl(f.curl || "");
    setTab("replay");
  };

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
    axios.get(`${API}/exploits`).then(r => setAllExploits(r.data?.available || [])).catch(() => {});
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
        crawl_depth: Number(crawlDepth) || 2,
        crawl_max_pages: Number(crawlMaxPages) || 30,
        i_have_authorization: true,
      };
      const portList = ports
        .split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !isNaN(n));
      if (portList.length) payload.ports = portList;

      // cookies "a=b; c=d"
      const cookies = {};
      cookieStr.split(";").forEach(p => {
        const i = p.indexOf("=");
        if (i > 0) cookies[p.slice(0, i).trim()] = p.slice(i + 1).trim();
      });
      if (Object.keys(cookies).length) payload.cookies = cookies;

      // headers, one per line, "Name: value"
      const headers = {};
      headerStr.split("\n").forEach(line => {
        const i = line.indexOf(":");
        if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      });
      if (Object.keys(headers).length) payload.headers = headers;

      if (loginUrl && loginUser && loginPassword) {
        payload.login_url = loginUrl;
        payload.login_user = loginUser;
        payload.login_password = loginPassword;
      }
      if (exploitsList.length) payload.enabled_exploits = exploitsList;

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
              bug-bounty-toolkit <span className="dim">// v1.2</span>
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

            <button
              type="button"
              className="pill"
              style={{ width: "100%", padding: "10px", marginBottom: 12 }}
              onClick={() => setShowAdvanced(!showAdvanced)}
              data-testid="btn-toggle-advanced"
            >
              {showAdvanced ? "▾ hide" : "▸ show"} advanced (session, exploits, crawl)
            </button>

            {showAdvanced && (
              <div data-testid="advanced-panel" style={{ marginBottom: 8 }}>
                <div className="row">
                  <div className="field">
                    <label>crawl depth</label>
                    <input type="number" min="0" max="5" value={crawlDepth}
                           onChange={(e) => setCrawlDepth(e.target.value)}
                           data-testid="input-crawl-depth" />
                  </div>
                  <div className="field">
                    <label>crawl max pages</label>
                    <input type="number" min="1" max="200" value={crawlMaxPages}
                           onChange={(e) => setCrawlMaxPages(e.target.value)}
                           data-testid="input-crawl-pages" />
                  </div>
                </div>

                <div className="field">
                  <label>cookies (name=val; name2=val2)</label>
                  <input type="text" value={cookieStr}
                         onChange={(e) => setCookieStr(e.target.value)}
                         placeholder="PHPSESSID=abc; security=low"
                         data-testid="input-cookies" />
                </div>

                <div className="field">
                  <label>custom headers (one per line, Name: value)</label>
                  <textarea rows={2} value={headerStr}
                            onChange={(e) => setHeaderStr(e.target.value)}
                            placeholder="X-API-Key: 123"
                            data-testid="input-headers" />
                </div>

                <div className="field">
                  <label>login url (optional auto-login)</label>
                  <input type="text" value={loginUrl}
                         onChange={(e) => setLoginUrl(e.target.value)}
                         placeholder="http://target/login.php"
                         data-testid="input-login-url" />
                </div>
                <div className="row">
                  <div className="field">
                    <label>login user</label>
                    <input type="text" value={loginUser}
                           onChange={(e) => setLoginUser(e.target.value)}
                           data-testid="input-login-user" />
                  </div>
                  <div className="field">
                    <label>login password</label>
                    <input type="text" value={loginPassword}
                           onChange={(e) => setLoginPassword(e.target.value)}
                           data-testid="input-login-password" />
                  </div>
                </div>

                {allExploits.length > 0 && (
                  <div className="field">
                    <label>active exploits (empty = all)</label>
                    <div className="module-pills" data-testid="exploit-pills">
                      {allExploits.map(ex => (
                        <button
                          key={ex} type="button"
                          className={`pill ${exploitsList.includes(ex) ? "active" : ""}`}
                          onClick={() => setExploitsList(
                            exploitsList.includes(ex)
                              ? exploitsList.filter(x => x !== ex)
                              : [...exploitsList, ex]
                          )}
                          data-testid={`exploit-pill-${ex}`}
                        >{ex}</button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

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
            {["console", "recon", "scan", "vuln", "replay", "report"].map((t) => (
              <button
                key={t}
                type="button"
                className={tab === t ? "active" : ""}
                onClick={() => setTab(t)}
                data-testid={`tab-${t}`}
              >{t}</button>
            ))}
          </div>

          {!activeJob && tab !== "replay" && (
            <div className="empty" data-testid="no-active-job">
              Run a scan to see live results here.
            </div>
          )}

          {activeJob && tab === "console" && <Console progress={activeJob.progress || []} />}
          {activeJob && tab === "recon" && <ReconView recon={activeJob.result?.recon} />}
          {activeJob && tab === "scan" && <ScanView scan={activeJob.result?.scan} />}
          {activeJob && tab === "vuln" && <VulnView vuln={activeJob.result?.vuln} onReplay={sendToReplay} />}
          {tab === "replay" && <ReplayView initialUrl={replayUrl} initialCurl={replayCurl} />}
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
