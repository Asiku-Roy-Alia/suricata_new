import React, { useEffect, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const ES_URL = process.env.REACT_APP_ES_URL || "";
const ES_INDEX = process.env.REACT_APP_ES_INDEX || "hybrid-ids-decisions";
const COLORS = {
  benign: "#16a34a",
  attack_both: "#dc2626",
  attack_suricata_only: "#d97706",
  attack_ml_only: "#2563eb",
};

function fmtNumber(x) {
  return Number(x || 0).toLocaleString();
}

function fmtBytes(bytes) {
  const value = Number(bytes || 0);
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)} GB`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)} KB`;
  return `${value.toFixed(0)} B`;
}

function labelVerdict(v) {
  return {
    benign: "Benign",
    attack_both: "Both engines",
    attack_suricata_only: "Suricata only",
    attack_ml_only: "ML only",
  }[v] || v || "Unknown";
}

function normalizeRecord(source, id) {
  const timestamp = source["@timestamp"] || source.timestamp || new Date().toISOString();
  return {
    id,
    timestamp,
    time: new Date(timestamp).toLocaleTimeString(),
    src_ip: source.src_ip || "",
    dst_ip: source.dst_ip || source.dest_ip || "",
    dst_port: Number(source.dst_port || 0),
    proto: source.proto || "",
    bytes_total: Number(source.bytes_total || 0),
    pkts_total: Number(source.pkts_total || 0),
    duration_ms: Number(source.duration_ms || 0),
    suricata_alert: Boolean(source.suricata_alert),
    suricata_signature: source.suricata_signature || "",
    ml_proba: Number(source.ml_proba || 0),
    ml_decision: Boolean(source.ml_decision),
    fused_decision: Boolean(source.fused_decision),
    fusion_reason: source.fusion_reason || "none",
    verdict: source.verdict || (source.fused_decision ? "attack_ml_only" : "benign"),
  };
}

async function fetchDecisions(limit = 600) {
  const response = await fetch(`${ES_URL}/${ES_INDEX}/_search`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      size: limit,
      sort: [{ "@timestamp": { order: "desc", unmapped_type: "date" } }],
      query: { match_all: {} },
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Elasticsearch ${response.status}: ${body.slice(0, 160)}`);
  }

  const json = await response.json();
  return (json.hits?.hits || []).map((hit) => normalizeRecord(hit._source || {}, hit._id));
}

function groupBy(items, keyFn) {
  const out = new Map();
  for (const item of items) {
    const key = keyFn(item);
    out.set(key, (out.get(key) || 0) + 1);
  }
  return [...out.entries()].map(([name, value]) => ({ name, value }));
}

function topBy(items, keyFn, n = 8) {
  return groupBy(items, keyFn).sort((a, b) => b.value - a.value).slice(0, n);
}

function buildTimeline(records) {
  const buckets = new Map();
  for (const row of [...records].reverse()) {
    const d = new Date(row.timestamp);
    if (Number.isNaN(d.getTime())) continue;
    const bucketDate = new Date(Math.floor(d.getTime() / 15000) * 15000);
    const key = bucketDate.toLocaleTimeString();
    const bucket = buckets.get(key) || { time: key, benign: 0, attack_both: 0, attack_suricata_only: 0, attack_ml_only: 0 };
    bucket[row.verdict] = (bucket[row.verdict] || 0) + 1;
    buckets.set(key, bucket);
  }
  return [...buckets.values()].slice(-24);
}

function StatCard({ title, value, caption, tone }) {
  return (
    <div style={{ background: "white", border: "1px solid #e5e7eb", borderRadius: 14, padding: 18 }}>
      <div style={{ color: "#64748b", fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em" }}>{title}</div>
      <div style={{ color: tone || "#0f172a", fontSize: 30, fontWeight: 800, marginTop: 8 }}>{value}</div>
      <div style={{ color: "#64748b", fontSize: 12, marginTop: 6 }}>{caption}</div>
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <section style={{ background: "white", border: "1px solid #e5e7eb", borderRadius: 14, padding: 18, minHeight: 300 }}>
      <h2 style={{ margin: "0 0 16px 0", fontSize: 16, color: "#0f172a" }}>{title}</h2>
      {children}
    </section>
  );
}

export default function HybridIDSDashboard() {
  const [records, setRecords] = useState([]);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [status, setStatus] = useState("Connecting to Elasticsearch...");
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    let alive = true;

    async function load() {
      if (paused) return;
      try {
        const rows = await fetchDecisions();
        if (!alive) return;
        setRecords(rows);
        setLastRefresh(new Date());
        setStatus(rows.length ? "Live" : "Connected, waiting for bridge decisions");
      } catch (err) {
        if (!alive) return;
        setStatus(err.message);
      }
    }

    load();
    const timer = setInterval(load, 3000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [paused]);

  const stats = useMemo(() => {
    const total = records.length;
    const attacks = records.filter((r) => r.fused_decision).length;
    const suri = records.filter((r) => r.suricata_alert).length;
    const ml = records.filter((r) => r.ml_decision).length;
    const both = records.filter((r) => r.suricata_alert && r.ml_decision).length;
    const bytes = records.reduce((sum, r) => sum + r.bytes_total, 0);
    return { total, attacks, benign: total - attacks, suri, ml, both, bytes };
  }, [records]);

  const verdictData = useMemo(() => {
    return topBy(records, (r) => r.verdict, 10).map((row) => ({ ...row, label: labelVerdict(row.name) }));
  }, [records]);

  const timeline = useMemo(() => buildTimeline(records), [records]);
  const signatures = useMemo(() => topBy(records.filter((r) => r.suricata_signature), (r) => r.suricata_signature, 8), [records]);
  const attackers = useMemo(() => topBy(records.filter((r) => r.fused_decision), (r) => r.src_ip, 8), [records]);
  const recentAlerts = records.filter((r) => r.fused_decision).slice(0, 20);

  return (
    <div style={{ minHeight: "100vh", background: "#f1f5f9", fontFamily: "Inter, Segoe UI, Arial, sans-serif", color: "#0f172a" }}>
      <header style={{ background: "#020617", color: "white", padding: "18px 28px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ fontSize: 24, fontWeight: 900 }}>Hybrid IDS Command Dashboard</div>
          <div style={{ color: "#94a3b8", fontSize: 13, marginTop: 4 }}>Suricata signatures + stacked ML fusion, backed by Elasticsearch</div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ background: status === "Live" ? "#14532d" : "#713f12", color: "white", padding: "8px 12px", borderRadius: 999, fontSize: 12, fontWeight: 700 }}>{status}</span>
          <button onClick={() => setPaused((p) => !p)} style={{ border: 0, borderRadius: 10, padding: "9px 14px", fontWeight: 800, cursor: "pointer" }}>{paused ? "Resume" : "Pause"}</button>
        </div>
      </header>

      <main style={{ padding: 24 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(0, 1fr))", gap: 14, marginBottom: 18 }}>
          <StatCard title="Recent flows" value={fmtNumber(stats.total)} caption="Last records pulled from Elasticsearch" />
          <StatCard title="Fused attacks" value={fmtNumber(stats.attacks)} caption={`${stats.total ? ((stats.attacks / stats.total) * 100).toFixed(1) : "0.0"}% of current window`} tone="#dc2626" />
          <StatCard title="Suricata hits" value={fmtNumber(stats.suri)} caption="Signature engine positives" tone="#d97706" />
          <StatCard title="ML hits" value={fmtNumber(stats.ml)} caption="Hybrid model positives" tone="#2563eb" />
          <StatCard title="Traffic volume" value={fmtBytes(stats.bytes)} caption={lastRefresh ? `Refreshed ${lastRefresh.toLocaleTimeString()}` : "Waiting"} />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18, marginBottom: 18 }}>
          <Panel title="Decision mix">
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={verdictData} dataKey="value" nameKey="label" outerRadius={95} label>
                  {verdictData.map((entry) => <Cell key={entry.name} fill={COLORS[entry.name] || "#64748b"} />)}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </Panel>

          <Panel title="Flow rate over time">
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" minTickGap={20} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Area dataKey="benign" stackId="1" stroke={COLORS.benign} fill={COLORS.benign} />
                <Area dataKey="attack_suricata_only" stackId="1" stroke={COLORS.attack_suricata_only} fill={COLORS.attack_suricata_only} />
                <Area dataKey="attack_ml_only" stackId="1" stroke={COLORS.attack_ml_only} fill={COLORS.attack_ml_only} />
                <Area dataKey="attack_both" stackId="1" stroke={COLORS.attack_both} fill={COLORS.attack_both} />
              </AreaChart>
            </ResponsiveContainer>
          </Panel>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18, marginBottom: 18 }}>
          <Panel title="Top attacker source IPs">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={attackers} layout="vertical" margin={{ left: 70 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" allowDecimals={false} />
                <YAxis dataKey="name" type="category" width={110} />
                <Tooltip />
                <Bar dataKey="value" fill="#dc2626" />
              </BarChart>
            </ResponsiveContainer>
          </Panel>

          <Panel title="Suricata signature hits">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={signatures} layout="vertical" margin={{ left: 130 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" allowDecimals={false} />
                <YAxis dataKey="name" type="category" width={170} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="value" fill="#d97706" />
              </BarChart>
            </ResponsiveContainer>
          </Panel>
        </div>

        <section style={{ background: "white", border: "1px solid #e5e7eb", borderRadius: 14, padding: 18 }}>
          <h2 style={{ marginTop: 0, fontSize: 16 }}>Recent fused alerts</h2>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ background: "#f8fafc", color: "#475569" }}>
                  {["Time", "Verdict", "Source", "Destination", "Proto", "Bytes", "ML probability", "Signature"].map((h) => (
                    <th key={h} style={{ textAlign: "left", padding: "10px 8px", borderBottom: "1px solid #e5e7eb" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((r) => (
                  <tr key={r.id}>
                    <td style={td}>{r.time}</td>
                    <td style={{ ...td, color: COLORS[r.verdict] || "#0f172a", fontWeight: 800 }}>{labelVerdict(r.verdict)}</td>
                    <td style={td}>{r.src_ip}</td>
                    <td style={td}>{r.dst_ip}:{r.dst_port}</td>
                    <td style={td}>{r.proto}</td>
                    <td style={td}>{fmtBytes(r.bytes_total)}</td>
                    <td style={td}>{r.ml_proba.toFixed(3)}</td>
                    <td style={td}>{r.suricata_signature || r.fusion_reason}</td>
                  </tr>
                ))}
                {!recentAlerts.length && (
                  <tr><td style={td} colSpan={8}>No attack records yet. Wait for the generator, Suricata and bridge to warm up, then refresh.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

const td = { padding: "9px 8px", borderBottom: "1px solid #eef2f7", whiteSpace: "nowrap" };
