import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Legend, CartesianGrid } from "recharts";

/* ═══════════════════════════════════════════════════════════════
   DATA SIMULATION ENGINE
   ═══════════════════════════════════════════════════════════════ */
const PROTOCOLS = ["TCP","UDP","ICMP","HTTP","HTTPS","DNS","SSH","FTP","SMTP"];
const ATTACK_SIGS = [
  { name:"SYN Flood", sig:"LOCAL Possible TCP SYN scan", sev:3, proto:"TCP", ports:[80,443,8080] },
  { name:"SSH Brute", sig:"LOCAL SSH connection attempt", sev:2, proto:"SSH", ports:[22] },
  { name:"HTTP Login Brute", sig:"LOCAL HTTP POST to login endpoint", sev:2, proto:"HTTP", ports:[80,443] },
  { name:"SQL Injection", sig:"LOCAL Possible SQL injection (UNION SELECT)", sev:3, proto:"HTTP", ports:[80,443,8080] },
  { name:"Port Scan", sig:"LOCAL Possible TCP SYN scan", sev:1, proto:"TCP", ports:[21,22,23,25,80,110,443] },
  { name:"ICMP Flood", sig:"LOCAL ICMP echo request seen", sev:1, proto:"ICMP", ports:[0] },
  { name:"FTP Brute", sig:"LOCAL FTP authentication attempt", sev:2, proto:"FTP", ports:[21] },
];
const SUBNETS = ["192.168.10","172.16.0","10.0.1","10.0.2"];
const EXT_IPS = ["104.18.32.7","8.8.8.8","1.1.1.1","13.107.42.14","151.101.1.69","93.184.216.34","52.84.150.11","142.250.80.46","34.117.59.81","185.199.108.153"];
const ri = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const rc = a => a[Math.floor(Math.random()*a.length)];
const ts = () => { const d=new Date(); return d.toTimeString().slice(0,8)+"."+String(d.getMilliseconds()).padStart(3,"0"); };
let flowId = 0;

function genFlow(attackRate=0.06, mlThreshold=0.5) {
  const isAtk = Math.random() < attackRate;
  const atk = isAtk ? rc(ATTACK_SIGS) : null;
  const proto = isAtk ? atk.proto : rc(PROTOCOLS);
  const srcIp = `${rc(SUBNETS)}.${ri(1,254)}`;
  const dstIp = isAtk ? `${rc(SUBNETS)}.${ri(1,254)}` : rc(EXT_IPS);
  const srcPort = ri(1024,65535);
  const dstPort = isAtk ? rc(atk.ports) : rc([80,443,53,22,8080,3306,5432]);
  const suriAlert = isAtk && Math.random() < 0.85;
  const mlProba = isAtk ? 0.45+Math.random()*0.55 : Math.random()*0.35;
  const mlDecision = mlProba >= mlThreshold;
  const both = suriAlert && mlDecision;
  const verdict = both ? "attack_both" : suriAlert ? "attack_suricata_only" : mlDecision ? "attack_ml_only" : "benign";
  const fusedDecision = verdict !== "benign";
  const bytesTotal = isAtk ? ri(40,800) : ri(200,15000);
  const pktsTotal = isAtk ? ri(1,12) : ri(2,45);
  return {
    id: ++flowId, time: ts(), timestamp: Date.now(),
    srcIp, dstIp, srcPort, dstPort, proto,
    suriAlert, suriSig: suriAlert ? atk.sig : "",
    mlProba: +mlProba.toFixed(4), mlDecision, verdict, fusedDecision,
    bytesTotal, pktsTotal, attackName: isAtk ? atk.name : ""
  };
}

/* ═══════════════════════════════════════════════════════════════
   DESIGN TOKENS
   ═══════════════════════════════════════════════════════════════ */
const T = {
  bg: "#f0f2f5", surface: "#ffffff", surfaceAlt: "#f8f9fb",
  border: "#e2e6ec", borderLight: "#edf0f4",
  text: "#1a1d23", textSec: "#4a5568", textMut: "#8896a8",
  accent: "#2563eb", accentLight: "#dbeafe",
  green: "#16a34a", greenBg: "#dcfce7", greenLight: "#bbf7d0",
  amber: "#d97706", amberBg: "#fef3c7",
  red: "#dc2626", redBg: "#fee2e2", redLight: "#fecaca",
  blue: "#2563eb", blueBg: "#dbeafe",
  purple: "#7c3aed",
  verdictColors: { benign:"#16a34a", attack_suricata_only:"#d97706", attack_ml_only:"#2563eb", attack_both:"#dc2626" },
};

/* ═══════════════════════════════════════════════════════════════
   MAIN DASHBOARD COMPONENT
   ═══════════════════════════════════════════════════════════════ */
export default function HybridIDSDashboard() {
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [suriLog, setSuriLog] = useState([]);
  const [timeData, setTimeData] = useState([]);
  const [stats, setStats] = useState({ total:0, attacks:0, benign:0, suriOnly:0, mlOnly:0, both:0, bytes:0, pkts:0, attackBytes:0 });
  const [protoStats, setProtoStats] = useState({});
  const [sigStats, setSigStats] = useState({});
  const [mlProbaHistory, setMlProbaHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("live");
  const [mlThreshold, setMlThreshold] = useState(0.5);
  const [attackRate, setAttackRate] = useState(0.06);
  const [refreshRate, setRefreshRate] = useState(800);
  const [showBenign, setShowBenign] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const [uptime, setUptime] = useState(0);
  const [batchSize, setBatchSize] = useState(5);
  const flowRef = useRef(null);
  const alertRef = useRef(null);
  const startTime = useRef(Date.now());

  // Uptime ticker
  useEffect(() => {
    const t = setInterval(() => setUptime(Math.floor((Date.now()-startTime.current)/1000)), 1000);
    return () => clearInterval(t);
  }, []);

  // Main simulation loop
  useEffect(() => {
    if (isPaused) return;
    const interval = setInterval(() => {
      const batch = Array.from({length: batchSize}, () => genFlow(attackRate, mlThreshold));
      setFlows(prev => [...batch, ...prev].slice(0, 500));
      setAlerts(prev => {
        const newAlerts = batch.filter(f => f.fusedDecision);
        return [...newAlerts, ...prev].slice(0, 300);
      });
      setSuriLog(prev => {
        const newSuri = batch.filter(f => f.suriAlert);
        return [...newSuri, ...prev].slice(0, 200);
      });
      setMlProbaHistory(prev => {
        const newPts = batch.map(f => ({ t: f.timestamp, p: f.mlProba, v: f.verdict }));
        return [...prev, ...newPts].slice(-400);
      });
      setStats(prev => {
        const s = {...prev};
        batch.forEach(f => {
          s.total++; s.bytes += f.bytesTotal; s.pkts += f.pktsTotal;
          if (f.fusedDecision) { s.attacks++; s.attackBytes += f.bytesTotal; }
          else s.benign++;
          if (f.verdict === "attack_suricata_only") s.suriOnly++;
          if (f.verdict === "attack_ml_only") s.mlOnly++;
          if (f.verdict === "attack_both") s.both++;
        });
        return s;
      });
      setProtoStats(prev => {
        const p = {...prev};
        batch.forEach(f => { p[f.proto] = (p[f.proto]||0)+1; });
        return p;
      });
      setSigStats(prev => {
        const s = {...prev};
        batch.filter(f => f.suriAlert).forEach(f => { s[f.suriSig] = (s[f.suriSig]||0)+1; });
        return s;
      });
      // Time series buckets (5s intervals)
      setTimeData(prev => {
        const now = Math.floor(Date.now()/5000)*5000;
        const updated = [...prev];
        let bucket = updated.find(b => b.t === now);
        if (!bucket) {
          bucket = { t: now, benign:0, attack_suricata_only:0, attack_ml_only:0, attack_both:0, total:0 };
          updated.push(bucket);
        }
        batch.forEach(f => { bucket[f.verdict]++; bucket.total++; });
        return updated.slice(-30);
      });
    }, refreshRate);
    return () => clearInterval(interval);
  }, [isPaused, attackRate, mlThreshold, refreshRate, batchSize]);

  // Auto-scroll logs
  useEffect(() => { if(flowRef.current) flowRef.current.scrollTop = 0; }, [flows]);
  useEffect(() => { if(alertRef.current) alertRef.current.scrollTop = 0; }, [alerts]);

  const fmtUptime = (s) => { const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60; return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`; };
  const fmtBytes = (b) => b > 1e6 ? `${(b/1e6).toFixed(1)} MB` : b > 1e3 ? `${(b/1e3).toFixed(1)} KB` : `${b} B`;
  const agreementPct = stats.total > 0 ? ((stats.both+stats.benign)/stats.total*100).toFixed(1) : "0.0";
  const attackPct = stats.total > 0 ? (stats.attacks/stats.total*100).toFixed(1) : "0.0";

  const verdictData = useMemo(() => [
    { name:"Benign", value: stats.benign, color: T.green },
    { name:"Suricata Only", value: stats.suriOnly, color: T.amber },
    { name:"ML Only", value: stats.mlOnly, color: T.blue },
    { name:"Both Engines", value: stats.both, color: T.red },
  ].filter(d => d.value > 0), [stats]);

  const protoData = useMemo(() =>
    Object.entries(protoStats).sort((a,b) => b[1]-a[1]).slice(0,8).map(([k,v]) => ({ name:k, count:v })),
  [protoStats]);

  const sigData = useMemo(() =>
    Object.entries(sigStats).sort((a,b) => b[1]-a[1]).slice(0,6).map(([k,v]) => ({ name: k.replace("LOCAL ",""), count:v })),
  [sigStats]);

  const matrixData = useMemo(() => ({
    benBen: stats.benign, benAtk: stats.mlOnly,
    atkBen: stats.suriOnly, atkAtk: stats.both
  }), [stats]);

  const verdictLabel = (v) => ({ benign:"CLEAN", attack_suricata_only:"SURI", attack_ml_only:"ML", attack_both:"BOTH" }[v]||v);
  const verdictColor = (v) => T.verdictColors[v] || T.textMut;

  const tabs = [
    { id:"live", label:"Live Feed", icon:"⚡" },
    { id:"charts", label:"Analytics", icon:"📊" },
    { id:"attribution", label:"Attribution", icon:"🎯" },
    { id:"model", label:"Model Insight", icon:"🧠" },
  ];

  return (
    <div style={{ fontFamily:"'IBM Plex Sans','Segoe UI',system-ui,sans-serif", background:T.bg, minHeight:"100vh", color:T.text }}>
      {/* ── HEADER ── */}
      <div style={{ background:T.surface, borderBottom:`1px solid ${T.border}`, padding:"12px 24px", display:"flex", alignItems:"center", justifyContent:"space-between", position:"sticky", top:0, zIndex:100 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:36, height:36, borderRadius:8, background:"linear-gradient(135deg,#2563eb,#7c3aed)", display:"flex", alignItems:"center", justifyContent:"center", color:"#fff", fontSize:18, fontWeight:700 }}>⛨</div>
          <div>
            <div style={{ fontSize:16, fontWeight:700, letterSpacing:"-0.01em" }}>Hybrid IDS</div>
            <div style={{ fontSize:11, color:T.textMut, fontFamily:"'IBM Plex Mono',monospace" }}>Suricata + Stacked ML · Fusion Engine · Real-Time Defence</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:20 }}>
          <div style={{ textAlign:"right" }}>
            <div style={{ fontSize:10, color:T.textMut, textTransform:"uppercase", letterSpacing:"0.08em" }}>Uptime</div>
            <div style={{ fontSize:14, fontWeight:600, fontFamily:"'IBM Plex Mono',monospace" }}>{fmtUptime(uptime)}</div>
          </div>
          <div style={{ textAlign:"right" }}>
            <div style={{ fontSize:10, color:T.textMut, textTransform:"uppercase", letterSpacing:"0.08em" }}>Engine Status</div>
            <div style={{ display:"flex", alignItems:"center", gap:6 }}>
              <span style={{ width:8, height:8, borderRadius:"50%", background: isPaused ? T.amber : T.green, display:"inline-block", boxShadow: isPaused ? "none" : `0 0 6px ${T.green}` }} />
              <span style={{ fontSize:13, fontWeight:600, color: isPaused ? T.amber : T.green }}>{isPaused ? "PAUSED" : "ACTIVE"}</span>
            </div>
          </div>
          <button onClick={() => setIsPaused(!isPaused)} style={{ padding:"6px 16px", borderRadius:6, border:`1px solid ${isPaused ? T.green : T.amber}`, background: isPaused ? T.greenBg : T.amberBg, color: isPaused ? T.green : T.amber, fontWeight:600, fontSize:12, cursor:"pointer" }}>
            {isPaused ? "▶ Resume" : "⏸ Pause"}
          </button>
        </div>
      </div>

      <div style={{ display:"flex", minHeight:"calc(100vh - 60px)" }}>
        {/* ── SIDEBAR ── */}
        <div style={{ width:240, background:T.surface, borderRight:`1px solid ${T.border}`, padding:"16px 12px", flexShrink:0, overflowY:"auto" }}>
          <div style={{ fontSize:10, fontWeight:600, color:T.textMut, textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:8 }}>Controls</div>

          <SidebarControl label="Attack Rate" value={`${(attackRate*100).toFixed(0)}%`}>
            <input type="range" min={1} max={30} value={attackRate*100} onChange={e => setAttackRate(e.target.value/100)} style={{ width:"100%" }} />
          </SidebarControl>

          <SidebarControl label="ML Threshold" value={mlThreshold.toFixed(2)}>
            <input type="range" min={10} max={90} value={mlThreshold*100} onChange={e => setMlThreshold(e.target.value/100)} style={{ width:"100%" }} />
          </SidebarControl>

          <SidebarControl label="Refresh (ms)" value={refreshRate}>
            <input type="range" min={200} max={3000} step={100} value={refreshRate} onChange={e => setRefreshRate(+e.target.value)} style={{ width:"100%" }} />
          </SidebarControl>

          <SidebarControl label="Batch Size" value={batchSize}>
            <input type="range" min={1} max={20} value={batchSize} onChange={e => setBatchSize(+e.target.value)} style={{ width:"100%" }} />
          </SidebarControl>

          <label style={{ display:"flex", alignItems:"center", gap:8, fontSize:12, color:T.textSec, marginTop:12, cursor:"pointer" }}>
            <input type="checkbox" checked={showBenign} onChange={e => setShowBenign(e.target.checked)} />
            Show benign in feed
          </label>

          <div style={{ marginTop:24, padding:12, background:T.surfaceAlt, borderRadius:8, border:`1px solid ${T.borderLight}` }}>
            <div style={{ fontSize:10, fontWeight:600, color:T.textMut, textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:8 }}>Network Stats</div>
            <StatLine label="Total Flows" value={stats.total.toLocaleString()} />
            <StatLine label="Total Packets" value={stats.pkts.toLocaleString()} />
            <StatLine label="Total Bytes" value={fmtBytes(stats.bytes)} />
            <StatLine label="Attack Bytes" value={fmtBytes(stats.attackBytes)} color={T.red} />
          </div>

          <div style={{ marginTop:16, padding:12, background:T.surfaceAlt, borderRadius:8, border:`1px solid ${T.borderLight}` }}>
            <div style={{ fontSize:10, fontWeight:600, color:T.textMut, textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:8 }}>Protocol Mix</div>
            {Object.entries(protoStats).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([p,c]) => (
              <div key={p} style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:T.textSec, marginBottom:3 }}>
                <span style={{ fontFamily:"'IBM Plex Mono',monospace", fontWeight:500 }}>{p}</span>
                <span>{c.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── MAIN CONTENT ── */}
        <div style={{ flex:1, padding:"16px 20px", overflowY:"auto" }}>
          {/* Metrics Row */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(7,1fr)", gap:10, marginBottom:16 }}>
            <MetricCard label="Total Flows" value={stats.total.toLocaleString()} />
            <MetricCard label="Confirmed Attacks" value={stats.attacks.toLocaleString()} accent={T.red} sub={`${attackPct}%`} />
            <MetricCard label="Benign" value={stats.benign.toLocaleString()} accent={T.green} />
            <MetricCard label="Suricata Only" value={stats.suriOnly.toLocaleString()} accent={T.amber} />
            <MetricCard label="ML Only" value={stats.mlOnly.toLocaleString()} accent={T.blue} />
            <MetricCard label="Both Engines" value={stats.both.toLocaleString()} accent={T.red} />
            <MetricCard label="Agreement" value={`${agreementPct}%`} accent={T.purple} />
          </div>

          {/* Tab Bar */}
          <div style={{ display:"flex", gap:0, borderBottom:`2px solid ${T.border}`, marginBottom:16 }}>
            {tabs.map(t => (
              <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
                padding:"8px 20px", fontSize:12, fontWeight:600, border:"none", cursor:"pointer",
                background:"none", color: activeTab===t.id ? T.accent : T.textMut,
                borderBottom: activeTab===t.id ? `2px solid ${T.accent}` : "2px solid transparent",
                marginBottom:-2, letterSpacing:"0.02em", transition:"all 0.15s"
              }}>
                {t.icon} {t.label}
              </button>
            ))}
          </div>

          {/* ── TAB: LIVE FEED ── */}
          {activeTab === "live" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                {/* Flow Monitor */}
                <Card title="📡 Flow Monitor" sub={`${flows.length} events buffered`}>
                  <div ref={flowRef} style={{ height:280, overflowY:"auto", fontFamily:"'IBM Plex Mono',monospace", fontSize:11.5, lineHeight:1.7, background:T.surfaceAlt, borderRadius:6, padding:"8px 10px", border:`1px solid ${T.borderLight}` }}>
                    {(showBenign ? flows : flows.filter(f => f.fusedDecision)).slice(0,80).map(f => (
                      <div key={f.id} style={{ opacity: f.fusedDecision ? 1 : 0.65, animation:"fadeIn 0.3s ease" }}>
                        <span style={{ color:T.textMut }}>{f.time}</span>
                        {" "}<span style={{ color:verdictColor(f.verdict), fontWeight:700 }}>{verdictLabel(f.verdict)}</span>
                        {" "}<span style={{ color:T.text }}>{f.srcIp}</span>
                        <span style={{ color:T.textMut }}> → </span>
                        <span style={{ color:T.text }}>{f.dstIp}</span>
                        <span style={{ color:T.textMut }}>:{f.dstPort} {f.proto}</span>
                        {" "}<span style={{ color:T.textMut }}>p={f.mlProba.toFixed(2)}</span>
                        {f.suriSig && <span style={{ color:T.amber }}> · {f.suriSig.replace("LOCAL ","")}</span>}
                      </div>
                    ))}
                  </div>
                </Card>

                {/* Alert Stream */}
                <Card title="🚨 Alert Stream" sub={`${alerts.length} confirmed attacks`} accent={T.red}>
                  <div ref={alertRef} style={{ height:280, overflowY:"auto", fontFamily:"'IBM Plex Mono',monospace", fontSize:11.5, lineHeight:1.7, background:"#fef8f8", borderRadius:6, padding:"8px 10px", border:`1px solid ${T.redLight}` }}>
                    {alerts.slice(0,60).map(f => (
                      <div key={f.id} style={{ animation:"fadeIn 0.3s ease" }}>
                        <span style={{ color:T.textMut }}>{f.time}</span>
                        {" "}<span style={{ color:verdictColor(f.verdict), fontWeight:700 }}>{verdictLabel(f.verdict)}</span>
                        {" "}<span style={{ color:T.text }}>{f.srcIp}</span>
                        <span style={{ color:T.textMut }}> → </span>
                        <span style={{ color:T.text }}>{f.dstIp}:{f.dstPort}</span>
                        {" "}<span style={{ color:T.red, fontWeight:600 }}>{f.attackName}</span>
                        {f.suriSig && <span style={{ color:T.amber }}> · {f.suriSig.replace("LOCAL ","")}</span>}
                      </div>
                    ))}
                    {alerts.length === 0 && <div style={{ color:T.textMut, fontStyle:"italic" }}>Waiting for attacks...</div>}
                  </div>
                </Card>
              </div>

              {/* Second row: Suricata Log + Live Area Chart */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                <Card title="🔔 Suricata Signature Log" sub={`${suriLog.length} alerts`} accent={T.amber}>
                  <div style={{ height:220, overflowY:"auto", fontFamily:"'IBM Plex Mono',monospace", fontSize:11.5, lineHeight:1.7, background:T.surfaceAlt, borderRadius:6, padding:"8px 10px", border:`1px solid ${T.borderLight}` }}>
                    {suriLog.slice(0,40).map(f => (
                      <div key={f.id} style={{ animation:"fadeIn 0.3s ease" }}>
                        <span style={{ color:T.textMut }}>{f.time}</span>
                        {" "}<span style={{ color:T.amber, fontWeight:700 }}>ALERT</span>
                        {" "}<span style={{ color:T.text }}>{f.srcIp}</span>
                        <span style={{ color:T.textMut }}> → </span>
                        <span>{f.dstIp}:{f.dstPort}</span>
                        {" "}<span style={{ color:T.amber }}>{f.suriSig.replace("LOCAL ","")}</span>
                      </div>
                    ))}
                  </div>
                </Card>

                <Card title="📈 Flow Rate (5s bins, live)" sub="Stacked by verdict">
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={timeData} margin={{ top:5,right:10,left:0,bottom:0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={T.borderLight} />
                      <XAxis dataKey="t" tickFormatter={v => new Date(v).toTimeString().slice(3,8)} tick={{ fontSize:10, fill:T.textMut }} />
                      <YAxis tick={{ fontSize:10, fill:T.textMut }} width={35} />
                      <Tooltip contentStyle={{ fontSize:11, borderRadius:6, border:`1px solid ${T.border}` }} labelFormatter={v => new Date(v).toTimeString().slice(0,8)} />
                      <Area type="monotone" dataKey="benign" stackId="1" fill={T.greenLight} stroke={T.green} fillOpacity={0.6} />
                      <Area type="monotone" dataKey="attack_suricata_only" stackId="1" fill={T.amberBg} stroke={T.amber} fillOpacity={0.7} />
                      <Area type="monotone" dataKey="attack_ml_only" stackId="1" fill={T.blueBg} stroke={T.blue} fillOpacity={0.7} />
                      <Area type="monotone" dataKey="attack_both" stackId="1" fill={T.redLight} stroke={T.red} fillOpacity={0.7} />
                    </AreaChart>
                  </ResponsiveContainer>
                </Card>
              </div>
            </div>
          )}

          {/* ── TAB: ANALYTICS ── */}
          {activeTab === "charts" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="Verdict Distribution" sub={`${stats.total.toLocaleString()} total flows`}>
                  <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:20 }}>
                    <ResponsiveContainer width={200} height={200}>
                      <PieChart>
                        <Pie data={verdictData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={3} dataKey="value">
                          {verdictData.map((d,i) => <Cell key={i} fill={d.color} />)}
                        </Pie>
                        <Tooltip contentStyle={{ fontSize:11, borderRadius:6 }} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div>
                      {verdictData.map(d => (
                        <div key={d.name} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                          <div style={{ width:10, height:10, borderRadius:2, background:d.color }} />
                          <span style={{ fontSize:12, color:T.textSec }}>{d.name}</span>
                          <span style={{ fontSize:12, fontWeight:600, marginLeft:4 }}>{d.value.toLocaleString()}</span>
                          <span style={{ fontSize:10, color:T.textMut }}>({stats.total > 0 ? (d.value/stats.total*100).toFixed(1) : 0}%)</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </Card>

                <Card title="Flow Rate Over Time" sub="5-second bins, stacked">
                  <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={timeData} margin={{ top:5,right:10,left:0,bottom:0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={T.borderLight} />
                      <XAxis dataKey="t" tickFormatter={v => new Date(v).toTimeString().slice(3,8)} tick={{ fontSize:10, fill:T.textMut }} />
                      <YAxis tick={{ fontSize:10, fill:T.textMut }} width={35} />
                      <Tooltip contentStyle={{ fontSize:11, borderRadius:6 }} labelFormatter={v => new Date(v).toTimeString().slice(0,8)} />
                      <Area type="monotone" dataKey="benign" stackId="1" fill={T.greenLight} stroke={T.green} fillOpacity={0.5} />
                      <Area type="monotone" dataKey="attack_suricata_only" stackId="1" fill={T.amberBg} stroke={T.amber} fillOpacity={0.6} />
                      <Area type="monotone" dataKey="attack_ml_only" stackId="1" fill={T.blueBg} stroke={T.blue} fillOpacity={0.6} />
                      <Area type="monotone" dataKey="attack_both" stackId="1" fill={T.redLight} stroke={T.red} fillOpacity={0.7} />
                    </AreaChart>
                  </ResponsiveContainer>
                </Card>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                <Card title="Protocol Breakdown" sub="Flows per protocol">
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={protoData} margin={{ top:5,right:10,left:0,bottom:0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={T.borderLight} />
                      <XAxis dataKey="name" tick={{ fontSize:10, fill:T.textSec }} />
                      <YAxis tick={{ fontSize:10, fill:T.textMut }} width={40} />
                      <Tooltip contentStyle={{ fontSize:11, borderRadius:6 }} />
                      <Bar dataKey="count" fill={T.accent} radius={[4,4,0,0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </Card>

                <Card title="Cumulative Attacks" sub="Running total over session">
                  <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={timeData.map((d,i) => ({ ...d, cumAtk: timeData.slice(0,i+1).reduce((a,b)=>a+b.attack_suricata_only+b.attack_ml_only+b.attack_both,0) }))} margin={{ top:5,right:10,left:0,bottom:0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={T.borderLight} />
                      <XAxis dataKey="t" tickFormatter={v => new Date(v).toTimeString().slice(3,8)} tick={{ fontSize:10, fill:T.textMut }} />
                      <YAxis tick={{ fontSize:10, fill:T.textMut }} width={40} />
                      <Tooltip contentStyle={{ fontSize:11, borderRadius:6 }} labelFormatter={v => new Date(v).toTimeString().slice(0,8)} />
                      <Area type="monotone" dataKey="cumAtk" fill={T.redLight} stroke={T.red} fillOpacity={0.4} name="Cumulative Attacks" />
                    </AreaChart>
                  </ResponsiveContainer>
                </Card>
              </div>
            </div>
          )}

          {/* ── TAB: ATTRIBUTION ── */}
          {activeTab === "attribution" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="Top Suricata Signatures" sub="By frequency">
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={sigData} layout="vertical" margin={{ top:5,right:10,left:10,bottom:0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={T.borderLight} />
                      <XAxis type="number" tick={{ fontSize:10, fill:T.textMut }} />
                      <YAxis type="category" dataKey="name" tick={{ fontSize:9, fill:T.textSec }} width={160} />
                      <Tooltip contentStyle={{ fontSize:11, borderRadius:6 }} />
                      <Bar dataKey="count" fill={T.amber} radius={[0,4,4,0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </Card>

                <Card title="Top Attacker IPs" sub="By confirmed attack count">
                  <AttackerTable alerts={alerts} />
                </Card>
              </div>

              <Card title="Attack Type Distribution" sub="Breakdown of attack categories seen in this session">
                <AttackTypeTable alerts={alerts} />
              </Card>
            </div>
          )}

          {/* ── TAB: MODEL INSIGHT ── */}
          {activeTab === "model" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="ML Probability Scatter" sub={`Threshold at ${mlThreshold.toFixed(2)}`}>
                  <div style={{ height:240, position:"relative" }}>
                    <div style={{ position:"absolute", top:0, left:40, right:0, bottom:25, overflow:"hidden" }}>
                      {mlProbaHistory.slice(-200).map((pt,i) => {
                        const x = (i/200)*100;
                        const y = (1-pt.p)*100;
                        return <div key={i} style={{ position:"absolute", left:`${x}%`, top:`${y}%`, width:4, height:4, borderRadius:"50%", background:verdictColor(pt.v), opacity:0.6 }} />;
                      })}
                      <div style={{ position:"absolute", left:0, right:0, top:`${(1-mlThreshold)*100}%`, height:1, background:T.amber, borderTop:"1px dashed" }} />
                      <div style={{ position:"absolute", left:4, top:`${(1-mlThreshold)*100-14}%`, fontSize:9, color:T.amber, fontWeight:600 }}>threshold={mlThreshold}</div>
                    </div>
                    <div style={{ position:"absolute", left:0, top:0, bottom:25, width:35, display:"flex", flexDirection:"column", justifyContent:"space-between", fontSize:9, color:T.textMut, textAlign:"right", paddingRight:4 }}>
                      <span>1.0</span><span>0.5</span><span>0.0</span>
                    </div>
                    <div style={{ position:"absolute", bottom:0, left:40, right:0, fontSize:9, color:T.textMut, textAlign:"center" }}>Recent 200 flows → time</div>
                  </div>
                </Card>

                <Card title="Engine Agreement Matrix" sub="Suricata vs ML classification">
                  <div style={{ display:"grid", gridTemplateColumns:"auto 1fr 1fr", gridTemplateRows:"auto 1fr 1fr", gap:2, padding:16 }}>
                    <div />
                    <div style={{ textAlign:"center", fontSize:11, fontWeight:600, color:T.textSec, padding:8 }}>ML: Benign</div>
                    <div style={{ textAlign:"center", fontSize:11, fontWeight:600, color:T.textSec, padding:8 }}>ML: Attack</div>
                    <div style={{ fontSize:11, fontWeight:600, color:T.textSec, padding:8, display:"flex", alignItems:"center" }}>Suricata: Benign</div>
                    <MatrixCell value={matrixData.benBen} total={stats.total} color={T.greenBg} textColor={T.green} />
                    <MatrixCell value={matrixData.benAtk} total={stats.total} color={T.blueBg} textColor={T.blue} />
                    <div style={{ fontSize:11, fontWeight:600, color:T.textSec, padding:8, display:"flex", alignItems:"center" }}>Suricata: Alert</div>
                    <MatrixCell value={matrixData.atkBen} total={stats.total} color={T.amberBg} textColor={T.amber} />
                    <MatrixCell value={matrixData.atkAtk} total={stats.total} color={T.redBg} textColor={T.red} />
                  </div>
                </Card>
              </div>

              <Card title="ML Probability Distribution Over Time" sub="Color coded by verdict class">
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timeData} margin={{ top:5,right:10,left:0,bottom:0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={T.borderLight} />
                    <XAxis dataKey="t" tickFormatter={v => new Date(v).toTimeString().slice(3,8)} tick={{ fontSize:10, fill:T.textMut }} />
                    <YAxis tick={{ fontSize:10, fill:T.textMut }} width={35} />
                    <Tooltip contentStyle={{ fontSize:11, borderRadius:6 }} labelFormatter={v => new Date(v).toTimeString().slice(0,8)} />
                    <Area type="monotone" dataKey="total" fill={T.accentLight} stroke={T.accent} fillOpacity={0.3} name="Total Flows" />
                    <Area type="monotone" dataKey="attack_both" fill={T.redLight} stroke={T.red} fillOpacity={0.5} name="Both Engines" />
                  </AreaChart>
                </ResponsiveContainer>
              </Card>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes fadeIn { from { opacity:0; transform:translateY(-2px); } to { opacity:1; transform:translateY(0); } }
        input[type="range"] { -webkit-appearance:none; height:4px; border-radius:2px; background:${T.border}; outline:none; }
        input[type="range"]::-webkit-slider-thumb { -webkit-appearance:none; width:14px; height:14px; border-radius:50%; background:${T.accent}; cursor:pointer; border:2px solid #fff; box-shadow:0 1px 3px rgba(0,0,0,0.2); }
        ::-webkit-scrollbar { width:5px; } ::-webkit-scrollbar-track { background:transparent; } ::-webkit-scrollbar-thumb { background:${T.border}; border-radius:3px; }
      `}</style>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   SUB-COMPONENTS
   ═══════════════════════════════════════════════════════════════ */
function SidebarControl({ label, value, children }) {
  return (
    <div style={{ marginBottom:14 }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
        <span style={{ fontSize:11, color:T.textSec }}>{label}</span>
        <span style={{ fontSize:11, fontWeight:600, color:T.accent, fontFamily:"'IBM Plex Mono',monospace" }}>{value}</span>
      </div>
      {children}
    </div>
  );
}

function MetricCard({ label, value, accent, sub }) {
  return (
    <div style={{ background:T.surface, border:`1px solid ${T.border}`, borderRadius:8, padding:"12px 14px", borderTop: accent ? `3px solid ${accent}` : `3px solid ${T.border}` }}>
      <div style={{ fontSize:9.5, color:T.textMut, textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:4 }}>{label}</div>
      <div style={{ fontSize:20, fontWeight:700, color: accent || T.text, fontFamily:"'IBM Plex Mono','Tabular Nums',monospace" }}>{value}</div>
      {sub && <div style={{ fontSize:10, color: accent || T.textMut, marginTop:2 }}>{sub}</div>}
    </div>
  );
}

function Card({ title, sub, accent, children }) {
  return (
    <div style={{ background:T.surface, border:`1px solid ${T.border}`, borderRadius:10, padding:"14px 16px", borderLeft: accent ? `3px solid ${accent}` : undefined }}>
      <div style={{ marginBottom:10 }}>
        <div style={{ fontSize:13, fontWeight:600 }}>{title}</div>
        {sub && <div style={{ fontSize:10.5, color:T.textMut }}>{sub}</div>}
      </div>
      {children}
    </div>
  );
}

function StatLine({ label, value, color }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, marginBottom:3 }}>
      <span style={{ color:T.textMut }}>{label}</span>
      <span style={{ fontWeight:600, fontFamily:"'IBM Plex Mono',monospace", color: color || T.text }}>{value}</span>
    </div>
  );
}

function MatrixCell({ value, total, color, textColor }) {
  const pct = total > 0 ? (value/total*100).toFixed(1) : "0.0";
  return (
    <div style={{ background:color, borderRadius:8, padding:16, textAlign:"center", minHeight:70, display:"flex", flexDirection:"column", justifyContent:"center" }}>
      <div style={{ fontSize:22, fontWeight:700, color:textColor, fontFamily:"'IBM Plex Mono',monospace" }}>{value.toLocaleString()}</div>
      <div style={{ fontSize:10, color:textColor, opacity:0.7 }}>{pct}%</div>
    </div>
  );
}

function AttackerTable({ alerts }) {
  const ipCounts = {};
  alerts.forEach(a => { ipCounts[a.srcIp] = (ipCounts[a.srcIp]||0)+1; });
  const top = Object.entries(ipCounts).sort((a,b) => b[1]-a[1]).slice(0,10);
  return (
    <div style={{ maxHeight:240, overflowY:"auto" }}>
      <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
        <thead><tr style={{ borderBottom:`1px solid ${T.border}` }}>
          <th style={{ textAlign:"left", padding:"6px 8px", color:T.textMut, fontSize:10, fontWeight:600, textTransform:"uppercase" }}>Source IP</th>
          <th style={{ textAlign:"right", padding:"6px 8px", color:T.textMut, fontSize:10, fontWeight:600, textTransform:"uppercase" }}>Attacks</th>
          <th style={{ textAlign:"right", padding:"6px 8px", color:T.textMut, fontSize:10, fontWeight:600, textTransform:"uppercase" }}>Share</th>
        </tr></thead>
        <tbody>
          {top.map(([ip,count]) => (
            <tr key={ip} style={{ borderBottom:`1px solid ${T.borderLight}` }}>
              <td style={{ padding:"5px 8px", fontFamily:"'IBM Plex Mono',monospace", fontWeight:500 }}>{ip}</td>
              <td style={{ padding:"5px 8px", textAlign:"right", fontWeight:600, color:T.red }}>{count}</td>
              <td style={{ padding:"5px 8px", textAlign:"right", color:T.textMut }}>{alerts.length > 0 ? (count/alerts.length*100).toFixed(1) : 0}%</td>
            </tr>
          ))}
        </tbody>
      </table>
      {top.length === 0 && <div style={{ padding:16, color:T.textMut, fontSize:12, textAlign:"center" }}>No attacks recorded yet</div>}
    </div>
  );
}

function AttackTypeTable({ alerts }) {
  const typeCounts = {};
  alerts.forEach(a => { if(a.attackName) typeCounts[a.attackName] = (typeCounts[a.attackName]||0)+1; });
  const types = Object.entries(typeCounts).sort((a,b) => b[1]-a[1]);
  const max = types.length > 0 ? types[0][1] : 1;
  return (
    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))", gap:10, marginTop:8 }}>
      {types.map(([name,count]) => (
        <div key={name} style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 12px", background:T.surfaceAlt, borderRadius:6, border:`1px solid ${T.borderLight}` }}>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:12, fontWeight:600 }}>{name}</div>
            <div style={{ height:4, background:T.border, borderRadius:2, marginTop:4 }}>
              <div style={{ height:4, background:T.red, borderRadius:2, width:`${(count/max)*100}%`, transition:"width 0.5s" }} />
            </div>
          </div>
          <div style={{ fontSize:16, fontWeight:700, color:T.red, fontFamily:"'IBM Plex Mono',monospace", minWidth:40, textAlign:"right" }}>{count}</div>
        </div>
      ))}
      {types.length === 0 && <div style={{ padding:16, color:T.textMut, fontSize:12 }}>No attack types recorded yet</div>}
    </div>
  );
}
