import React from 'react';
import { 
  ShieldAlert, 
  Layers, 
  Key, 
  AlertTriangle, 
  Activity, 
  Clock, 
  FileText, 
  Flame, 
  CheckCircle,
  ExternalLink,
  Play
} from 'lucide-react';

export default function DashboardView({ data, mitreData, onNavigate, onTriggerAnalysis }) {
  const summary = data?.summary || {};
  const sevDist = data?.severity_distribution || {};
  const tactics = data?.mitre_tactics || {};
  const recent = data?.recent_activity || [];

  return (
    <div>
      {/* Top Disclaimer Banner */}
      <div className="disclaimer-banner">
        <ShieldAlert size={18} color="var(--accent-cyan)" />
        <div>
          <strong>Controlled Security Lab Mode:</strong> {data?.disclaimer || "Defensive academic analysis using synthetic Windows telemetry."}
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card cyan">
          <div className="stat-header">
            <span className="stat-title">Hashes Analyzed</span>
            <Key size={18} className="stat-icon" />
          </div>
          <div className="stat-value">{summary.total_hashes || 0}</div>
          <div className="stat-subtext">{summary.unique_hashes || 0} unique · {summary.duplicate_hashes || 0} duplicates</div>
        </div>

        <div className="stat-card red">
          <div className="stat-header">
            <span className="stat-title">Critical IOC Alerts</span>
            <Flame size={18} className="stat-icon" color="var(--sev-critical)" />
          </div>
          <div className="stat-value" style={{ color: "var(--sev-critical)" }}>{summary.critical_iocs || 0}</div>
          <div className="stat-subtext">Immediate containment required</div>
        </div>

        <div className="stat-card orange">
          <div className="stat-header">
            <span className="stat-title">Total Active IOCs</span>
            <AlertTriangle size={18} className="stat-icon" color="var(--sev-high)" />
          </div>
          <div className="stat-value">{summary.total_iocs || 0}</div>
          <div className="stat-subtext">{summary.high_iocs || 0} High · {summary.critical_iocs || 0} Critical</div>
        </div>

        <div className="stat-card amber">
          <div className="stat-header">
            <span className="stat-title">High Risk Accounts</span>
            <ShieldAlert size={18} className="stat-icon" color="var(--sev-medium)" />
          </div>
          <div className="stat-value">{summary.high_risk_accounts || 0}</div>
          <div className="stat-subtext">Score ≥ 41 (Hygiene exposure)</div>
        </div>

        <div className="stat-card green">
          <div className="stat-header">
            <span className="stat-title">Auth Telemetry Events</span>
            <Activity size={18} className="stat-icon" color="var(--sev-low)" />
          </div>
          <div className="stat-value">{summary.total_auth_events || 0}</div>
          <div className="stat-subtext">{summary.failed_auth_events || 0} Logon Failures (4625)</div>
        </div>
      </div>

      {/* Main 2-Column Section */}
      <div className="dashboard-grid-2">
        {/* Left: MITRE ATT&CK SOC Matrix Overview */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Layers size={18} color="var(--accent-cyan)" />
              MITRE ATT&CK Matrix SOC Alignment
            </div>
            <button className="btn btn-secondary" onClick={() => onNavigate('iocs')}>
              View All IOCs
            </button>
          </div>

          <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginBottom: "16px" }}>
            Real-time correlation of Windows credential hygiene anomalies and authentication logs with adversary tactics.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {mitreData?.techniques?.map((tech) => (
              <div 
                key={tech.technique_id}
                style={{
                  background: tech.is_active ? "rgba(239, 68, 68, 0.08)" : "rgba(255, 255, 255, 0.02)",
                  border: tech.is_active ? "1px solid rgba(239, 68, 68, 0.3)" : "1px solid var(--border-subtle)",
                  borderRadius: "6px",
                  padding: "12px 16px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between"
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span className="mitre-badge">{tech.technique_id}</span>
                    <strong style={{ fontSize: "13.5px", color: "#fff" }}>{tech.technique_name}</strong>
                  </div>
                  <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "4px" }}>
                    Tactic: <span style={{ color: "var(--text-secondary)" }}>{tech.tactic}</span>
                  </div>
                </div>

                <div>
                  {tech.is_active ? (
                    <span className="badge badge-CRITICAL">
                      {tech.detection_count} Alert(s) Active
                    </span>
                  ) : (
                    <span className="badge badge-LOW">
                      Clean (Baseline)
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Severity Distribution & Quick Actions */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Severity Breakdown Panel */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <ShieldAlert size={18} color="var(--sev-high)" />
                IOC Severity Distribution
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                  <span style={{ color: "var(--sev-critical)", fontWeight: "600" }}>CRITICAL (Immediate Breach Risk)</span>
                  <strong>{sevDist.CRITICAL || 0}</strong>
                </div>
                <div style={{ background: "rgba(255,255,255,0.05)", height: "8px", borderRadius: "4px", overflow: "hidden" }}>
                  <div style={{ width: `${Math.min((sevDist.CRITICAL || 0) * 20, 100)}%`, height: "100%", background: "var(--sev-critical)" }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                  <span style={{ color: "var(--sev-high)", fontWeight: "600" }}>HIGH (Significant Vulnerability)</span>
                  <strong>{sevDist.HIGH || 0}</strong>
                </div>
                <div style={{ background: "rgba(255,255,255,0.05)", height: "8px", borderRadius: "4px", overflow: "hidden" }}>
                  <div style={{ width: `${Math.min((sevDist.HIGH || 0) * 20, 100)}%`, height: "100%", background: "var(--sev-high)" }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                  <span style={{ color: "var(--sev-medium)", fontWeight: "600" }}>MEDIUM (Hygiene Anomaly)</span>
                  <strong>{sevDist.MEDIUM || 0}</strong>
                </div>
                <div style={{ background: "rgba(255,255,255,0.05)", height: "8px", borderRadius: "4px", overflow: "hidden" }}>
                  <div style={{ width: `${Math.min((sevDist.MEDIUM || 0) * 20, 100)}%`, height: "100%", background: "var(--sev-medium)" }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                  <span style={{ color: "var(--sev-low)", fontWeight: "600" }}>LOW (Baseline Telemetry)</span>
                  <strong>{sevDist.LOW || 0}</strong>
                </div>
                <div style={{ background: "rgba(255,255,255,0.05)", height: "8px", borderRadius: "4px", overflow: "hidden" }}>
                  <div style={{ width: `${Math.min((sevDist.LOW || 0) * 20, 100)}%`, height: "100%", background: "var(--sev-low)" }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Engine Actions Panel */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <Play size={18} color="var(--accent-cyan)" />
                SOC Engine Control
              </div>
            </div>

            <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "14px" }}>
              Re-correlate hash collisions, brute-force event sequences, and out-of-hours logons.
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <button className="btn btn-primary" onClick={onTriggerAnalysis} style={{ justifyContent: "center" }}>
                <Play size={16} /> Run Full Security Analysis
              </button>
              <button className="btn btn-secondary" onClick={() => onNavigate('reports')} style={{ justifyContent: "center" }}>
                <FileText size={16} /> View Executive Assessment Report
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Incident Telemetry Feed */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <Clock size={18} color="var(--accent-cyan)" />
            Recent Security Telemetry & Detection Activity
          </div>
          <button className="btn btn-secondary" onClick={() => onNavigate('timeline')}>
            Full Timeline
          </button>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Subject / Target</th>
                <th>Origin / Host</th>
                <th>Severity</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((item, idx) => (
                <tr key={idx}>
                  <td className="mono-tag" style={{ color: "var(--accent-cyan)" }}>{item.time_display || item.timestamp}</td>
                  <td>
                    <span style={{ 
                      fontSize: "11px", 
                      fontWeight: "700",
                      color: item.type === "IOC_ALERT" ? "var(--sev-critical)" : "var(--text-secondary)"
                    }}>
                      {item.type}
                    </span>
                  </td>
                  <td><strong>{item.username}</strong></td>
                  <td className="mono-tag">{item.machine}</td>
                  <td>
                    <span className={`badge badge-${item.severity}`}>
                      {item.severity}
                    </span>
                  </td>
                  <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{item.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
