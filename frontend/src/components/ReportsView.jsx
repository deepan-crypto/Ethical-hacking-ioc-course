import React from 'react';
import { FileText, Download, Printer, Shield, CheckCircle, AlertTriangle } from 'lucide-react';

export default function ReportsView({ reportData }) {
  const meta = reportData?.report_metadata || {};
  const exec = reportData?.executive_summary || {};
  const hashes = reportData?.hash_analysis || {};
  const auth = reportData?.authentication_analysis || {};
  const iocs = reportData?.ioc_findings || [];
  const recs = reportData?.recommendations || [];

  const handleDownloadMarkdown = async () => {
    try {
      const res = await fetch('/api/report/markdown');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Windows_Password_Hash_Security_Report_${new Date().toISOString().split('T')[0]}.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Error downloading report: " + err.message);
    }
  };

  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Windows_Security_Assessment_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      {/* Header & Export Actions */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px", flexWrap: "wrap", gap: "10px" }}>
        <div>
          <h2 style={{ fontSize: "20px", color: "#fff" }}>Executive Security Assessment Report</h2>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            Classification: <strong style={{ color: "var(--accent-cyan)" }}>{meta.classification || "AUTHORIZED LAB AUDIT"}</strong> · Generated: {meta.generated_at}
          </span>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <button className="btn btn-secondary" onClick={() => window.print()}>
            <Printer size={16} /> Print Report
          </button>
          <button className="btn btn-secondary" onClick={handleDownloadJSON}>
            <Download size={16} /> Export JSON
          </button>
          <button className="btn btn-primary" onClick={handleDownloadMarkdown}>
            <Download size={16} /> Download Markdown (.md)
          </button>
        </div>
      </div>

      {/* 1. Executive Summary Panel */}
      <div className="panel" style={{ marginBottom: "20px" }}>
        <div className="panel-title" style={{ marginBottom: "14px" }}>
          <Shield size={18} color="var(--accent-cyan)" />
          1. Executive Summary & Exposure Posture
        </div>

        <div className="stats-grid" style={{ marginBottom: "16px" }}>
          <div className="stat-card cyan">
            <div className="stat-title">Hashes Analyzed</div>
            <div className="stat-value">{exec.total_hashes_analyzed || 0}</div>
          </div>
          <div className="stat-card red">
            <div className="stat-title">Critical IOCs</div>
            <div className="stat-value" style={{ color: "var(--sev-critical)" }}>{exec.critical_iocs || 0}</div>
          </div>
          <div className="stat-card orange">
            <div className="stat-title">High-Risk Findings</div>
            <div className="stat-value">{exec.high_risk_findings || 0}</div>
          </div>
          <div className="stat-card amber">
            <div className="stat-title">Affected Accounts</div>
            <div className="stat-value">{exec.total_affected_accounts || 0}</div>
          </div>
        </div>

        <p style={{ fontSize: "13px", color: "var(--text-secondary)", lineHeight: "1.6" }}>
          This assessment evaluated synthetic credential hashes and authentication event logs 
          from a controlled laboratory network. The detection engine identified <strong>{exec.total_iocs_detected || 0} Indicators of Compromise</strong>, 
          including credential reuse across domain administrative accounts, brute-force logon failure bursts, 
          and anomalous out-of-hours logons.
        </p>
      </div>

      {/* 2. Hash & Auth Findings */}
      <div className="dashboard-grid-2" style={{ marginBottom: "20px" }}>
        <div className="panel">
          <div className="panel-title" style={{ marginBottom: "12px" }}>
            2. Credential Hygiene Overview
          </div>
          <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "8px", fontSize: "13px" }}>
            <li>• Reused Credential Clusters: <strong>{hashes.reused_clusters_count || 0}</strong></li>
            <li>• Known Weak Lab Test Hashes: <strong>{hashes.weak_hashes_count || 0}</strong></li>
            <li>• Duplicate Hash Entries: <strong>{exec.duplicate_hashes || 0}</strong></li>
          </ul>
        </div>

        <div className="panel">
          <div className="panel-title" style={{ marginBottom: "12px" }}>
            3. Authentication Telemetry
          </div>
          <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "8px", fontSize: "13px" }}>
            <li>• Total Events Processed: <strong>{auth.total_events || 0}</strong></li>
            <li>• Successful Logons (4624): <strong>{auth.successful_logons || 0}</strong></li>
            <li>• Failed Logons (4625): <strong style={{ color: "var(--sev-critical)" }}>{auth.failed_logons || 0} ({auth.failure_rate_pct || 0}%)</strong></li>
            <li>• Anomalous/Suspicious Logons: <strong>{auth.suspicious_events || 0}</strong></li>
          </ul>
        </div>
      </div>

      {/* 4. Detailed IOC Table */}
      <div className="panel" style={{ marginBottom: "20px" }}>
        <div className="panel-title" style={{ marginBottom: "14px" }}>
          4. Indicators of Compromise (IOC) Findings
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>IOC ID</th>
                <th>Type</th>
                <th>Severity</th>
                <th>MITRE Technique</th>
                <th>Affected Subject</th>
                <th>Evidence / Details</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.ioc_id}>
                  <td className="mono-tag" style={{ color: "#fff", fontWeight: "700" }}>{ioc.ioc_id}</td>
                  <td><strong>{ioc.ioc_type}</strong></td>
                  <td>
                    <span className={`badge badge-${ioc.severity}`}>{ioc.severity}</span>
                  </td>
                  <td>
                    <span className="mitre-badge">{ioc.mitre_technique_id}</span>
                  </td>
                  <td>{ioc.username}</td>
                  <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{ioc.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 5. Prioritized Defensive Recommendations */}
      <div className="panel">
        <div className="panel-title" style={{ marginBottom: "14px" }}>
          5. Prioritized Blue-Team Defensive Recommendations
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          {recs.map((rec, idx) => (
            <div 
              key={idx}
              style={{
                background: "rgba(255,255,255,0.02)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "6px",
                padding: "14px 18px"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <strong style={{ fontSize: "14px", color: "#fff" }}>{idx + 1}. {rec.title}</strong>
                <span className={`badge badge-${rec.priority}`}>{rec.priority}</span>
              </div>
              <div style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginBottom: "6px" }}>
                <strong>Scope / Target:</strong> {rec.target}
              </div>
              <div style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginBottom: "6px" }}>
                <strong>Rationale:</strong> {rec.rationale}
              </div>
              <div style={{ fontSize: "12.5px", color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>
                <strong>Recommended Action:</strong> {rec.action}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
