import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Layers, BookOpen, CheckCircle2, X } from 'lucide-react';

export default function IOCsView({ iocs, onUpdateStatus }) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);

  const filteredIOCs = (iocs || []).filter(ioc => {
    const matchesSev = severityFilter === 'ALL' || ioc.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || ioc.status === statusFilter;
    return matchesSev && matchesStatus;
  });

  return (
    <div>
      {/* Filter Header */}
      <div className="filter-bar">
        <select 
          value={severityFilter} 
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="select-input"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical Only</option>
          <option value="HIGH">High Only</option>
          <option value="MEDIUM">Medium Only</option>
          <option value="LOW">Low Only</option>
        </select>

        <select 
          value={statusFilter} 
          onChange={(e) => setStatusFilter(e.target.value)}
          className="select-input"
        >
          <option value="ALL">All Triage Statuses</option>
          <option value="ACTIVE">Active Incidents</option>
          <option value="INVESTIGATING">Under Investigation</option>
          <option value="RESOLVED">Resolved / Remediated</option>
        </select>

        <span style={{ fontSize: "12px", color: "var(--text-muted)", marginLeft: "auto" }}>
          Showing {filteredIOCs.length} of {iocs?.length || 0} Indicators of Compromise
        </span>
      </div>

      {/* IOC Grid / Cards */}
      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        {filteredIOCs.map((ioc) => (
          <div 
            key={ioc.ioc_id}
            className="panel"
            style={{
              borderLeft: ioc.severity === 'CRITICAL' ? '4px solid var(--sev-critical)' :
                          ioc.severity === 'HIGH' ? '4px solid var(--sev-high)' :
                          ioc.severity === 'MEDIUM' ? '4px solid var(--sev-medium)' : '4px solid var(--sev-low)'
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "10px" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                  <span className="mono-tag" style={{ color: "#fff", fontWeight: "700" }}>{ioc.ioc_id}</span>
                  <span className={`badge badge-${ioc.severity}`}>{ioc.severity}</span>
                  <span className="mitre-badge">
                    <Layers size={12} /> {ioc.mitre_technique_id} · {ioc.mitre_tactic}
                  </span>
                </div>
                <h3 style={{ fontSize: "15px", color: "#fff", marginTop: "8px" }}>{ioc.description}</h3>
              </div>

              {/* Triage Status Dropdown */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>Triage Status:</span>
                <select 
                  value={ioc.status} 
                  onChange={(e) => onUpdateStatus(ioc.ioc_id, e.target.value)}
                  className="select-input"
                  style={{
                    fontWeight: "600",
                    color: ioc.status === 'RESOLVED' ? 'var(--sev-low)' :
                           ioc.status === 'INVESTIGATING' ? 'var(--sev-medium)' : 'var(--sev-critical)'
                  }}
                >
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>
            </div>

            {/* Evidence & Scope Details */}
            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: "6px", padding: "12px", marginTop: "12px", fontSize: "12.5px" }}>
              <div style={{ marginBottom: "6px" }}>
                <strong style={{ color: "var(--text-secondary)" }}>Target Account(s):</strong>{' '}
                <span style={{ color: "#fff" }}>{ioc.username || "System-wide"}</span>
                {ioc.machine && (
                  <span style={{ marginLeft: "14px" }}>
                    <strong style={{ color: "var(--text-secondary)" }}>Host Machine(s):</strong>{' '}
                    <span className="mono-tag">{ioc.machine}</span>
                  </span>
                )}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: "12px" }}>
                <strong style={{ color: "var(--text-secondary)" }}>Detection Evidence:</strong> {ioc.evidence}
              </div>
            </div>

            {/* Actions Footer */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "12px", paddingTop: "10px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
              <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                Detected: {ioc.timestamp}
              </span>
              <button 
                className="btn btn-secondary" 
                onClick={() => setSelectedPlaybook(ioc)}
                style={{ fontSize: "12px", padding: "4px 10px" }}
              >
                <BookOpen size={14} color="var(--accent-cyan)" /> View Defensive Remediation Playbook
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Defensive Playbook Modal */}
      {selectedPlaybook && (
        <div className="modal-overlay" onClick={() => setSelectedPlaybook(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <BookOpen size={18} color="var(--accent-cyan)" />
                <h3 style={{ fontSize: "16px", color: "#fff" }}>Blue Team Playbook: {selectedPlaybook.ioc_id}</h3>
              </div>
              <button 
                onClick={() => setSelectedPlaybook(null)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={20} />
              </button>
            </div>

            <div className="modal-body">
              <div style={{ marginBottom: "16px" }}>
                <span className="mitre-badge" style={{ fontSize: "12px", marginBottom: "6px" }}>
                  {selectedPlaybook.mitre_technique_id} — {selectedPlaybook.mitre_tactic}
                </span>
                <h4 style={{ color: "#fff", marginTop: "6px" }}>{selectedPlaybook.description}</h4>
              </div>

              <div style={{ marginBottom: "16px" }}>
                <h5 style={{ fontSize: "12px", color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "6px" }}>
                  Evidence Artifact:
                </h5>
                <pre style={{ background: "rgba(0,0,0,0.4)", padding: "10px", borderRadius: "6px", fontSize: "11.5px", color: "#cbd5e1", whiteSpace: "pre-wrap" }}>
                  {selectedPlaybook.evidence}
                </pre>
              </div>

              <div>
                <h5 style={{ fontSize: "12px", color: "var(--accent-cyan)", textTransform: "uppercase", marginBottom: "6px" }}>
                  Recommended Defensive Actions & Containment Steps:
                </h5>
                <pre style={{ background: "rgba(0, 229, 255, 0.05)", border: "1px solid rgba(0, 229, 255, 0.2)", padding: "14px", borderRadius: "6px", fontSize: "12.5px", color: "#f1f5f9", lineHeight: "1.6", whiteSpace: "pre-wrap", fontFamily: "var(--font-mono)" }}>
                  {selectedPlaybook.defensive_action}
                </pre>
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedPlaybook(null)}>
                Close Playbook
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
