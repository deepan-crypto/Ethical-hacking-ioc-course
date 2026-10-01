import React from 'react';
import { Clock, ShieldAlert, Activity, AlertOctagon } from 'lucide-react';

export default function TimelineView({ timelineData }) {
  const items = timelineData?.timeline || [];

  return (
    <div>
      <div className="panel" style={{ marginBottom: "20px" }}>
        <div className="panel-title" style={{ marginBottom: "8px" }}>
          <Clock size={18} color="var(--accent-cyan)" />
          Chronological Adversary & Telemetry Incident Timeline
        </div>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
          Sequence of observed security events from initial password spraying to brute-force bursts, 
          privileged off-hours logons, and cross-machine lateral movement.
        </p>
      </div>

      <div className="panel">
        <div className="timeline-container">
          {items.map((item, idx) => {
            const isAlert = item.type === 'IOC_ALERT';
            const sevClass = item.severity?.toLowerCase() || 'low';

            return (
              <div key={idx} className="timeline-node">
                <div className={`timeline-marker ${sevClass}`}>
                  {isAlert ? <AlertOctagon size={10} color={item.severity === 'CRITICAL' ? 'var(--sev-critical)' : 'var(--sev-high)'} /> : <div style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--accent-cyan)' }} />}
                </div>

                <div 
                  className="timeline-content"
                  style={{
                    borderLeft: isAlert ? (
                      item.severity === 'CRITICAL' ? '3px solid var(--sev-critical)' :
                      item.severity === 'HIGH' ? '3px solid var(--sev-high)' : '3px solid var(--sev-medium)'
                    ) : '1px solid var(--border-subtle)'
                  }}
                >
                  <div className="timeline-meta">
                    <span className="mono-tag" style={{ color: "var(--accent-cyan)", fontSize: "11px" }}>
                      {item.timestamp}
                    </span>
                    <span>·</span>
                    <span style={{ 
                      fontSize: "11px", 
                      fontWeight: "700",
                      color: isAlert ? "var(--sev-critical)" : "var(--text-secondary)"
                    }}>
                      {item.type}
                    </span>
                    {item.severity && (
                      <span className={`badge badge-${item.severity}`} style={{ fontSize: "10px", padding: "1px 6px" }}>
                        {item.severity}
                      </span>
                    )}
                    {item.mitre && (
                      <span className="mitre-badge" style={{ fontSize: "10px" }}>
                        {item.mitre}
                      </span>
                    )}
                  </div>

                  <h4 style={{ fontSize: "14px", color: "#fff", margin: "4px 0" }}>
                    {item.title}
                  </h4>

                  <p style={{ fontSize: "12.5px", color: "var(--text-secondary)" }}>
                    {item.details}
                  </p>

                  <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "6px" }}>
                    <strong>Subject:</strong> {item.username} | <strong>Host:</strong> <span className="mono-tag">{item.machine}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
