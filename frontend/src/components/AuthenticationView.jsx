import React, { useState } from 'react';
import { Activity, ShieldAlert, CheckCircle, XCircle, Search, Filter } from 'lucide-react';

export default function AuthenticationView({ authData }) {
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [search, setSearch] = useState('');

  const events = authData?.events || [];

  const filteredEvents = events.filter(e => {
    const matchesStatus = statusFilter === 'ALL' || e.status === statusFilter;
    const matchesSuspicious = !suspiciousOnly || e.is_suspicious;
    const matchesSearch = 
      e.username.toLowerCase().includes(search.toLowerCase()) ||
      e.source_machine.toLowerCase().includes(search.toLowerCase()) ||
      e.destination_machine.toLowerCase().includes(search.toLowerCase()) ||
      e.ip_address.includes(search);
    return matchesStatus && matchesSuspicious && matchesSearch;
  });

  const total = events.length;
  const successCount = events.filter(e => e.status === 'SUCCESS').length;
  const failCount = events.filter(e => e.status === 'FAILURE').length;
  const suspCount = events.filter(e => e.is_suspicious).length;

  return (
    <div>
      {/* Telemetry Stat Cards */}
      <div className="stats-grid" style={{ marginBottom: "20px" }}>
        <div className="stat-card cyan">
          <div className="stat-header">
            <span className="stat-title">Total Logons</span>
            <Activity size={18} className="stat-icon" />
          </div>
          <div className="stat-value">{total}</div>
          <div className="stat-subtext">Windows 4624 & 4625 telemetry</div>
        </div>

        <div className="stat-card green">
          <div className="stat-header">
            <span className="stat-title">Logon Success (4624)</span>
            <CheckCircle size={18} className="stat-icon" color="var(--sev-low)" />
          </div>
          <div className="stat-value" style={{ color: "var(--sev-low)" }}>{successCount}</div>
          <div className="stat-subtext">{total > 0 ? ((successCount / total) * 100).toFixed(1) : 0}% success rate</div>
        </div>

        <div className="stat-card red">
          <div className="stat-header">
            <span className="stat-title">Logon Failure (4625)</span>
            <XCircle size={18} className="stat-icon" color="var(--sev-critical)" />
          </div>
          <div className="stat-value" style={{ color: "var(--sev-critical)" }}>{failCount}</div>
          <div className="stat-subtext">Brute-force & spraying candidates</div>
        </div>

        <div className="stat-card orange">
          <div className="stat-header">
            <span className="stat-title">Anomalous Events</span>
            <ShieldAlert size={18} className="stat-icon" color="var(--sev-high)" />
          </div>
          <div className="stat-value" style={{ color: "var(--sev-high)" }}>{suspCount}</div>
          <div className="stat-subtext">Off-hours or unauthorized hosts</div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="panel">
        <div className="filter-bar">
          <input 
            type="text" 
            placeholder="Search account, machine, or IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="search-input"
          />

          <select 
            value={statusFilter} 
            onChange={(e) => setStatusFilter(e.target.value)}
            className="select-input"
          >
            <option value="ALL">All Event Statuses</option>
            <option value="SUCCESS">Success Only (4624)</option>
            <option value="FAILURE">Failure Only (4625)</option>
          </select>

          <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", color: "#fff", cursor: "pointer" }}>
            <input 
              type="checkbox" 
              checked={suspiciousOnly} 
              onChange={(e) => setSuspiciousOnly(e.target.checked)} 
            />
            Suspicious Events Only
          </label>

          <span style={{ fontSize: "12px", color: "var(--text-muted)", marginLeft: "auto" }}>
            Showing {filteredEvents.length} of {total} events
          </span>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Account</th>
                <th>Event Code</th>
                <th>Status</th>
                <th>Source Machine</th>
                <th>Destination</th>
                <th>Source IP</th>
                <th>Anomaly Analysis</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((e) => (
                <tr key={e.id}>
                  <td className="mono-tag" style={{ color: "var(--accent-cyan)", fontSize: "11.5px" }}>{e.timestamp}</td>
                  <td><strong>{e.username}</strong></td>
                  <td><span className="mono-tag">{e.event_type}</span></td>
                  <td>
                    {e.status === 'SUCCESS' ? (
                      <span className="badge badge-LOW">SUCCESS</span>
                    ) : (
                      <span className="badge badge-CRITICAL">FAILURE</span>
                    )}
                  </td>
                  <td className="mono-tag">{e.source_machine}</td>
                  <td className="mono-tag">{e.destination_machine}</td>
                  <td className="mono-tag" style={{ color: "var(--accent-blue)" }}>{e.ip_address}</td>
                  <td style={{ fontSize: "12px" }}>
                    {e.is_suspicious ? (
                      <span style={{ color: "var(--sev-high)", fontWeight: "600" }}>
                        ⚠️ {e.anomaly_reason}
                      </span>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>Normal domain activity</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
