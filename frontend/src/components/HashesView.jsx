import React, { useState } from 'react';
import { Key, Users, Search, AlertTriangle, ShieldCheck, Copy, Check } from 'lucide-react';

export default function HashesView({ hashesData, reuseData, onRefresh }) {
  const [activeTab, setActiveTab] = useState('reuse'); // 'reuse' or 'all'
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [copiedFp, setCopiedFp] = useState(null);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedFp(text);
    setTimeout(() => setCopiedFp(null), 2000);
  };

  const records = hashesData?.records || [];
  const clusters = reuseData?.clusters || [];

  const filteredRecords = records.filter(r => {
    const matchesSearch = 
      r.username.toLowerCase().includes(search.toLowerCase()) ||
      r.machine.toLowerCase().includes(search.toLowerCase()) ||
      r.hash_value.toLowerCase().includes(search.toLowerCase()) ||
      r.hash_fingerprint.toLowerCase().includes(search.toLowerCase());
    const matchesRisk = riskFilter === 'ALL' || r.risk_level === riskFilter;
    return matchesSearch && matchesRisk;
  });

  return (
    <div>
      {/* View Switcher Tabs */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
        <button 
          className={`btn ${activeTab === 'reuse' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('reuse')}
        >
          <Users size={16} /> Credential Reuse Matrix ({clusters.length} Clusters)
        </button>
        <button 
          className={`btn ${activeTab === 'all' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('all')}
        >
          <Key size={16} /> All Imported Hashes ({records.length})
        </button>
      </div>

      {activeTab === 'reuse' ? (
        /* Tab 1: Credential Reuse Matrix */
        <div>
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div className="panel-title" style={{ marginBottom: "8px" }}>
              <Users size={18} color="var(--accent-cyan)" />
              Cross-Account Hash Collision & Reuse Analysis
            </div>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
              Identifies instances where identical password hashes are shared across multiple user accounts and hosts.
              Sharing hashes across privileged accounts (e.g., Domain Admin) and regular endpoints enables <strong>Pass-the-Hash (PtH)</strong> lateral movement.
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "16px" }}>
            {clusters.map((cluster, idx) => (
              <div 
                key={idx} 
                className="panel"
                style={{
                  borderTop: cluster.risk_level === 'CRITICAL' ? "4px solid var(--sev-critical)" : "4px solid var(--sev-high)"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
                  <div>
                    <span className={`badge badge-${cluster.risk_level}`}>
                      {cluster.risk_level} RISK
                    </span>
                    {cluster.has_privileged_account && (
                      <span className="badge badge-CRITICAL" style={{ marginLeft: "8px" }}>
                        ADMIN ACCOUNT AFFECTED
                      </span>
                    )}
                  </div>
                  <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    {cluster.affected_count} Accounts
                  </span>
                </div>

                <div style={{ marginBottom: "14px" }}>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>
                    SHA-256 Fingerprint:
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px" }}>
                    <code className="mono-tag" style={{ color: "var(--accent-cyan)", fontSize: "11px", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {cluster.hash_fingerprint}
                    </code>
                    <button 
                      onClick={() => copyToClipboard(cluster.hash_fingerprint)}
                      style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
                      title="Copy SHA-256 Fingerprint"
                    >
                      {copiedFp === cluster.hash_fingerprint ? <Check size={14} color="var(--sev-low)" /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>

                <div style={{ marginBottom: "12px" }}>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                    Affected Accounts:
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {cluster.affected_accounts.map((acc, aIdx) => (
                      <span 
                        key={aIdx} 
                        style={{
                          background: acc.toLowerCase().includes('admin') ? "var(--sev-critical-bg)" : "rgba(255,255,255,0.06)",
                          color: acc.toLowerCase().includes('admin') ? "var(--sev-critical)" : "#fff",
                          border: acc.toLowerCase().includes('admin') ? "1px solid rgba(239, 68, 68, 0.4)" : "1px solid var(--border-subtle)",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontSize: "12px",
                          fontWeight: "600"
                        }}
                      >
                        {acc}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ fontSize: "12px", color: "var(--text-secondary)", borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: "10px" }}>
                  <div><strong>Observed Hosts:</strong> {cluster.machines.join(', ')}</div>
                  {cluster.known_weak_note && (
                    <div style={{ color: "var(--sev-high)", marginTop: "4px" }}>
                      ⚠️ Weak Baseline Hash: {cluster.known_weak_note}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        /* Tab 2: All Hashes Table */
        <div className="panel">
          <div className="filter-bar">
            <input 
              type="text" 
              placeholder="Search user, machine, or hash..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="search-input"
            />

            <select 
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="select-input"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Only</option>
              <option value="MEDIUM">Medium Only</option>
              <option value="LOW">Low Only</option>
            </select>

            <span style={{ fontSize: "12px", color: "var(--text-muted)", marginLeft: "auto" }}>
              Showing {filteredRecords.length} of {records.length} records
            </span>
          </div>

          <div className="table-responsive">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Machine / Source</th>
                  <th>Hash Type</th>
                  <th>Masked Hash (Synthetic)</th>
                  <th>SHA-256 Fingerprint</th>
                  <th>Risk Score</th>
                  <th>Level</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map((r) => (
                  <tr key={r.id}>
                    <td><strong>{r.username}</strong></td>
                    <td>
                      <div>{r.machine}</div>
                      <span style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>{r.source}</span>
                    </td>
                    <td><span className="mono-tag">{r.hash_type}</span></td>
                    <td>
                      <code className="mono-tag" style={{ color: "#cbd5e1" }}>
                        {r.hash_value ? `${r.hash_value.slice(0, 6)}...${r.hash_value.slice(-6)}` : "—"}
                      </code>
                    </td>
                    <td>
                      <code className="mono-tag" style={{ color: "var(--accent-cyan)", fontSize: "10.5px" }}>
                        {r.hash_fingerprint ? `${r.hash_fingerprint.slice(0, 12)}...` : "—"}
                      </code>
                    </td>
                    <td style={{ fontWeight: "700" }}>{r.risk_score} / 100</td>
                    <td>
                      <span className={`badge badge-${r.risk_level}`}>
                        {r.risk_level}
                      </span>
                    </td>
                    <td style={{ fontSize: "11.5px", color: "var(--text-secondary)", maxWidth: "240px" }}>
                      {r.notes}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
