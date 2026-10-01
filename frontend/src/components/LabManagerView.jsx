import React, { useState } from 'react';
import { Database, UploadCloud, RefreshCw, CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function LabManagerView({ onSeedLabData, onRefreshAll }) {
  const [hashUploading, setHashUploading] = useState(false);
  const [authUploading, setAuthUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState(null);

  const handleHashUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setHashUploading(true);
    setUploadMessage(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/hashes/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (res.ok) {
        setUploadMessage({ type: 'success', text: `Hash dataset imported successfully! Processed ${data.details?.total_records_processed || 0} records.` });
        onRefreshAll();
      } else {
        setUploadMessage({ type: 'error', text: data.detail || 'Upload failed.' });
      }
    } catch (err) {
      setUploadMessage({ type: 'error', text: err.message });
    } finally {
      setHashUploading(false);
      e.target.value = '';
    }
  };

  const handleAuthUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setAuthUploading(true);
    setUploadMessage(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/authentication/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (res.ok) {
        setUploadMessage({ type: 'success', text: `Authentication log imported successfully! Processed ${data.details?.total_events_imported || 0} events.` });
        onRefreshAll();
      } else {
        setUploadMessage({ type: 'error', text: data.detail || 'Upload failed.' });
      }
    } catch (err) {
      setUploadMessage({ type: 'error', text: err.message });
    } finally {
      setAuthUploading(false);
      e.target.value = '';
    }
  };

  return (
    <div>
      <div className="panel" style={{ marginBottom: "20px" }}>
        <div className="panel-title" style={{ marginBottom: "8px" }}>
          <Database size={18} color="var(--accent-cyan)" />
          Controlled Lab Dataset & Ingestion Manager
        </div>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
          Manage synthetic Windows NTLM hash records and Windows Security Event logs (Event IDs 4624/4625).
          You can load the standardized simulated lab datasets with one click or import custom CSV files exported from your authorized lab.
        </p>
      </div>

      {uploadMessage && (
        <div 
          style={{
            background: uploadMessage.type === 'success' ? 'var(--sev-low-bg)' : 'var(--sev-critical-bg)',
            border: uploadMessage.type === 'success' ? '1px solid var(--sev-low)' : '1px solid var(--sev-critical)',
            color: uploadMessage.type === 'success' ? 'var(--sev-low)' : 'var(--sev-critical)',
            padding: '12px 16px',
            borderRadius: '6px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '13px'
          }}
        >
          {uploadMessage.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{uploadMessage.text}</span>
        </div>
      )}

      {/* Action Cards */}
      <div className="dashboard-grid-2" style={{ marginBottom: "20px" }}>
        {/* Quick One-Click Lab Generator */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <RefreshCw size={18} color="var(--accent-cyan)" />
              Generate & Seed Pre-Built Lab Datasets
            </div>
          </div>

          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "16px" }}>
            Resets the SQLite database and populates 25+ synthetic Windows accounts with deliberate credential reuse clusters,
            known weak test hashes, and 48+ simulated authentication logs (including brute-force bursts and off-hours logons).
          </p>

          <button className="btn btn-primary" onClick={onSeedLabData} style={{ width: "100%", justifyContent: "center" }}>
            <RefreshCw size={16} /> Seed Standard Lab Datasets
          </button>
        </div>

        {/* Custom CSV Upload */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <UploadCloud size={18} color="var(--accent-cyan)" />
              Import Custom Lab Datasets
            </div>
          </div>

          <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginBottom: "14px" }}>
            Upload CSV files exported from your controlled lab virtual machines.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <div>
              <label style={{ display: "block", fontSize: "12px", color: "#fff", marginBottom: "4px", fontWeight: "600" }}>
                1. Upload Windows Hash Dataset (CSV)
              </label>
              <input 
                type="file" 
                accept=".csv"
                onChange={handleHashUpload}
                disabled={hashUploading}
                style={{ fontSize: "12px", color: "var(--text-secondary)" }}
              />
              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                Expected columns: <code>username, hash_type, hash, machine, source, timestamp</code>
              </div>
            </div>

            <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: "10px" }}>
              <label style={{ display: "block", fontSize: "12px", color: "#fff", marginBottom: "4px", fontWeight: "600" }}>
                2. Upload Authentication Event Logs (CSV)
              </label>
              <input 
                type="file" 
                accept=".csv"
                onChange={handleAuthUpload}
                disabled={authUploading}
                style={{ fontSize: "12px", color: "var(--text-secondary)" }}
              />
              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                Expected columns: <code>timestamp, username, source_machine, destination_machine, event_type, status, ip_address</code>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Ethical Guardrails & Course Compliance */}
      <div className="panel" style={{ borderLeft: "4px solid var(--accent-cyan)" }}>
        <div className="panel-title" style={{ marginBottom: "10px" }}>
          <ShieldCheck size={18} color="var(--accent-cyan)" />
          Ethical Hacking & Defensive Analysis Guidelines
        </div>
        <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "8px", fontSize: "13px", color: "var(--text-secondary)" }}>
          <li>✅ <strong>Defensive Blue-Team Scope:</strong> Strictly designed for detection engineering, SOC monitoring, and hygiene analysis.</li>
          <li>🚫 <strong>No Credential Extraction:</strong> No LSASS dumping, SAM dumping, or Mimikatz mechanisms are implemented.</li>
          <li>🚫 <strong>No Password Cracking:</strong> The engine analyzes structural properties (fingerprints, collisions, machine origins) without recovering plaintext.</li>
          <li>🔒 <strong>Cryptographic Fingerprinting:</strong> All hashes are tracked via SHA-256 fingerprints to prevent accidental credential leakage in tickets or alerts.</li>
        </ul>
      </div>
    </div>
  );
}
