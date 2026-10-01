import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Key, 
  AlertTriangle, 
  Activity, 
  Clock, 
  FileText, 
  Database, 
  RefreshCw,
  Layers,
  Terminal
} from 'lucide-react';

import DashboardView from './components/DashboardView';
import HashesView from './components/HashesView';
import IOCsView from './components/IOCsView';
import AuthenticationView from './components/AuthenticationView';
import TimelineView from './components/TimelineView';
import ReportsView from './components/ReportsView';
import LabManagerView from './components/LabManagerView';

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState(null);

  // Data states
  const [dashboardData, setDashboardData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [hashesData, setHashesData] = useState(null);
  const [reuseData, setReuseData] = useState(null);
  const [iocsData, setIocsData] = useState(null);
  const [authData, setAuthData] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [reportData, setReportData] = useState(null);

  const fetchAllData = async () => {
    try {
      setLoading(true);
      const [dashRes, mitreRes, hashesRes, reuseRes, iocsRes, authRes, timeRes, repRes] = await Promise.all([
        fetch('/api/dashboard').then(r => r.json()),
        fetch('/api/mitre-matrix').then(r => r.json()),
        fetch('/api/hashes?limit=200').then(r => r.json()),
        fetch('/api/hashes/reuse').then(r => r.json()),
        fetch('/api/iocs').then(r => r.json()),
        fetch('/api/authentication-events?limit=200').then(r => r.json()),
        fetch('/api/timeline').then(r => r.json()),
        fetch('/api/report').then(r => r.json())
      ]);

      setDashboardData(dashRes);
      setMitreData(mitreRes);
      setHashesData(hashesRes);
      setReuseData(reuseRes);
      setIocsData(iocsRes);
      setAuthData(authRes);
      setTimelineData(timeRes);
      setReportData(repRes);
    } catch (err) {
      console.error("Error loading SOC data:", err);
      showNotice('error', 'Failed to communicate with SOC backend: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const showNotice = (type, message) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  const handleTriggerAnalysis = async () => {
    try {
      const res = await fetch('/api/analyze', { method: 'POST' });
      const data = await res.json();
      showNotice('success', data.message || 'Analysis complete.');
      fetchAllData();
    } catch (err) {
      showNotice('error', err.message);
    }
  };

  const handleSeedLabData = async () => {
    try {
      const res = await fetch('/api/seed-lab-data', { method: 'POST' });
      const data = await res.json();
      showNotice('success', data.message || 'Lab data seeded.');
      fetchAllData();
    } catch (err) {
      showNotice('error', err.message);
    }
  };

  const handleUpdateIOCStatus = async (iocId, newStatus) => {
    try {
      const res = await fetch(`/api/iocs/${iocId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        showNotice('success', `Updated ${iocId} status to ${newStatus}`);
        // Update local state
        setIocsData(prev => ({
          ...prev,
          iocs: prev.iocs.map(ioc => ioc.ioc_id === iocId ? { ...ioc, status: newStatus } : ioc)
        }));
      }
    } catch (err) {
      showNotice('error', err.message);
    }
  };

  const criticalCount = dashboardData?.summary?.critical_iocs || 0;

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon-wrap">
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="brand-title">AegisSOC</div>
            <div className="brand-subtitle">Hash & IOC Defense</div>
          </div>
        </div>

        <ul className="nav-menu">
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'dashboard' ? 'active' : ''}`}
              onClick={() => setActivePage('dashboard')}
            >
              <Terminal size={17} />
              <span>SOC Dashboard</span>
            </button>
          </li>
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'hashes' ? 'active' : ''}`}
              onClick={() => setActivePage('hashes')}
            >
              <Key size={17} />
              <span>Hash Analysis</span>
            </button>
          </li>
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'iocs' ? 'active' : ''}`}
              onClick={() => setActivePage('iocs')}
            >
              <AlertTriangle size={17} />
              <span>IOC Detections</span>
              {criticalCount > 0 && (
                <span className="nav-badge critical">{criticalCount}</span>
              )}
            </button>
          </li>
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'authentication' ? 'active' : ''}`}
              onClick={() => setActivePage('authentication')}
            >
              <Activity size={17} />
              <span>Auth Telemetry</span>
            </button>
          </li>
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'timeline' ? 'active' : ''}`}
              onClick={() => setActivePage('timeline')}
            >
              <Clock size={17} />
              <span>Attack Timeline</span>
            </button>
          </li>
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'reports' ? 'active' : ''}`}
              onClick={() => setActivePage('reports')}
            >
              <FileText size={17} />
              <span>Security Reports</span>
            </button>
          </li>
          <li>
            <button 
              className={`nav-item-btn ${activePage === 'lab' ? 'active' : ''}`}
              onClick={() => setActivePage('lab')}
            >
              <Database size={17} />
              <span>Lab Datasets</span>
            </button>
          </li>
        </ul>

        <div className="sidebar-footer">
          <div className="status-pill">
            <div className="pulse-dot"></div>
            <span>SOC Engine Active</span>
          </div>
          <div style={{ marginTop: "4px" }}>Controlled Lab Environment</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Top Header */}
        <header className="top-header">
          <div>
            <h1 className="page-title">
              {activePage === 'dashboard' && 'Defensive Security Operations Center'}
              {activePage === 'hashes' && 'Windows Password Hash Hygiene & Reuse Matrix'}
              {activePage === 'iocs' && 'Indicators of Compromise (IOC) Incident Center'}
              {activePage === 'authentication' && 'Windows Authentication Telemetry Analysis'}
              {activePage === 'timeline' && 'Chronological Threat & Telemetry Timeline'}
              {activePage === 'reports' && 'Defensive Blue Team Security Assessment Report'}
              {activePage === 'lab' && 'Lab Data Management & Dataset Importer'}
            </h1>
            <p className="page-desc">
              {activePage === 'dashboard' && 'Real-time credential hygiene analysis, anomaly correlation, and MITRE ATT&CK alignment.'}
              {activePage === 'hashes' && 'Cryptographic fingerprinting, multi-account hash collisions, and risk modeling.'}
              {activePage === 'iocs' && 'Threat intelligence artifacts with mapped MITRE techniques and defensive playbooks.'}
              {activePage === 'authentication' && 'Windows Event ID 4624 (Logon Success) and 4625 (Logon Failure) pattern inspection.'}
              {activePage === 'timeline' && 'Chronological sequence of simulated adversary operations from password spray to lateral movement.'}
              {activePage === 'reports' && 'Executive summary, credential vulnerability statistics, and prioritized GPO remediation steps.'}
              {activePage === 'lab' && 'Generate synthetic lab samples or import custom CSV telemetry.'}
            </p>
          </div>

          <div className="header-actions">
            <button className="btn btn-secondary" onClick={fetchAllData} disabled={loading}>
              <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh Telemetry
            </button>
          </div>
        </header>

        {/* Global Notification Toast */}
        {notification && (
          <div 
            style={{
              padding: "10px 16px",
              borderRadius: "6px",
              marginBottom: "20px",
              background: notification.type === 'success' ? 'var(--sev-low-bg)' : 'var(--sev-critical-bg)',
              border: notification.type === 'success' ? '1px solid var(--sev-low)' : '1px solid var(--sev-critical)',
              color: notification.type === 'success' ? 'var(--sev-low)' : 'var(--sev-critical)',
              fontSize: "13px",
              fontWeight: "600"
            }}
          >
            {notification.message}
          </div>
        )}

        {/* View Switcher */}
        {loading && !dashboardData ? (
          <div style={{ textAlign: "center", padding: "60px", color: "var(--text-muted)" }}>
            <RefreshCw size={32} className="spin" style={{ marginBottom: "12px", color: "var(--accent-cyan)" }} />
            <div>Initializing Blue Team SOC Telemetry...</div>
          </div>
        ) : (
          <>
            {activePage === 'dashboard' && (
              <DashboardView 
                data={dashboardData} 
                mitreData={mitreData} 
                onNavigate={setActivePage} 
                onTriggerAnalysis={handleTriggerAnalysis}
              />
            )}

            {activePage === 'hashes' && (
              <HashesView 
                hashesData={hashesData} 
                reuseData={reuseData} 
                onRefresh={fetchAllData}
              />
            )}

            {activePage === 'iocs' && (
              <IOCsView 
                iocs={iocsData?.iocs} 
                onUpdateStatus={handleUpdateIOCStatus}
              />
            )}

            {activePage === 'authentication' && (
              <AuthenticationView 
                authData={authData} 
              />
            )}

            {activePage === 'timeline' && (
              <TimelineView 
                timelineData={timelineData} 
              />
            )}

            {activePage === 'reports' && (
              <ReportsView 
                reportData={reportData} 
              />
            )}

            {activePage === 'lab' && (
              <LabManagerView 
                onSeedLabData={handleSeedLabData}
                onRefreshAll={fetchAllData}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}
