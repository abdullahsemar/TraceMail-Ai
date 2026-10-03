import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  Mail, 
  ClipboardCheck, 
  AlertTriangle, 
  Search, 
  Activity, 
  Globe, 
  Radio, 
  CheckCircle2,
  ExternalLink
} from 'lucide-react';
import { fetchStats, fetchEmails } from '../services/api';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentEmails, setRecentEmails] = useState([]);

  const loadData = async () => {
    try {
      const [s, e] = await Promise.all([
        fetchStats(), 
        fetchEmails({ page: 1, pageSize: 10 })
      ]);
      setStats(s);
      setRecentEmails(e?.items || (Array.isArray(e) ? e : []));
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  const getActionBadgeClass = (action) => {
    switch ((action || '').toUpperCase()) {
      case 'FLAG_AND_ALERT': return 'badge-critical';
      case 'FLAG': return 'badge-warn';
      case 'ALLOW': return 'badge-safe';
      default: return 'badge-safe';
    }
  };

  return (
    <div>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            SOC Threat Intelligence & Gateway Monitor
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Research-Grounded Pre-Delivery SMTP Proxy & Retrospective Mailbox Forensics
          </p>
        </div>

        {/* Live Operational Ingestion Status Badge */}
        <div className="glass-panel" style={{ padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--accent-green)', display: 'inline-block', boxShadow: '0 0 8px var(--accent-green)' }}></span>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
              PIPELINE ACTIVE
            </span>
          </div>
          <span style={{ color: 'var(--border-color)' }}>|</span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
            PORT {stats?.gateway_port || 1025} (SMTP PROXY)
          </span>
        </div>
      </div>

      {/* KPI Metrics Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '1.25rem',
        marginBottom: '2rem'
      }}>
        <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '10px',
            backgroundColor: 'rgba(0, 242, 254, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Mail size={22} color="var(--accent-cyan)" />
          </div>
          <div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800 }}>{stats?.total_emails ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Emails Screened</div>
          </div>
        </div>

        <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '10px',
            backgroundColor: 'var(--status-critical-bg)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <ShieldAlert size={22} color="var(--status-critical)" />
          </div>
          <div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--status-critical)' }}>{stats?.total_threats ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threats Detected</div>
          </div>
        </div>

        <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '10px',
            backgroundColor: 'var(--status-warn-bg)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <ClipboardCheck size={22} color="var(--status-warn)" />
          </div>
          <div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--status-warn)' }}>{stats?.flagged_for_review ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Flagged For Review</div>
          </div>
        </div>

        <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '10px',
            backgroundColor: 'rgba(139, 92, 246, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Search size={22} color="var(--accent-purple)" />
          </div>
          <div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--accent-purple)' }}>{stats?.active_cases ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Cases</div>
          </div>
        </div>
      </div>

      {/* Threat Classification & Ingestion Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="glass-panel">
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} color="var(--accent-cyan)" />
            <span>Threat Taxonomy Breakdown (Final Verdicts)</span>
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem' }}>
            {stats?.classifications && Object.entries(stats.classifications).map(([key, val]) => (
              <div key={key} style={{
                padding: '0.75rem',
                backgroundColor: 'rgba(15, 21, 35, 0.6)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)'
              }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '0.2rem' }}>
                  {key.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: '1.25rem', fontWeight: 700, color: val > 0 ? (key === 'LEGITIMATE' ? 'var(--status-safe)' : (key === 'SUSPICIOUS_ANOMALY' ? 'var(--status-warn)' : 'var(--status-critical)')) : 'var(--text-muted)' }}>
                  {val}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Dual-Mode Architecture Card */}
        <div className="glass-panel">
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Globe size={18} color="var(--accent-blue)" />
            <span>Dual-Mode Ingestion Architecture</span>
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8rem' }}>
            <div style={{
              padding: '0.75rem',
              backgroundColor: 'rgba(0, 242, 254, 0.05)',
              border: '1px solid rgba(0, 242, 254, 0.2)',
              borderRadius: 'var(--radius-sm)'
            }}>
              <div style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '0.2rem' }}>
                Mode A: Pre-Delivery SMTP Proxy (Port 1025)
              </div>
              <p style={{ color: 'var(--text-secondary)' }}>
                Real-time stream evaluation. Injects X-TraceMail warning headers and forwards to destination MTA.
              </p>
            </div>

            <div style={{
              padding: '0.75rem',
              backgroundColor: 'rgba(139, 92, 246, 0.05)',
              border: '1px solid rgba(139, 92, 246, 0.2)',
              borderRadius: 'var(--radius-sm)'
            }}>
              <div style={{ fontWeight: 700, color: 'var(--accent-purple)', marginBottom: '0.2rem' }}>
                Mode B: Retrospective Ingestion (Gmail / API / EML)
              </div>
              <p style={{ color: 'var(--text-secondary)' }}>
                Retrospective mailbox analysis feeding the unified organizational behavioral intelligence baseline.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Live Stream Table */}
      <div className="glass-panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} color="var(--status-safe)" />
            <span>Recent Inbound Email Stream</span>
          </h2>
          <Link to="/inbox" style={{ color: 'var(--accent-cyan)', fontSize: '0.8rem', textDecoration: 'none', fontWeight: 600 }}>
            Open Security Inbox &rarr;
          </Link>
        </div>

        {recentEmails.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
            No emails processed yet. Send SMTP traffic to port 1025 or synchronize mailbox in Mail Connectors.
          </div>
        ) : (
          <table className="cyber-table">
            <thead>
              <tr>
                <th>MSG ID</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Threat Class</th>
                <th>Risk Score</th>
                <th>Action</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {recentEmails.map((em) => (
                <tr key={em.id}>
                  <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                    {em.gateway_message_id}
                  </td>
                  <td>{em.mail_from}</td>
                  <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {em.subject}
                  </td>
                  <td>
                    <span className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                      {em.threat_classification}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${em.risk_severity.toLowerCase()}`}>
                      {Math.round(em.risk_score)} / 100
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${getActionBadgeClass(em.action_taken)}`} style={{ fontSize: '0.7rem' }}>
                      {em.action_taken}
                    </span>
                  </td>
                  <td>
                    <Link to={`/investigations?emailId=${em.id}`} className="btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                      Inspect
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
