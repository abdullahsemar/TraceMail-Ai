import React, { useEffect, useState } from 'react';
import { Activity, Search, ShieldAlert, Radio } from 'lucide-react';
import { fetchEmails } from '../services/api';
import { Link } from 'react-router-dom';

export default function LiveMonitor() {
  const [emails, setEmails] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    fetchEmails(100).then(setEmails).catch(console.error);

    // Setup SSE connection
    const eventSource = new EventSource('http://localhost:8000/api/events/stream');
    eventSource.onopen = () => setConnected(true);
    eventSource.onerror = () => setConnected(false);

    eventSource.addEventListener('EMAIL_PROCESSED', (e) => {
      const data = JSON.parse(e.data);
      setEmails(prev => [data, ...prev]);
    });

    return () => eventSource.close();
  }, []);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            Live Inbound Mail Monitor
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Near-realtime stream of all emails received, screened, and analyzed by TraceMail AI.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className={`badge ${connected ? 'badge-safe' : 'badge-warn'}`}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: connected ? 'var(--status-safe)' : 'var(--status-warn)' }}></span>
            <span>{connected ? 'SSE STREAM LIVE' : 'RECONNECTING'}</span>
          </span>
        </div>
      </div>

      <div className="glass-panel">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>MSG ID</th>
              <th>Source</th>
              <th>Sender</th>
              <th>Subject</th>
              <th>Classification</th>
              <th>Risk Score</th>
              <th>Decision</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {emails.map((e) => (
              <tr key={e.id}>
                <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                  {e.gateway_message_id}
                </td>
                <td>
                  <span className="badge badge-safe" style={{ fontSize: '0.65rem' }}>
                    {e.source || 'SMTP_GATEWAY'}
                  </span>
                </td>
                <td>{e.mail_from || e.sender}</td>
                <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {e.subject}
                </td>
                <td className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                  {e.threat_classification || e.classification}
                </td>
                <td>
                  <span className={`badge badge-${(e.risk_severity || e.severity || 'safe').toLowerCase()}`}>
                    {Math.round(e.final_risk_score || e.risk_score || 0)} / 100
                  </span>
                </td>
                <td>
                  <span className="font-mono" style={{ fontSize: '0.75rem', color: (e.action_taken || '').includes('QUARANTINE') ? 'var(--status-critical)' : 'var(--status-safe)' }}>
                    {e.action_taken}
                  </span>
                </td>
                <td>
                  <Link to={`/investigations?emailId=${e.id}`} className="btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                    Inspect
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
