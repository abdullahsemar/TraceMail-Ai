import React, { useEffect, useState } from 'react';
import { FileCheck2, ShieldCheck, AlertOctagon, RefreshCw } from 'lucide-react';
import { fetchAuditEvents, verifyAuditChain } from '../services/api';

export default function AuditTrail() {
  const [events, setEvents] = useState([]);
  const [integrity, setIntegrity] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [evts, integ] = await Promise.all([fetchAuditEvents(), verifyAuditChain()]);
      setEvents(evts);
      setIntegrity(integ);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            Tamper-Evident Hash-Chained Audit Trail
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Cryptographically linked immutable log entries for all forensic events, preservations, and analyst actions.
          </p>
        </div>

        <button className="btn-secondary" onClick={loadData} disabled={loading}>
          <RefreshCw size={16} />
          <span>Verify & Refresh Chain</span>
        </button>
      </div>

      {/* Chain Status Card */}
      {integrity && (
        <div className="glass-panel" style={{
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderLeft: `4px solid ${integrity.status === 'VALID' ? 'var(--status-safe)' : 'var(--status-critical)'}`
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {integrity.status === 'VALID' ? (
              <ShieldCheck size={32} color="var(--status-safe)" />
            ) : (
              <AlertOctagon size={32} color="var(--status-critical)" />
            )}
            <div>
              <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>
                Audit Chain Integrity: <span style={{ color: integrity.status === 'VALID' ? 'var(--status-safe)' : 'var(--status-critical)' }}>{integrity.status}</span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                {integrity.status === 'VALID' 
                  ? `All ${integrity.total_records} audit entries verified with valid cryptographic SHA-256 parent links.`
                  : `Tampering detected at record index ${integrity.broken_at_index}: ${integrity.reason}`}
              </div>
            </div>
          </div>
          <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            LATEST HASH: {integrity.last_hash?.slice(0, 16)}...
          </div>
        </div>
      )}

      <div className="glass-panel">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Event Type</th>
              <th>Actor</th>
              <th>Target Resource</th>
              <th>Event SHA-256 Hash</th>
              <th>Prev Hash Pointer</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td>
                  <span className="badge badge-warn" style={{ fontSize: '0.65rem' }}>
                    {e.event_type}
                  </span>
                </td>
                <td className="font-mono" style={{ fontSize: '0.8rem' }}>{e.actor}</td>
                <td className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>{e.target_resource}</td>
                <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--status-safe)' }}>
                  {e.event_hash.slice(0, 16)}...
                </td>
                <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {e.prev_event_hash?.slice(0, 16)}...
                </td>
                <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {e.created_at}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
