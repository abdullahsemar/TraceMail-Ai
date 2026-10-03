import React, { useEffect, useState } from 'react';
import { Lock, CheckCircle, XCircle, Search, AlertOctagon } from 'lucide-react';
import { fetchQuarantine, releaseQuarantine, blockQuarantine } from '../services/api';
import { Link } from 'react-router-dom';

export default function Quarantine() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  const loadData = async () => {
    try {
      const data = await fetchQuarantine();
      setItems(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRelease = async (emailId) => {
    setLoading(true);
    setMsg(null);
    try {
      const res = await releaseQuarantine(emailId, { analyst: 'SOC_ANALYST', notes: 'Manual quarantine release' });
      setMsg(`Released: ${res.message}`);
      loadData();
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleBlock = async (emailId) => {
    setLoading(true);
    setMsg(null);
    try {
      const res = await blockQuarantine(emailId, { analyst: 'SOC_ANALYST', notes: 'Confirmed malicious threat' });
      setMsg(`Blocked: ${res.message}`);
      loadData();
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            Pre-Delivery Quarantine Queue
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            High-risk messages held before reaching user inboxes. Full immutable evidence preserved under SHA-256.
          </p>
        </div>
        <div className="badge badge-warn" style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
          <Lock size={14} />
          <span>{items.length} Messages Held</span>
        </div>
      </div>

      {msg && (
        <div style={{
          padding: '0.75rem 1rem',
          backgroundColor: 'rgba(0, 242, 254, 0.1)',
          border: '1px solid var(--accent-cyan)',
          borderRadius: 'var(--radius-sm)',
          fontSize: '0.85rem',
          marginBottom: '1.5rem',
          fontFamily: 'var(--font-mono)'
        }}>
          {msg}
        </div>
      )}

      <div className="glass-panel">
        {items.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            <AlertOctagon size={32} color="var(--status-safe)" style={{ margin: '0 auto 0.75rem auto', display: 'block' }} />
            No messages currently quarantined. Inbound mail stream is clean.
          </div>
        ) : (
          <table className="cyber-table">
            <thead>
              <tr>
                <th>MSG ID</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Threat Classification</th>
                <th>Risk</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                    {item.gateway_message_id}
                  </td>
                  <td>{item.sender}</td>
                  <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.subject}
                  </td>
                  <td>
                    <span className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                      {item.threat_classification}
                    </span>
                  </td>
                  <td>
                    <span className="badge badge-critical">
                      {Math.round(item.risk_score)} / 100
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${item.quarantine_state === 'RELEASED' ? 'safe' : (item.quarantine_state === 'BLOCKED' ? 'critical' : 'warn')}`}>
                      {item.quarantine_state}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                      <Link to={`/investigations?emailId=${item.email_id}`} className="btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                        Inspect
                      </Link>
                      {item.quarantine_state === 'QUARANTINED' && (
                        <>
                          <button
                            className="btn-success"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                            disabled={loading}
                            onClick={() => handleRelease(item.email_id)}
                          >
                            Release
                          </button>
                          <button
                            className="btn-danger"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                            disabled={loading}
                            onClick={() => handleBlock(item.email_id)}
                          >
                            Block
                          </button>
                        </>
                      )}
                    </div>
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
