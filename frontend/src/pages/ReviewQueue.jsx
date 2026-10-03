import React, { useEffect, useState } from 'react';
import { ClipboardCheck, CheckCircle, XCircle, Search, AlertTriangle, ShieldAlert, ArrowRight, Check, Eye } from 'lucide-react';
import { fetchReviewQueue, updateCaseReviewStatus, submitAnalystFeedback } from '../services/api';
import { Link } from 'react-router-dom';

export default function ReviewQueue() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);
  const [filterStatus, setFilterStatus] = useState('ALL');

  const loadData = async () => {
    try {
      const data = await fetchReviewQueue();
      setItems(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleUpdateStatus = async (caseId, status) => {
    setLoading(true);
    setMsg(null);
    try {
      await updateCaseReviewStatus(caseId, {
        status: status,
        analyst: 'SOC_ANALYST',
        notes: `Status updated to ${status} via Review Queue`
      });
      setMsg(`Case status updated to ${status}`);
      loadData();
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleFeedback = async (caseId, verdict) => {
    setLoading(true);
    setMsg(null);
    try {
      await submitAnalystFeedback(caseId, {
        verdict_label: verdict,
        analyst_name: 'SOC_ANALYST',
        notes: `Analyst review verdict: ${verdict}`
      });
      setMsg(`Feedback recorded: ${verdict} (Stored for offline calibration)`);
      loadData();
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const filteredItems = filterStatus === 'ALL'
    ? items
    : items.filter(i => (i.review_status || 'UNREVIEWED').toUpperCase() === filterStatus);

  const getStatusBadgeClass = (st) => {
    switch ((st || '').toUpperCase()) {
      case 'CONFIRMED_THREAT': return 'badge-critical';
      case 'FALSE_POSITIVE': return 'badge-safe';
      case 'RESOLVED': return 'badge-safe';
      case 'IN_REVIEW': return 'badge-warn';
      default: return 'badge-warn';
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            SOC Incident Review Queue
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Analytical triage workspace for flagged and high-risk emails. All messages delivered downstream with X-TraceMail warning headers while evidence is cryptographically preserved.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="badge badge-warn" style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
            <ClipboardCheck size={14} />
            <span>{items.filter(i => i.review_status === 'UNREVIEWED').length} Unreviewed Cases</span>
          </div>
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

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem' }}>
        {['ALL', 'UNREVIEWED', 'IN_REVIEW', 'CONFIRMED_THREAT', 'FALSE_POSITIVE', 'RESOLVED'].map(st => (
          <button
            key={st}
            onClick={() => setFilterStatus(st)}
            className={`btn-tab ${filterStatus === st ? 'active' : ''}`}
            style={{
              padding: '0.4rem 0.8rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              backgroundColor: filterStatus === st ? 'rgba(0, 242, 254, 0.12)' : 'rgba(15, 21, 35, 0.6)',
              color: filterStatus === st ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              border: filterStatus === st ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              cursor: 'pointer'
            }}
          >
            {st.replace(/_/g, ' ')} {st === 'ALL' ? `(${items.length})` : `(${items.filter(i => (i.review_status || 'UNREVIEWED') === st).length})`}
          </button>
        ))}
      </div>

      <div className="glass-panel">
        {filteredItems.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--text-muted)' }}>
            <CheckCircle size={36} color="var(--status-safe)" style={{ margin: '0 auto 0.75rem auto', display: 'block' }} />
            No incidents currently matching the '{filterStatus}' review queue filter.
          </div>
        ) : (
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Threat Classification</th>
                <th>Risk Score</th>
                <th>Confidence</th>
                <th>Review Status</th>
                <th>Analyst Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredItems.map((item) => (
                <tr key={item.case_id}>
                  <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                    {item.case_number}
                  </td>
                  <td style={{ maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.sender}
                  </td>
                  <td style={{ maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.subject || '(No Subject)'}
                  </td>
                  <td>
                    <span className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                      {item.threat_classification}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${(item.severity || 'high').toLowerCase()}`}>
                      {Math.round(item.risk_score)} / 100
                    </span>
                  </td>
                  <td>
                    <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {Math.round((item.evidence_confidence || 0.85) * 100)}%
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${getStatusBadgeClass(item.review_status)}`}>
                      {item.review_status || 'UNREVIEWED'}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                      <Link to={`/investigations?emailId=${item.email_id}`} className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                        <Eye size={12} />
                        <span>Inspect</span>
                      </Link>
                      
                      {item.review_status !== 'CONFIRMED_THREAT' && (
                        <button
                          className="btn-danger"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.72rem' }}
                          disabled={loading}
                          onClick={() => handleFeedback(item.case_id, 'CONFIRMED_THREAT')}
                          title="Confirm threat for intelligence and offline calibration"
                        >
                          Confirm Threat
                        </button>
                      )}

                      {item.review_status !== 'FALSE_POSITIVE' && (
                        <button
                          className="btn-success"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.72rem' }}
                          disabled={loading}
                          onClick={() => handleFeedback(item.case_id, 'FALSE_POSITIVE')}
                          title="Mark as benign false positive"
                        >
                          False Positive
                        </button>
                      )}

                      {item.review_status !== 'RESOLVED' && item.review_status !== 'CONFIRMED_THREAT' && item.review_status !== 'FALSE_POSITIVE' && (
                        <button
                          className="btn-secondary"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.72rem' }}
                          disabled={loading}
                          onClick={() => handleUpdateStatus(item.case_id, 'RESOLVED')}
                        >
                          Resolve
                        </button>
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
