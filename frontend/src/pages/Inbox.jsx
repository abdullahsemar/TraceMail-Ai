import React, { useEffect, useState, useCallback } from 'react';
import { 
  Inbox as InboxIcon, 
  Search, 
  RefreshCw, 
  ShieldAlert, 
  Filter, 
  ChevronLeft, 
  ChevronRight, 
  Mail, 
  Server, 
  Radio, 
  ArrowUpRight,
  CheckCircle2,
  AlertTriangle,
  Loader2
} from 'lucide-react';
import { fetchEmails, syncGmailInbox } from '../services/api';
import { Link } from 'react-router-dom';

export default function Inbox() {
  const [emails, setEmails] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState(null);
  const [connected, setConnected] = useState(false);

  const loadInbox = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchEmails({
        page,
        pageSize,
        severity: severityFilter,
        source: sourceFilter,
        search: searchTerm
      });

      if (res && res.items) {
        setEmails(res.items);
        setTotal(res.total || 0);
        setTotalPages(res.total_pages || 1);
      } else if (Array.isArray(res)) {
        setEmails(res);
        setTotal(res.length);
        setTotalPages(1);
      }
    } catch (e) {
      console.error("Failed to load inbox:", e);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, sourceFilter, severityFilter, searchTerm]);

  useEffect(() => {
    loadInbox();
  }, [loadInbox]);

  // Real-time SSE Stream for Instant Push Ingestion
  useEffect(() => {
    const eventSource = new EventSource('http://localhost:8000/api/events/stream');
    eventSource.onopen = () => setConnected(true);
    eventSource.onerror = () => setConnected(false);

    eventSource.addEventListener('EMAIL_PROCESSED', (e) => {
      try {
        const newEmail = JSON.parse(e.data);
        const src = 'GMAIL' in (newEmail.source || '').toUpperCase() ? 'GMAIL' : 'SMTP';
        const formatted = {
          id: newEmail.id,
          gateway_message_id: newEmail.gateway_message_id,
          source: newEmail.source,
          source_display: src,
          mail_from: newEmail.sender,
          sender: newEmail.sender,
          subject: newEmail.subject,
          risk_score: newEmail.risk_score,
          final_risk_score: newEmail.risk_score,
          risk_severity: newEmail.severity,
          threat_classification: newEmail.classification,
          action_taken: newEmail.action_taken,
          created_at: newEmail.timestamp
        };

        // Prepend to current list if on page 1
        setEmails(prev => [formatted, ...prev.slice(0, pageSize - 1)]);
        setTotal(prev => prev + 1);
      } catch (err) {
        console.error("SSE parse error:", err);
      }
    });

    return () => eventSource.close();
  }, [pageSize]);

  const handleSyncGmail = async () => {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const res = await syncGmailInbox(25);
      setSyncMessage({
        type: 'success',
        text: `Sync complete: ${res.synced_count} recent Gmail messages screened & normalized.`
      });
      loadInbox();
    } catch (err) {
      setSyncMessage({
        type: 'error',
        text: err.message || 'Gmail sync failed. Check OAuth connection in Settings.'
      });
    } finally {
      setSyncing(false);
    }
  };

  const formatTime = (isoString) => {
    if (!isoString) return '--:--';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return isoString;
    }
  };

  const getSourceBadge = (source) => {
    const isGmail = (source || '').toUpperCase().includes('GMAIL');
    return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.3rem',
        padding: '0.2rem 0.55rem',
        borderRadius: '4px',
        fontSize: '0.7rem',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        backgroundColor: isGmail ? 'rgba(234, 67, 53, 0.15)' : 'rgba(0, 242, 254, 0.15)',
        color: isGmail ? '#ff6b6b' : 'var(--accent-cyan)',
        border: `1px solid ${isGmail ? 'rgba(234, 67, 53, 0.35)' : 'rgba(0, 242, 254, 0.35)'}`
      }}>
        {isGmail ? <Mail size={11} /> : <Server size={11} />}
        <span>{isGmail ? 'GMAIL' : 'SMTP'}</span>
      </span>
    );
  };

  const getActionBadge = (action) => {
    const act = (action || 'ALLOW').toUpperCase();
    
    let color = 'var(--status-safe)';
    let bg = 'rgba(0, 230, 118, 0.1)';
    let border = 'rgba(0, 230, 118, 0.3)';

    if (act === 'FLAG_AND_ALERT') {
      color = 'var(--status-critical)';
      bg = 'rgba(255, 75, 75, 0.15)';
      border = 'rgba(255, 75, 75, 0.4)';
    } else if (act === 'FLAG') {
      color = 'var(--status-warn)';
      bg = 'rgba(255, 179, 0, 0.15)';
      border = 'rgba(255, 179, 0, 0.4)';
    } else {
      color = 'var(--status-safe)';
      bg = 'rgba(0, 230, 118, 0.1)';
      border = 'rgba(0, 230, 118, 0.3)';
    }

    return (
      <span style={{
        fontSize: '0.7rem',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        padding: '0.15rem 0.45rem',
        borderRadius: '3px',
        color: color,
        backgroundColor: bg,
        border: `1px solid ${border}`
      }}>
        {act}
      </span>
    );
  };

  return (
    <div>
      {/* Top Header & Action Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
              Security Inbox & Ingested Messages
            </h1>
            <span className={`badge ${connected ? 'badge-safe' : 'badge-warn'}`} style={{ fontSize: '0.65rem' }}>
              <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: connected ? 'var(--status-safe)' : 'var(--status-warn)' }}></span>
              <span>{connected ? 'LIVE STREAM' : 'OFFLINE'}</span>
            </span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Unified SOC inbox screening real Gmail API ingestion and Pre-Delivery SMTP Proxy traffic.
          </p>
        </div>

        {/* Sync Gmail Button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button
            onClick={handleSyncGmail}
            disabled={syncing}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.55rem 1.1rem', fontSize: '0.85rem' }}
          >
            {syncing ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Syncing Gmail...</span>
              </>
            ) : (
              <>
                <RefreshCw size={16} />
                <span>Sync Gmail Inbox</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Sync Status Banner */}
      {syncMessage && (
        <div style={{
          padding: '0.75rem 1rem',
          borderRadius: 'var(--radius-sm)',
          fontSize: '0.85rem',
          marginBottom: '1.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          backgroundColor: syncMessage.type === 'success' ? 'rgba(0, 230, 118, 0.12)' : 'rgba(255, 75, 75, 0.12)',
          border: `1px solid ${syncMessage.type === 'success' ? 'rgba(0, 230, 118, 0.35)' : 'rgba(255, 75, 75, 0.35)'}`,
          color: syncMessage.type === 'success' ? 'var(--accent-green)' : 'var(--status-danger)',
          fontFamily: 'var(--font-mono)'
        }}>
          {syncMessage.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{syncMessage.text}</span>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="glass-panel" style={{ padding: '0.85rem 1.25rem', marginBottom: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        
        {/* Source Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginRight: '0.25rem' }}>SOURCE:</span>
          {['ALL', 'GMAIL', 'SMTP'].map((src) => (
            <button
              key={src}
              onClick={() => { setSourceFilter(src); setPage(1); }}
              style={{
                padding: '0.35rem 0.75rem',
                borderRadius: '4px',
                fontSize: '0.75rem',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                backgroundColor: sourceFilter === src ? 'rgba(0, 242, 254, 0.15)' : 'transparent',
                border: sourceFilter === src ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                color: sourceFilter === src ? 'var(--accent-cyan)' : 'var(--text-secondary)'
              }}
            >
              {src === 'ALL' ? 'All Sources' : src}
            </button>
          ))}
        </div>

        {/* Severity Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginRight: '0.25rem' }}>SEVERITY:</span>
          {['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((sev) => (
            <button
              key={sev}
              onClick={() => { setSeverityFilter(sev); setPage(1); }}
              style={{
                padding: '0.35rem 0.65rem',
                borderRadius: '4px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                backgroundColor: severityFilter === sev ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
                border: severityFilter === sev ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                color: severityFilter === sev ? 'var(--text-primary)' : 'var(--text-muted)'
              }}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative', minWidth: '240px' }}>
          <input
            type="text"
            placeholder="Search sender, subject, ID..."
            value={searchTerm}
            onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
            style={{
              width: '100%',
              padding: '0.45rem 0.75rem 0.45rem 2rem',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-primary)',
              fontSize: '0.8rem'
            }}
          />
          <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)' }} />
        </div>
      </div>

      {/* Main Inbox Table */}
      <div className="glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
        {loading && emails.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
            <Loader2 size={32} className="animate-spin" style={{ margin: '0 auto 0.75rem auto', display: 'block', color: 'var(--accent-cyan)' }} />
            Loading analyzed emails...
          </div>
        ) : emails.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
            <InboxIcon size={40} color="var(--text-muted)" style={{ margin: '0 auto 0.75rem auto', display: 'block' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
              No Analyzed Emails Yet
            </h3>
            <p style={{ fontSize: '0.85rem', maxWidth: '440px', margin: '0 auto' }}>
              Click <strong>Sync Gmail Inbox</strong> above to import recent messages, or route inbound SMTP traffic to port 1025.
            </p>
          </div>
        ) : (
          <>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th style={{ width: '70px' }}>TIME</th>
                  <th style={{ width: '90px' }}>SOURCE</th>
                  <th style={{ width: '220px' }}>FROM</th>
                  <th>SUBJECT</th>
                  <th style={{ width: '80px' }}>RISK</th>
                  <th style={{ width: '90px' }}>SEVERITY</th>
                  <th style={{ width: '180px' }}>VERDICT</th>
                  <th style={{ width: '130px' }}>ACTION</th>
                  <th style={{ width: '80px', textAlign: 'right' }}>INSPECT</th>
                </tr>
              </thead>
              <tbody>
                {emails.map((e) => (
                  <tr key={e.id} style={{ cursor: 'pointer' }}>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {formatTime(e.created_at)}
                    </td>
                    <td>
                      {getSourceBadge(e.source)}
                    </td>
                    <td style={{ maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.8rem' }}>
                      <span title={e.mail_from || e.sender}>{e.mail_from || e.sender}</span>
                    </td>
                    <td style={{ maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }}>
                      <Link to={`/investigations?emailId=${e.id}`} style={{ color: 'var(--text-primary)', textDecoration: 'none' }}>
                        {e.subject || '(No Subject)'}
                      </Link>
                    </td>
                    <td>
                      <span className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: (e.final_risk_score || e.risk_score || 0) >= 60 ? 'var(--status-critical)' : ((e.final_risk_score || e.risk_score || 0) >= 30 ? 'var(--status-warn)' : 'var(--status-safe)') }}>
                        {Math.round(e.final_risk_score || e.risk_score || 0)}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${(e.risk_severity || 'safe').toLowerCase()}`} style={{ fontSize: '0.65rem' }}>
                        {e.risk_severity || 'LOW'}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: (e.threat_classification === 'LEGITIMATE' || !e.threat_classification) ? 'var(--status-safe)' : 'var(--status-critical)' }}>
                      {e.threat_classification || 'LEGITIMATE'}
                    </td>
                    <td>
                      {getActionBadge(e.action_taken)}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <Link to={`/investigations?emailId=${e.id}`} className="btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                        <span>Inspect</span>
                        <ArrowUpRight size={12} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination Controls */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '0.85rem 1.25rem',
              borderTop: '1px solid var(--border-color)',
              backgroundColor: 'rgba(10, 13, 20, 0.4)'
            }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Showing {emails.length} of {total} messages (Page {page} of {totalPages})
              </span>

              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  className="btn-secondary"
                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                  disabled={page <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                >
                  <ChevronLeft size={14} />
                  <span>Previous</span>
                </button>
                <button
                  className="btn-secondary"
                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                  disabled={page >= totalPages}
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                >
                  <span>Next</span>
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
