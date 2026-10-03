import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Radio, 
  ShieldCheck, 
  AlertCircle, 
  CheckCircle, 
  ExternalLink,
  Play,
  RotateCcw,
  Unplug,
  Cpu,
  Mail,
  Zap
} from 'lucide-react';
import { 
  fetchConnectors, 
  fetchGmailStatus, 
  getGmailAuthUrl, 
  startGmailWatch, 
  pollGmailNow, 
  disconnectGmail 
} from '../services/api';

export default function Connections() {
  const [searchParams] = useSearchParams();
  const successParam = searchParams.get('success');
  const errorParam = searchParams.get('error');

  const [connectors, setConnectors] = useState([]);
  const [gmailStatus, setGmailStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [actionMsg, setActionMsg] = useState(null);

  const loadData = async () => {
    try {
      const [connList, gStatus] = await Promise.all([
        fetchConnectors(),
        fetchGmailStatus().catch(() => null)
      ]);
      setConnectors(connList);
      setGmailStatus(gStatus);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
    if (successParam === 'gmail_connected') {
      setActionMsg('Google Gmail account connected successfully via OAuth 2.0!');
    } else if (errorParam) {
      setActionMsg(`Authentication error: ${errorParam}`);
    }
  }, [successParam, errorParam]);

  const handleConnectGmail = async () => {
    setLoading(true);
    setActionMsg(null);
    try {
      const res = await getGmailAuthUrl();
      if (res.auth_url) {
        window.location.href = res.auth_url;
      }
    } catch (e) {
      setActionMsg(`Failed to initiate Google OAuth: ${e.message}`);
      setLoading(false);
    }
  };

  const handleStartWatch = async () => {
    setLoading(true);
    setActionMsg(null);
    try {
      const res = await startGmailWatch();
      setActionMsg(res.message || 'Gmail watch / monitoring activated!');
      loadData();
    } catch (e) {
      setActionMsg(`Failed to start watch: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handlePollNow = async () => {
    setLoading(true);
    setActionMsg(null);
    try {
      const res = await pollGmailNow();
      setActionMsg(`Incremental sync complete: ${res.new_emails_processed} new messages analyzed by TraceMail pipeline.`);
      loadData();
    } catch (e) {
      setActionMsg(`Polling error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnectGmail = async () => {
    setLoading(true);
    setActionMsg(null);
    try {
      await disconnectGmail();
      setActionMsg('Gmail disconnected and stored tokens revoked.');
      loadData();
    } catch (e) {
      setActionMsg(`Disconnect failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
          Mailbox Connectors & Ingestion Gateways
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
          Distinguishes Pre-Delivery SMTP Gateway from Connected-Mailbox API Monitoring (Google Gmail, Microsoft 365, Yahoo/IMAP).
        </p>
      </div>

      {actionMsg && (
        <div style={{
          padding: '0.75rem 1rem',
          backgroundColor: 'rgba(0, 242, 254, 0.1)',
          border: '1px solid var(--accent-cyan)',
          borderRadius: 'var(--radius-sm)',
          fontSize: '0.85rem',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontFamily: 'var(--font-mono)'
        }}>
          <CheckCircle size={16} color="var(--accent-cyan)" />
          <span>{actionMsg}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>
        
        {/* Card 1: TraceMail Inbound SMTP Gateway */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', borderLeft: '4px solid var(--status-safe)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
                PRE_DELIVERY_ENFORCEMENT
              </span>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '0.2rem' }}>
                TraceMail SMTP Gateway
              </h2>
            </div>
            <span className="badge badge-safe">CONNECTED (PORT 1025)</span>
          </div>

          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Real pre-delivery mail transfer agent layer. Intercepts incoming messages, executes SHA-256 evidence preservation, sentinel screening, and ML threat classification before downstream delivery.
          </p>

          <div style={{ padding: '0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>LISTENER HOST / PORT</div>
            <div className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>0.0.0.0:1025 &rarr; Downstream: 127.0.0.1:1026</div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--status-safe)' }}>● Gateway Online</span>
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SOURCE: SMTP_GATEWAY</span>
          </div>
        </div>

        {/* Card 2: Interactive Google Gmail Connector */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', borderLeft: `4px solid ${gmailStatus?.status === 'CONNECTED' ? 'var(--accent-cyan)' : 'var(--border-color)'}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
                  {gmailStatus?.monitoring_mode === 'PUB/SUB_PUSH' ? 'PUB/SUB PUSH' : 'DEVELOPMENT POLLING'}
                </span>
                <span className={`badge ${gmailStatus?.monitoring_mode === 'PUB/SUB_PUSH' ? 'badge-safe' : 'badge-warn'}`} style={{ fontSize: '0.6rem', padding: '0.1rem 0.35rem' }}>
                  {gmailStatus?.monitoring_mode || 'DEV_MODE'}
                </span>
              </div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '0.2rem' }}>
                Google Gmail
              </h2>
            </div>
            <span className={`badge badge-${gmailStatus?.status === 'CONNECTED' ? 'safe' : (gmailStatus?.status === 'NOT_CONFIGURED' ? 'warn' : 'critical')}`}>
              {gmailStatus?.status || 'CHECKING...'}
            </span>
          </div>

          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Google Workspace OAuth 2.0 & Gmail API connector. Retrieves raw MIME format and routes directly through the existing TraceMail forensic pipeline.
          </p>

          <div style={{ padding: '0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>ACCOUNT:</span>
              <span className="font-mono" style={{ fontWeight: 600 }}>{gmailStatus?.account_email || 'None'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>LAST SYNC:</span>
              <span className="font-mono" style={{ fontSize: '0.75rem' }}>{gmailStatus?.last_sync || 'Never'}</span>
            </div>
          </div>

          {/* Interactive Controls */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: 'auto', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
            {gmailStatus?.status !== 'CONNECTED' ? (
              <button 
                className="btn-cyber" 
                style={{ width: '100%', justifyContent: 'center' }} 
                disabled={loading}
                onClick={handleConnectGmail}
              >
                <Mail size={16} />
                <span>Connect Google Gmail</span>
              </button>
            ) : (
              <>
                <button 
                  className="btn-secondary" 
                  style={{ flex: 1, fontSize: '0.75rem', padding: '0.4rem 0.6rem' }} 
                  disabled={loading}
                  onClick={handlePollNow}
                >
                  <RotateCcw size={14} />
                  <span>Poll Ingestion Now</span>
                </button>
                <button 
                  className="btn-secondary" 
                  style={{ flex: 1, fontSize: '0.75rem', padding: '0.4rem 0.6rem' }} 
                  disabled={loading}
                  onClick={handleStartWatch}
                >
                  <Zap size={14} />
                  <span>Start Watch</span>
                </button>
                <button 
                  className="btn-danger" 
                  style={{ fontSize: '0.75rem', padding: '0.4rem 0.6rem' }} 
                  disabled={loading}
                  onClick={handleDisconnectGmail}
                >
                  <Unplug size={14} />
                  <span>Disconnect</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Card 3: Microsoft 365 / Outlook Graph */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
                GRAPH_WEBHOOK_NOTIFICATIONS
              </span>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '0.2rem' }}>
                Microsoft 365 / Outlook
              </h2>
            </div>
            <span className="badge badge-warn">NOT CONFIGURED</span>
          </div>

          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Microsoft Graph Webhook notification connector for corporate Exchange / Outlook cloud mailboxes.
          </p>

          <div style={{ padding: '0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>TARGET TENANT</div>
            <div className="font-mono" style={{ fontWeight: 600 }}>azure-tenant@example.com</div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>OAuth 2.0 Graph API</span>
            <button className="btn-secondary" style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}>
              Configure
            </button>
          </div>
        </div>

        {/* Card 4: Yahoo / Generic IMAP */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
                IMAP_IDLE_OR_POLLING
              </span>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '0.2rem' }}>
                Yahoo / Generic IMAP
              </h2>
            </div>
            <span className="badge badge-warn">NOT CONFIGURED</span>
          </div>

          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Standards-based authorized IMAP IDLE and polling adapter for Yahoo and generic IMAP mail providers.
          </p>

          <div style={{ padding: '0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>PROTOCOL</div>
            <div className="font-mono" style={{ fontWeight: 600 }}>IMAP over TLS (Port 993)</div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>IMAP / App Password</span>
            <button className="btn-secondary" style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}>
              Configure
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
