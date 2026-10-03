import React, { useEffect, useState } from 'react';
import { 
  Settings as SettingsIcon, 
  Server, 
  Shield, 
  Database, 
  Cpu, 
  Send, 
  Globe, 
  Mail, 
  CheckCircle2, 
  AlertCircle, 
  HelpCircle, 
  Loader2,
  RefreshCw,
  Activity,
  ArrowRight,
  BookOpen
} from 'lucide-react';
import { fetchHealth, testTelegramConnection, fetchSmtpStatus, testDownstreamSmtp } from '../services/api';

export default function Settings() {
  const [health, setHealth] = useState(null);
  const [smtpStatus, setSmtpStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  
  // Telegram testing state
  const [telegramLoading, setTelegramLoading] = useState(false);
  const [telegramStatus, setTelegramStatus] = useState(null);

  // Downstream SMTP testing state
  const [smtpTesting, setSmtpTesting] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState(null);

  const loadData = async () => {
    try {
      const [h, s] = await Promise.all([
        fetchHealth(),
        fetchSmtpStatus().catch(() => null)
      ]);
      setHealth(h);
      setSmtpStatus(s);
    } catch (e) {
      console.error("Health check error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleTestTelegram = async () => {
    setTelegramLoading(true);
    setTelegramStatus(null);
    try {
      const res = await testTelegramConnection();
      setTelegramStatus({
        success: true,
        message: res.message || "Notification sent successfully."
      });
      loadData();
    } catch (err) {
      setTelegramStatus({
        success: false,
        message: err.message || "Failed to reach Telegram API. Check backend/.env."
      });
    } finally {
      setTelegramLoading(false);
    }
  };

  const handleTestDownstreamSmtp = async () => {
    setSmtpTesting(true);
    setSmtpTestResult(null);
    try {
      const res = await testDownstreamSmtp();
      setSmtpTestResult(res);
      loadData();
    } catch (err) {
      setSmtpTestResult({
        success: false,
        status: "ERROR",
        error: err.message || "Downstream SMTP test failed."
      });
    } finally {
      setSmtpTesting(false);
    }
  };

  const renderStatusBadge = (val, okValues = ['ok', 'healthy', 'loaded', 'connected', 'running', 'configured', 'available']) => {
    const isOk = okValues.includes(String(val).toLowerCase());
    const isUnconfigured = String(val).toLowerCase().includes('not_configured') || String(val).toLowerCase().includes('uninitialized') || String(val).toLowerCase().includes('disabled');
    
    let color = 'var(--status-danger)';
    let text = String(val).toUpperCase();
    let bg = 'rgba(255, 75, 75, 0.15)';
    let border = 'rgba(255, 75, 75, 0.4)';

    if (isOk) {
      color = 'var(--accent-green)';
      bg = 'rgba(0, 230, 118, 0.15)';
      border = 'rgba(0, 230, 118, 0.4)';
    } else if (isUnconfigured) {
      color = 'var(--text-muted)';
      bg = 'rgba(140, 150, 170, 0.15)';
      border = 'rgba(140, 150, 170, 0.3)';
    }

    return (
      <span style={{
        fontSize: '0.75rem',
        fontWeight: 700,
        padding: '0.2rem 0.6rem',
        borderRadius: '4px',
        backgroundColor: bg,
        border: `1px solid ${border}`,
        color: color,
        fontFamily: 'var(--font-mono)'
      }}>
        {text}
      </span>
    );
  };

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
          System Configuration & Subsystem Diagnostics
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
          Real-time integration status, ML engine health, research methodology, and non-quarantining security policies.
        </p>
      </div>

      {/* Research Methodology Banner */}
      <div className="glass-panel" style={{ marginBottom: '2rem', padding: '1.25rem', border: '1px solid rgba(0, 242, 254, 0.25)', backgroundColor: 'rgba(0, 242, 254, 0.03)' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-cyan)' }}>
          <BookOpen size={18} />
          <span>Research Foundation & Architecture Grounding</span>
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '0.75rem' }}>
          TraceMail AI utilizes principles inspired by <strong>Asaf Cidon et al., "High Precision Detection of Business Email Compromise", 28th USENIX Security Symposium, 2019</strong>.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <div style={{ padding: '0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)' }}>
            <strong style={{ color: 'var(--accent-cyan)' }}>Research-Informed Components:</strong>
            <ul style={{ paddingLeft: '1.2rem', marginTop: '0.25rem', lineHeight: '1.5' }}>
              <li>Historical organizational sender identity pairing (Table 3)</li>
              <li>Sequential detection (Stage A metadata &rarr; Stage B content)</li>
              <li>Known legitimate Reply-To service mitigation</li>
              <li>Sender-recipient communication graph familiarity</li>
            </ul>
          </div>
          <div style={{ padding: '0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)' }}>
            <strong style={{ color: 'var(--accent-purple)' }}>TraceMail Extensions:</strong>
            <ul style={{ paddingLeft: '1.2rem', marginTop: '0.25rem', lineHeight: '1.5' }}>
              <li>Pretrained Contextual Transformer NLP (DistilBERT)</li>
              <li>Dependency-aware heterogeneous evidence fusion</li>
              <li>Cross-platform fuzzy campaign clustering (SimHash)</li>
              <li>Pre-Delivery SMTP proxy inspection & header injection</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Subsystems Live Status Grid */}
      <div className="glass-panel" style={{ marginBottom: '2rem', padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={18} color="var(--accent-cyan)" />
          <span>Subsystems & Providers Live Health</span>
        </h2>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem'
        }}>
          {/* DistilBERT */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <Cpu size={15} />
                <span>DistilBERT ML</span>
              </div>
              {renderStatusBadge(health?.distilbert ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Pretrained Hugging Face Model</div>
          </div>

          {/* Gmail Connector */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <Mail size={15} />
                <span>Gmail API</span>
              </div>
              {renderStatusBadge(health?.gmail ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Retrospective Ingestion</div>
          </div>

          {/* Inbound SMTP Proxy */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <Server size={15} />
                <span>SMTP Proxy</span>
              </div>
              {renderStatusBadge(health?.smtp_gateway ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Pre-Delivery Port 1025</div>
          </div>

          {/* Downstream SMTP Relay */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <ArrowRight size={15} />
                <span>Downstream SMTP</span>
              </div>
              {renderStatusBadge(health?.downstream_smtp ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Target MTA Delivery</div>
          </div>

          {/* Telegram */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <Send size={15} />
                <span>Telegram Bot</span>
              </div>
              {renderStatusBadge(health?.telegram ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>SOC Incident Alerting</div>
          </div>

          {/* GeoIP */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <Globe size={15} />
                <span>MaxMind GeoIP</span>
              </div>
              {renderStatusBadge(health?.geoip ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Observable Infrastructure MMDB</div>
          </div>

          {/* Database */}
          <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                <Database size={15} />
                <span>Database</span>
              </div>
              {renderStatusBadge(health?.database ?? 'LOADING')}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Audit & Behavioral Graph DB</div>
          </div>
        </div>
      </div>

      {/* Downstream SMTP Relay Diagnostics Card */}
      <div className="glass-panel" style={{ marginBottom: '2rem', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={18} color="var(--accent-blue)" />
              <span>Downstream SMTP Relay Diagnostics</span>
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Safely tests DNS resolution, TCP reachability, and TLS/STARTTLS handshake to your downstream mail server without sending fake emails.
            </p>
          </div>

          <button
            onClick={handleTestDownstreamSmtp}
            disabled={smtpTesting}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem', fontSize: '0.85rem' }}
          >
            {smtpTesting ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Testing Connection...</span>
              </>
            ) : (
              <>
                <Activity size={16} />
                <span>TEST DOWNSTREAM SMTP</span>
              </>
            )}
          </button>
        </div>

        {smtpStatus && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginTop: '1rem' }}>
            <div style={{ padding: '0.5rem 0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>TARGET HOST:PORT</span>
              <div className="font-mono" style={{ fontWeight: 600 }}>
                {smtpStatus.downstream_host || 'Not Configured'}:{smtpStatus.downstream_port || 1026}
              </div>
            </div>
            <div style={{ padding: '0.5rem 0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>TLS ENCRYPTION</span>
              <div className="font-mono" style={{ fontWeight: 600 }}>
                {smtpStatus.downstream_tls ? 'DIRECT TLS' : (smtpStatus.downstream_starttls ? 'STARTTLS' : 'PLAIN / NONE')}
              </div>
            </div>
            <div style={{ padding: '0.5rem 0.75rem', background: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>FLAGGED MESSAGES</span>
              <div className="font-mono" style={{ fontWeight: 600, color: 'var(--status-warn)' }}>
                {smtpStatus.flagged_count || 0} flagged
              </div>
            </div>
          </div>
        )}

        {smtpTestResult && (
          <div style={{
            marginTop: '1rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            backgroundColor: smtpTestResult.success ? 'rgba(0, 230, 118, 0.12)' : 'rgba(255, 179, 0, 0.12)',
            border: `1px solid ${smtpTestResult.success ? 'rgba(0, 230, 118, 0.35)' : 'rgba(255, 179, 0, 0.35)'}`,
            color: smtpTestResult.success ? 'var(--accent-green)' : 'var(--status-warn)',
            fontFamily: 'var(--font-mono)'
          }}>
            {smtpTestResult.success ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
            <span>{smtpTestResult.message || smtpTestResult.error || `Status: ${smtpTestResult.status}`}</span>
          </div>
        )}
      </div>

      {/* Telegram Alerting Channel Control */}
      <div className="glass-panel" style={{ marginBottom: '2rem', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Send size={18} color="var(--accent-cyan)" />
              <span>Telegram Threat Notification Channel</span>
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Asynchronous incident alerting dispatched directly to your SOC / Mobile Chat. Configured securely via <code>backend/.env</code>.
            </p>
          </div>

          <button
            id="test-telegram-btn"
            onClick={handleTestTelegram}
            disabled={telegramLoading}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem', fontSize: '0.85rem' }}
          >
            {telegramLoading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Connecting...</span>
              </>
            ) : (
              <>
                <Send size={16} />
                <span>TEST TELEGRAM</span>
              </>
            )}
          </button>
        </div>

        {telegramStatus && (
          <div style={{
            marginTop: '1rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            backgroundColor: telegramStatus.success ? 'rgba(0, 230, 118, 0.12)' : 'rgba(255, 75, 75, 0.12)',
            border: `1px solid ${telegramStatus.success ? 'rgba(0, 230, 118, 0.35)' : 'rgba(255, 75, 75, 0.35)'}`,
            color: telegramStatus.success ? 'var(--accent-green)' : 'var(--status-danger)',
            fontFamily: 'var(--font-mono)'
          }}>
            {telegramStatus.success ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
            <span>{telegramStatus.message}</span>
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
        <div className="glass-panel">
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={18} color="var(--accent-cyan)" />
            <span>Deployment Mode & Routing</span>
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
            <div>
              <label style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Active Deployment Mode</label>
              <input type="text" value={health?.deployment_mode ? health.deployment_mode.toUpperCase() : "HYBRID (GMAIL + SMTP PROXY)"} readOnly style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)' }} />
            </div>
            <div>
              <label style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Inbound SMTP Listen Port</label>
              <input type="text" value="1025" readOnly style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)' }} />
            </div>
            <div>
              <label style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Downstream Mail Server Target</label>
              <input type="text" value="127.0.0.1:1026 (Configurable via .env)" readOnly style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)' }} />
            </div>
          </div>
        </div>

        <div className="glass-panel">
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={18} color="var(--status-warn)" />
            <span>Risk Thresholds & Operational Policy</span>
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
            <div>
              <label style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>High-Risk Flag & Alert Threshold</label>
              <input type="text" value=">= 60 / 100 (FLAG_AND_ALERT -> Case Created + Telegram)" readOnly style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)' }} />
            </div>
            <div>
              <label style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Suspicious Warning Threshold</label>
              <input type="text" value=">= 30 / 100 (FLAG -> Warning Headers Injected)" readOnly style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)' }} />
            </div>
            <div>
              <label style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Delivery Policy</label>
              <input type="text" value="NON-QUARANTINING PROXY (All valid messages forwarded)" readOnly style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)' }} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
