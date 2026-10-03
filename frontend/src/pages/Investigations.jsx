import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Search, 
  Globe, 
  FileCheck2, 
  Layers, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Cpu, 
  Send,
  FileCode,
  Mail,
  Eye,
  FileText,
  Key,
  Server,
  Terminal,
  ShieldCheck,
  ShieldX,
  BookOpen,
  UserCheck,
  Link2,
  Paperclip,
  Network
} from 'lucide-react';
import { fetchEmails, fetchEmailDetails, submitAnalystFeedback, updateCaseReviewStatus } from '../services/api';
import ScoreGauge from '../components/ScoreGauge';

export default function Investigations() {
  const [searchParams] = useSearchParams();
  const emailIdParam = searchParams.get('emailId');

  const [emails, setEmails] = useState([]);
  const [selectedId, setSelectedId] = useState(emailIdParam);
  const [details, setDetails] = useState(null);
  const [activeTab, setActiveTab] = useState('OVERVIEW'); // OVERVIEW | BEC_RESEARCH | CONTENT | AUTH | IDENTITY | BEHAVIOR | URLS | ATTACHMENTS | RELAY | ORIGIN | EVIDENCE | HEADERS
  const [contentMode, setContentMode] = useState('TEXT'); // TEXT | HTML_SANITIZED
  const [loadRemoteImages, setLoadRemoteImages] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMsg, setActionMsg] = useState(null);

  useEffect(() => {
    fetchEmails({ page: 1, pageSize: 50 }).then((data) => {
      const list = data?.items || (Array.isArray(data) ? data : []);
      setEmails(list);
      if (!selectedId && list.length > 0) {
        setSelectedId(list[0].id);
      }
    }).catch(console.error);
  }, []);

  useEffect(() => {
    if (selectedId) {
      fetchEmailDetails(selectedId).then(setDetails).catch(console.error);
      setLoadRemoteImages(false);
    }
  }, [selectedId]);

  const handleAnalystFeedback = async (verdict) => {
    if (!details?.case?.case_number) return;
    setActionLoading(true);
    setActionMsg(null);
    try {
      await submitAnalystFeedback(details.case.case_number, {
        verdict_label: verdict,
        analyst_name: 'SOC_ANALYST',
        notes: `Analyst feedback recorded from Investigation View: ${verdict}`
      });
      setActionMsg(`Analyst feedback recorded: ${verdict}. Preserved for offline calibration.`);
      const updated = await fetchEmailDetails(selectedId);
      setDetails(updated);
    } catch (e) {
      setActionMsg(`Feedback error: ${e.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleResolveCase = async () => {
    if (!details?.case?.case_number) return;
    setActionLoading(true);
    setActionMsg(null);
    try {
      await updateCaseReviewStatus(details.case.case_number, {
        status: 'RESOLVED',
        analyst: 'SOC_ANALYST',
        notes: 'Investigation concluded and case marked resolved'
      });
      setActionMsg('Case successfully resolved.');
      const updated = await fetchEmailDetails(selectedId);
      setDetails(updated);
    } catch (e) {
      setActionMsg(`Resolve error: ${e.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const sanitizeHtmlForDisplay = (htmlStr, allowRemoteImages) => {
    if (!htmlStr) return '';
    let sanitized = htmlStr
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
      .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
      .replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, '')
      .replace(/<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi, '')
      .replace(/on\w+="[^"]*"/gi, '')
      .replace(/on\w+='[^']*'/gi, '')
      .replace(/javascript:[^"']*/gi, '#');

    if (!allowRemoteImages) {
      sanitized = sanitized.replace(/<img\b([^>]*)\bsrc="https?:\/\/[^"]*"([^>]*)>/gi, '<span style="display:inline-block;padding:2px 6px;background:rgba(255,255,255,0.08);border:1px dashed #555;font-size:11px;color:#aaa;border-radius:3px;">[Remote Image Blocked]</span>');
    }
    return sanitized;
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1.5rem', minHeight: '85vh' }}>
      {/* Left Column: Email Incident List */}
      <div className="glass-panel" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', height: 'calc(100vh - 4rem)' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Search size={16} color="var(--accent-cyan)" />
          <span>Incident Cases ({emails.length})</span>
        </h2>
        
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {emails.map((e) => {
            const isSelected = e.id === selectedId;
            const src = (e.source || '').toUpperCase().includes('GMAIL') ? 'GMAIL' : 'SMTP';
            return (
              <div
                key={e.id}
                onClick={() => setSelectedId(e.id)}
                style={{
                  padding: '0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: isSelected ? 'rgba(0, 242, 254, 0.08)' : 'rgba(15, 21, 35, 0.6)',
                  border: isSelected ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                  <span className="font-mono" style={{ fontSize: '0.7rem', color: isSelected ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
                    {e.gateway_message_id}
                  </span>
                  <span className={`badge badge-${(e.risk_severity || 'low').toLowerCase()}`} style={{ fontSize: '0.6rem', padding: '0.1rem 0.4rem' }}>
                    {src} : {e.risk_severity || 'LOW'}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {e.subject || '(No Subject)'}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {e.mail_from || e.sender}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Column: Deep Forensic Breakdown & Content Tabs */}
      <div style={{ overflowY: 'auto', maxHeight: 'calc(100vh - 4rem)', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {!details ? (
          <div className="glass-panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            Select an incident from the left panel to inspect deep forensic evidence.
          </div>
        ) : (
          <>
            {/* Top Incident Summary Header */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
                    <span className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                      {details.gateway_message_id}
                    </span>
                    <span className={`badge badge-${(details.risk_severity || 'low').toLowerCase()}`}>
                      {details.threat_classification}
                    </span>
                    <span className="badge badge-safe" style={{ fontSize: '0.65rem' }}>
                      ACTION: {details.action_taken || 'ALLOW'}
                    </span>
                  </div>
                  <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.3rem' }}>
                    {details.subject || '(No Subject)'}
                  </h2>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    FROM: <span style={{ color: 'var(--text-primary)' }}>{details.mail_from}</span>
                    {details.reply_to && details.reply_to !== details.mail_from && (
                      <span style={{ marginLeft: '1rem', color: 'var(--status-warn)' }}>
                        REPLY-TO: {details.reply_to}
                      </span>
                    )}
                  </div>
                </div>

                {/* Score & Multi-Dimensional Risk Meters */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '1.8rem', fontWeight: 800, color: details.final_risk_score >= 60 ? 'var(--status-critical)' : (details.final_risk_score >= 30 ? 'var(--status-warn)' : 'var(--status-safe)') }}>
                      {Math.round(details.final_risk_score)}<span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/100</span>
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</div>
                  </div>

                  <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '1rem', display: 'flex', flexDirection: 'column', gap: '0.2rem', fontSize: '0.72rem' }}>
                    <div>Threat Prob: <strong>{Math.round((details.threat_probability || (details.final_risk_score/100)) * 100)}%</strong></div>
                    <div>Evidence Conf: <strong>{Math.round((details.evidence_confidence || 0.85) * 100)}%</strong></div>
                    <div>Impact Score: <strong>{Math.round((details.impact_score || 0.5) * 100)}%</strong></div>
                  </div>
                </div>
              </div>

              {/* Action message banner if any */}
              {actionMsg && (
                <div style={{ marginTop: '1rem', padding: '0.5rem 0.75rem', backgroundColor: 'rgba(0, 242, 254, 0.1)', border: '1px solid var(--accent-cyan)', borderRadius: '4px', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                  {actionMsg}
                </div>
              )}

              {/* SOC Analyst Review Action Row */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Review Status: <span className="badge badge-warn" style={{ marginLeft: '0.4rem' }}>{details.review_status || 'UNREVIEWED'}</span>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    className="btn-danger"
                    style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                    disabled={actionLoading}
                    onClick={() => handleAnalystFeedback('CONFIRMED_THREAT')}
                  >
                    Confirm Threat
                  </button>
                  <button
                    className="btn-success"
                    style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                    disabled={actionLoading}
                    onClick={() => handleAnalystFeedback('FALSE_POSITIVE')}
                  >
                    Mark False Positive
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem' }}
                    disabled={actionLoading}
                    onClick={handleResolveCase}
                  >
                    Resolve Case
                  </button>
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
              {[
                { id: 'OVERVIEW', label: 'Forensic Overview', icon: Layers },
                { id: 'BEC_RESEARCH', label: 'Research-Based BEC Analysis', icon: BookOpen },
                { id: 'CONTENT', label: 'Email Content', icon: FileText },
                { id: 'AUTH', label: 'Authentication (SPF/DKIM)', icon: ShieldCheck },
                { id: 'IDENTITY', label: 'Identity & Display Name', icon: UserCheck },
                { id: 'URLS', label: 'URLs & Domains', icon: Link2 },
                { id: 'ATTACHMENTS', label: 'Attachments', icon: Paperclip },
                { id: 'RELAY', label: 'Relay & Hop Trace', icon: Network },
                { id: 'ORIGIN', label: 'Infrastructure & Origin', icon: Globe },
                { id: 'HEADERS', label: 'Raw Headers', icon: Terminal }
              ].map(tab => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`btn-tab ${activeTab === tab.id ? 'active' : ''}`}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '0.4rem 0.75rem',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      backgroundColor: activeTab === tab.id ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                      color: activeTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                      border: activeTab === tab.id ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer'
                    }}
                  >
                    <Icon size={14} />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            {/* TAB CONTENT: OVERVIEW */}
            {activeTab === 'OVERVIEW' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                <div className="glass-panel">
                  <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--status-critical)' }}>
                    Top Supporting Threat Evidence
                  </h3>
                  {details.analysis?.supporting_reasons?.length > 0 ? (
                    <ul style={{ paddingLeft: '1.2rem', fontSize: '0.82rem', lineHeight: '1.6' }}>
                      {details.analysis.supporting_reasons.map((r, i) => (
                        <li key={i} style={{ marginBottom: '0.35rem' }}>{r}</li>
                      ))}
                    </ul>
                  ) : (
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No strong malicious indicators observed.</div>
                  )}
                </div>

                <div className="glass-panel">
                  <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--status-safe)' }}>
                    Top Mitigating Evidence
                  </h3>
                  {details.analysis?.mitigating_reasons?.length > 0 ? (
                    <ul style={{ paddingLeft: '1.2rem', fontSize: '0.82rem', lineHeight: '1.6' }}>
                      {details.analysis.mitigating_reasons.map((r, i) => (
                        <li key={i} style={{ marginBottom: '0.35rem' }}>{r}</li>
                      ))}
                    </ul>
                  ) : (
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No significant mitigating factors recorded.</div>
                  )}

                  {details.analysis?.uncertainties?.length > 0 && (
                    <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)' }}>
                      <h4 style={{ fontSize: '0.78rem', color: 'var(--status-warn)', marginBottom: '0.35rem' }}>
                        Baseline Uncertainties
                      </h4>
                      <ul style={{ paddingLeft: '1.2rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {details.analysis.uncertainties.map((u, i) => (
                          <li key={i}>{u}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB CONTENT: RESEARCH-BASED BEC ANALYSIS */}
            {activeTab === 'BEC_RESEARCH' && (
              <div className="glass-panel">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem' }}>
                  <div>
                    <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>
                      Sequential BEC Detection Architecture
                    </h3>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      Methodology inspired by Asaf Cidon et al., "High Precision Detection of Business Email Compromise", 28th USENIX Security Symposium, 2019.
                    </p>
                  </div>
                  <span className="badge badge-safe" style={{ fontSize: '0.7rem' }}>
                    CIDON ET AL. 2019 COMPATIBLE
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
                  <div style={{ padding: '0.85rem', backgroundColor: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>STAGE A: IMPERSONATION PROBABILITY</div>
                    <div style={{ fontSize: '1.3rem', fontWeight: 800, color: (details.research_bec_analysis?.stage_a_impersonation_score || 0) >= 0.4 ? 'var(--status-critical)' : 'var(--status-safe)' }}>
                      {Math.round((details.research_bec_analysis?.stage_a_impersonation_score || 0) * 100)}%
                    </div>
                    <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      Evaluates From/Reply-To divergence, sender corporate domain status, and historical name/address pairing.
                    </p>
                  </div>

                  <div style={{ padding: '0.85rem', backgroundColor: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>STAGE B: CONTENT / NLP RISK</div>
                    <div style={{ fontSize: '1.3rem', fontWeight: 800, color: (details.research_bec_analysis?.stage_b_content_risk || 0) >= 0.5 ? 'var(--status-critical)' : 'var(--status-safe)' }}>
                      {Math.round((details.research_bec_analysis?.stage_b_content_risk || 0) * 100)}%
                    </div>
                    <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      Evaluates wire transfer lures, gift card requests, PII solicitations, and executive urgency.
                    </p>
                  </div>

                  <div style={{ padding: '0.85rem', backgroundColor: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>BASELINE MATURITY</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                      {details.research_bec_analysis?.baseline_maturity || 'COLD_START'}
                    </div>
                    <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      {details.research_bec_analysis?.historical_sample_count || 1} historical messages recorded in organization graph.
                    </p>
                  </div>
                </div>

                <div style={{ fontSize: '0.82rem', backgroundColor: 'rgba(0, 242, 254, 0.04)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(0, 242, 254, 0.2)' }}>
                  <h4 style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '0.35rem' }}>
                    Paper-Backed Identity Feature Verification (Table 3):
                  </h4>
                  <ul style={{ paddingLeft: '1.2rem', lineHeight: '1.6', color: 'var(--text-secondary)' }}>
                    <li>Sender corporate domain check: <strong>{details.research_bec_analysis?.sender_corporate_domain ? 'Corporate Member' : 'External Domain'}</strong></li>
                    <li>Reply-To address mismatch: <strong>{details.research_bec_analysis?.reply_to_anomaly ? 'Divergent Reply-To' : 'Aligned'}</strong></li>
                    <li>Known legitimate Reply-To service: <strong>{details.analysis?.mitigating_reasons?.some(r => r.includes('enterprise')) ? 'Yes (Mitigating)' : 'Standard Domain'}</strong></li>
                    <li>TraceMail Sequential Gate: Stage A metadata impersonation probability feeds Stage B semantic transformer analysis.</li>
                  </ul>
                </div>
              </div>
            )}

            {/* TAB CONTENT: EMAIL CONTENT */}
            {activeTab === 'CONTENT' && (
              <div className="glass-panel">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      onClick={() => setContentMode('TEXT')}
                      className={`btn-secondary ${contentMode === 'TEXT' ? 'active' : ''}`}
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                    >
                      Plain Text
                    </button>
                    <button
                      onClick={() => setContentMode('HTML_SANITIZED')}
                      className={`btn-secondary ${contentMode === 'HTML_SANITIZED' ? 'active' : ''}`}
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                    >
                      Sanitized HTML
                    </button>
                  </div>

                  {contentMode === 'HTML_SANITIZED' && (
                    <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={loadRemoteImages}
                        onChange={(e) => setLoadRemoteImages(e.target.checked)}
                      />
                      <span>Allow Remote Tracking Images</span>
                    </label>
                  )}
                </div>

                {contentMode === 'TEXT' ? (
                  <pre style={{
                    padding: '1rem',
                    backgroundColor: 'rgba(10, 13, 20, 0.8)',
                    borderRadius: 'var(--radius-sm)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.82rem',
                    whiteSpace: 'pre-wrap',
                    color: 'var(--text-primary)',
                    maxHeight: '400px',
                    overflowY: 'auto'
                  }}>
                    {details.evidence?.body_text || '(Empty Body Text)'}
                  </pre>
                ) : (
                  <div
                    style={{
                      padding: '1rem',
                      backgroundColor: '#ffffff',
                      color: '#222222',
                      borderRadius: 'var(--radius-sm)',
                      minHeight: '200px',
                      maxHeight: '400px',
                      overflowY: 'auto'
                    }}
                    dangerouslySetInnerHTML={{
                      __html: sanitizeHtmlForDisplay(details.evidence?.body_html_sanitized || details.evidence?.body_text, loadRemoteImages)
                    }}
                  />
                )}
              </div>
            )}

            {/* TAB CONTENT: AUTHENTICATION */}
            {activeTab === 'AUTH' && (
              <div className="glass-panel">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Cryptographic Email Authentication</h3>
                  <span className="badge badge-warn" style={{ fontSize: '0.68rem' }}>PRINCIPLE: AUTH PASS != SAFE</span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                  <div style={{ padding: '0.85rem', backgroundColor: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>SPF VALIDATION</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: details.authentication?.spf_result === 'PASS' ? 'var(--status-safe)' : (details.authentication?.spf_result === 'FAIL' ? 'var(--status-critical)' : 'var(--text-muted)') }}>
                      {details.authentication?.spf_result || 'UNKNOWN'}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Domain: {details.authentication?.spf_domain || 'N/A'}</div>
                  </div>

                  <div style={{ padding: '0.85rem', backgroundColor: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>DKIM CRYPTOGRAPHIC SIGNATURE</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: details.authentication?.dkim_result === 'PASS' ? 'var(--status-safe)' : (details.authentication?.dkim_result === 'FAIL' ? 'var(--status-critical)' : 'var(--text-muted)') }}>
                      {details.authentication?.dkim_result || 'UNKNOWN'}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Domain: {details.authentication?.dkim_domain || 'N/A'}</div>
                  </div>

                  <div style={{ padding: '0.85rem', backgroundColor: 'rgba(15, 21, 35, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>DMARC POLICY ALIGNMENT</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: details.authentication?.dmarc_result === 'PASS' ? 'var(--status-safe)' : (details.authentication?.dmarc_result === 'FAIL' ? 'var(--status-critical)' : 'var(--text-muted)') }}>
                      {details.authentication?.dmarc_result || 'UNKNOWN'}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Policy: {details.authentication?.dmarc_policy || 'none'}</div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: RAW HEADERS */}
            {activeTab === 'HEADERS' && (
              <div className="glass-panel">
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Preserved RFC822 Email Headers</h3>
                <pre style={{
                  padding: '1rem',
                  backgroundColor: 'rgba(10, 13, 20, 0.8)',
                  borderRadius: 'var(--radius-sm)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.75rem',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '400px',
                  overflowY: 'auto',
                  color: 'var(--text-primary)'
                }}>
                  {JSON.stringify(details.evidence?.headers || {}, null, 2)}
                </pre>
              </div>
            )}

            {/* TAB CONTENT: RELAY & HOP TRACE */}
            {activeTab === 'RELAY' && (
              <div className="glass-panel">
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Relay Hop Sequence Reconstruction</h3>
                {details.relay_hops?.length === 0 ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No intermediate Received headers detected.</div>
                ) : (
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Hop</th>
                        <th>IP Address</th>
                        <th>From Host</th>
                        <th>By Host</th>
                        <th>Public</th>
                      </tr>
                    </thead>
                    <tbody>
                      {details.relay_hops?.map((h) => (
                        <tr key={h.order}>
                          <td className="font-mono">#{h.order}</td>
                          <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{h.ip || 'Hidden'}</td>
                          <td>{h.from_host || 'N/A'}</td>
                          <td>{h.by_host || 'N/A'}</td>
                          <td>
                            <span className={`badge ${h.is_public ? 'badge-safe' : 'badge-warn'}`}>
                              {h.is_public ? 'PUBLIC' : 'INTERNAL'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB CONTENT: INFRASTRUCTURE & ORIGIN */}
            {activeTab === 'ORIGIN' && (
              <div className="glass-panel">
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>
                  Probable Observable Infrastructure (Never "Hacker Exact Location")
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', fontSize: '0.82rem' }}>
                  <div>Earliest Public IP: <strong>{details.origin_assessment?.earliest_observable_ip || 'N/A'}</strong></div>
                  <div>Observable Country: <strong>{details.origin_assessment?.country || 'UNKNOWN'}</strong></div>
                  <div>Autonomous System: <strong>{details.origin_assessment?.asn || 'UNKNOWN'} ({details.origin_assessment?.asn_org || 'N/A'})</strong></div>
                  <div>Infrastructure Confidence: <strong>{Math.round(details.origin_assessment?.confidence_score || 40)}%</strong></div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: URLS */}
            {activeTab === 'URLS' && (
              <div className="glass-panel">
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Extracted URLs & Link Analysis</h3>
                {details.evidence?.urls?.length === 0 ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No hyperlinks detected in email payload.</div>
                ) : (
                  <ul style={{ paddingLeft: '1.2rem', fontSize: '0.8rem', lineHeight: '1.6' }}>
                    {details.evidence?.urls?.map((u, i) => (
                      <li key={i} style={{ wordBreak: 'break-all' }}>
                        <span style={{ color: 'var(--accent-cyan)' }}>{u.url || u}</span>
                        {u.visible_text && <span style={{ color: 'var(--text-muted)', marginLeft: '0.5rem' }}>[Text: {u.visible_text}]</span>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {/* TAB CONTENT: ATTACHMENTS */}
            {activeTab === 'ATTACHMENTS' && (
              <div className="glass-panel">
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Attached File Forensics</h3>
                {details.evidence?.attachments?.length === 0 ? (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No file attachments present in message.</div>
                ) : (
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Filename</th>
                        <th>MIME Type</th>
                        <th>Size</th>
                        <th>SHA-256 Hash</th>
                      </tr>
                    </thead>
                    <tbody>
                      {details.evidence?.attachments?.map((a, i) => (
                        <tr key={i}>
                          <td>{a.filename}</td>
                          <td className="font-mono">{a.content_type}</td>
                          <td>{Math.round((a.size_bytes || 0) / 1024)} KB</td>
                          <td className="font-mono" style={{ fontSize: '0.7rem' }}>{a.sha256 || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB CONTENT: IDENTITY */}
            {activeTab === 'IDENTITY' && (
              <div className="glass-panel">
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Identity & Header Consistency</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.82rem' }}>
                  <div>Sender Display Name: <strong>{details.sender_display_name || '(None)'}</strong></div>
                  <div>Envelope From: <strong>{details.mail_from}</strong></div>
                  <div>Reply-To: <strong>{details.reply_to || '(None)'}</strong></div>
                  <div>Return-Path: <strong>{details.return_path || '(None)'}</strong></div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
