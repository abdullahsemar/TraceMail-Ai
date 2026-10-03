import React, { useEffect, useState } from 'react';
import { FileText, Download, Play, CheckCircle2, Calendar } from 'lucide-react';
import { fetchReports, generateReport } from '../services/api';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [generating, setGenerating] = useState(false);
  const [msg, setMsg] = useState(null);

  const loadData = async () => {
    try {
      const data = await fetchReports();
      setReports(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    setMsg(null);
    try {
      const res = await generateReport();
      setMsg(`Report generated successfully: ${res.filename}`);
      loadData();
    } catch (e) {
      setMsg(`Generation failed: ${e.message}`);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            Weekly Email Security Intelligence Reports
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Executive summaries, defensive action metrics, and forensic incident breakdowns generated in DOCX format.
          </p>
        </div>

        <button 
          className="btn-cyber" 
          disabled={generating}
          onClick={handleGenerate}
        >
          <Play size={16} />
          <span>{generating ? 'Generating DOCX...' : 'Generate Weekly Report'}</span>
        </button>
      </div>

      {msg && (
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
          <CheckCircle2 size={16} color="var(--accent-cyan)" />
          <span>{msg}</span>
        </div>
      )}

      <div className="glass-panel">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Report Title</th>
              <th>Period</th>
              <th>Total Analyzed</th>
              <th>Quarantined</th>
              <th>BEC Threats</th>
              <th>Created At</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td style={{ fontWeight: 600 }}>{r.title}</td>
                <td className="font-mono" style={{ fontSize: '0.75rem' }}>
                  {r.period_start.split('T')[0]} &rarr; {r.period_end.split('T')[0]}
                </td>
                <td>{r.stats?.total_emails ?? 0}</td>
                <td>
                  <span className="badge badge-critical">{r.stats?.quarantined ?? 0}</span>
                </td>
                <td>
                  <span className="badge badge-warn">{r.stats?.bec ?? 0}</span>
                </td>
                <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {r.created_at.split('T')[0]}
                </td>
                <td>
                  <a
                    href={`http://localhost:8000/api/reports/${r.id}/download`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-secondary"
                    style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', textDecoration: 'none' }}
                  >
                    <Download size={14} />
                    <span>Download DOCX</span>
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
