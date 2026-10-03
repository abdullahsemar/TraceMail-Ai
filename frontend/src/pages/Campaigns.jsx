import React, { useEffect, useState } from 'react';
import { Network, GitFork, Shield, AlertTriangle, Layers } from 'lucide-react';
import { fetchCampaigns } from '../services/api';

export default function Campaigns() {
  const [campaigns, setCampaigns] = useState([]);

  useEffect(() => {
    fetchCampaigns().then(setCampaigns).catch(console.error);
  }, []);

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
          Campaign Correlation & Infrastructure Clustering
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
          Graph-correlated threat campaigns sharing domains, lookalikes, reply-to vectors, and ASN infrastructure.
        </p>
      </div>

      {campaigns.length === 0 ? (
        <div className="glass-panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          <Network size={36} color="var(--accent-purple)" style={{ margin: '0 auto 0.75rem auto', display: 'block' }} />
          No multi-incident campaign clusters correlated yet. Correlator clusters recurring attacks automatically.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem' }}>
          {campaigns.map((c) => (
            <div key={c.id} className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
                    CAMPAIGN CLUSTER
                  </span>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 700, marginTop: '0.2rem' }}>{c.name}</h2>
                </div>
                <span className="badge badge-critical">{c.total_incidents} INCIDENTS</span>
              </div>

              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{c.description}</p>

              <div style={{ background: 'rgba(15, 21, 35, 0.6)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem' }}>
                <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <GitFork size={14} color="var(--accent-cyan)" />
                  <span>Correlated Graph Links</span>
                </div>
                {c.links && c.links.length > 0 ? (
                  <ul style={{ paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                    {c.links.map((l, idx) => (
                      <li key={idx} className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--accent-cyan)' }}>{l.source}</span> &rarr; <span style={{ color: 'var(--status-warn)' }}>{l.target}</span> ({l.type})
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>Clustered via shared threat attributes</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
