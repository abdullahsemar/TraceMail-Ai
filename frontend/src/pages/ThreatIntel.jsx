import React, { useEffect, useState } from 'react';
import { Database, ShieldAlert, Globe, Search } from 'lucide-react';
import { fetchIocs } from '../services/api';

export default function ThreatIntel() {
  const [iocs, setIocs] = useState([]);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetchIocs().then(setIocs).catch(console.error);
  }, []);

  const filtered = iocs.filter(i => 
    i.value.toLowerCase().includes(filter.toLowerCase()) || 
    i.type.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.25rem' }}>
            Threat Intelligence & IOC Feeds
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Observable indicators of compromise (IP, Domain, URL) extracted during pre-delivery forensic analysis.
          </p>
        </div>
        <div style={{ position: 'relative', width: '280px' }}>
          <input
            type="text"
            placeholder="Search IOC value or type..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              width: '100%',
              padding: '0.55rem 0.85rem',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-primary)',
              fontSize: '0.85rem'
            }}
          />
        </div>
      </div>

      <div className="glass-panel">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>IOC Type</th>
              <th>Indicator Value</th>
              <th>Reputation State</th>
              <th>Extracted At</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc) => (
              <tr key={ioc.id}>
                <td>
                  <span className="badge badge-warn" style={{ fontSize: '0.7rem' }}>
                    {ioc.type}
                  </span>
                </td>
                <td className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                  {ioc.value}
                </td>
                <td>
                  <span className={`badge badge-${ioc.reputation === 'KNOWN_BAD' ? 'critical' : (ioc.reputation === 'KNOWN_GOOD' ? 'safe' : 'warn')}`}>
                    {ioc.reputation}
                  </span>
                </td>
                <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {ioc.created_at}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
