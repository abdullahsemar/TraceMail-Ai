import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function ScoreGauge({ value, label, size = 'md' }) {
  const numValue = Number(value) || 0;
  
  let color = 'var(--status-safe)';
  if (numValue >= 80) color = 'var(--status-critical)';
  else if (numValue >= 60) color = 'var(--status-high)';
  else if (numValue >= 30) color = 'var(--status-warn)';

  const dimension = size === 'lg' ? 120 : 80;
  const strokeWidth = size === 'lg' ? 8 : 6;
  const radius = (dimension - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (numValue / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.4rem' }}>
      <div style={{ position: 'relative', width: dimension, height: dimension }}>
        <svg width={dimension} height={dimension} style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx={dimension / 2}
            cy={dimension / 2}
            r={radius}
            stroke="var(--border-color)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          <circle
            cx={dimension / 2}
            cy={dimension / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
        </svg>
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'var(--font-mono)'
        }}>
          <span style={{ fontSize: size === 'lg' ? '1.5rem' : '1.1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            {Math.round(numValue)}
          </span>
          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>/100</span>
        </div>
      </div>
      {label && (
        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {label}
        </span>
      )}
    </div>
  );
}
