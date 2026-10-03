import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  Inbox, 
  Search, 
  ClipboardCheck, 
  Network, 
  Database, 
  FileText, 
  FileCheck2, 
  Radio, 
  Settings 
} from 'lucide-react';

export default function Sidebar() {
  const navItems = [
    { name: 'SOC Dashboard', path: '/', icon: ShieldAlert },
    { name: 'Security Inbox', path: '/inbox', icon: Inbox },
    { name: 'Investigations', path: '/investigations', icon: Search },
    { name: 'Review Queue', path: '/review-queue', icon: ClipboardCheck },
    { name: 'Campaign Intel', path: '/campaigns', icon: Network },
    { name: 'Threat Intel & IOCs', path: '/threat-intel', icon: Database },
    { name: 'Weekly Reports', path: '/reports', icon: FileText },
    { name: 'Tamper Audit Chain', path: '/audit', icon: FileCheck2 },
    { name: 'Mail Connectors', path: '/connections', icon: Radio },
    { name: 'System Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside style={{
      width: '260px',
      backgroundColor: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border-color)',
      position: 'fixed',
      top: 0,
      left: 0,
      bottom: 0,
      display: 'flex',
      flexDirection: 'column',
      zIndex: 100
    }}>
      {/* Brand Header */}
      <div style={{
        padding: '1.5rem',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem'
      }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '8px',
          background: 'linear-gradient(135deg, #00f2fe 0%, #4facfe 100%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 16px rgba(0, 242, 254, 0.4)'
        }}>
          <ShieldAlert size={20} color="#030a16" />
        </div>
        <div>
          <h1 style={{ fontSize: '1.15rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
            TRACEMAIL <span style={{ color: 'var(--accent-cyan)' }}>AI</span>
          </h1>
          <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            RESEARCH FORENSIC PROXY v2.0
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={{ flex: 1, padding: '1rem 0.75rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.7rem 0.9rem',
                borderRadius: 'var(--radius-sm)',
                textDecoration: 'none',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                backgroundColor: isActive ? 'rgba(0, 242, 254, 0.08)' : 'transparent',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.85rem',
                transition: 'all 0.15s ease',
                borderLeft: isActive ? '3px solid var(--accent-cyan)' : '3px solid transparent'
              })}
            >
              <Icon size={18} />
              <span>{item.name}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Footer Gateway Status */}
      <div style={{
        padding: '1rem 1.25rem',
        borderTop: '1px solid var(--border-color)',
        backgroundColor: 'rgba(10, 13, 20, 0.5)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>SMTP PROXY</span>
          <span className="badge badge-safe" style={{ fontSize: '0.65rem', padding: '0.15rem 0.45rem' }}>PORT 1025</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--status-safe)' }}>
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--status-safe)' }}></span>
          <span>Inspection & Flagging Active</span>
        </div>
      </div>
    </aside>
  );
}
