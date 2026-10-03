import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Inbox from './pages/Inbox';
import Investigations from './pages/Investigations';
import ReviewQueue from './pages/ReviewQueue';
import Campaigns from './pages/Campaigns';
import ThreatIntel from './pages/ThreatIntel';
import Reports from './pages/Reports';
import AuditTrail from './pages/AuditTrail';
import Connections from './pages/Connections';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-container">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/inbox" element={<Inbox />} />
            <Route path="/monitor" element={<Inbox />} />
            <Route path="/investigations" element={<Investigations />} />
            <Route path="/review-queue" element={<ReviewQueue />} />
            <Route path="/quarantine" element={<Navigate to="/review-queue" replace />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/audit" element={<AuditTrail />} />
            <Route path="/connections" element={<Connections />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
