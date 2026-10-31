import React from 'react'
import type { ConnectionStatus } from '../hooks/useLiveUpdates'

interface HeaderProps {
  connectionStatus: ConnectionStatus
  userRole: 'staff' | 'approver'
  setUserRole: (role: 'staff' | 'approver') => void
  currentLang: string
  setCurrentLang: (lang: string) => void
  allowUnreviewedLangs: boolean
  demoMode: string
  onToggleDemoTools: () => void
}

export const Header: React.FC<HeaderProps> = ({
  connectionStatus,
  userRole,
  setUserRole,
  currentLang,
  setCurrentLang,
  allowUnreviewedLangs,
  demoMode,
  onToggleDemoTools,
}) => {
  return (
    <header
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: '#10172a',
        borderBottom: '1px solid #263149',
        padding: '12px 24px',
        color: '#e8edf8',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 22, color: '#8b9cff' }}>◈</span>
          <strong style={{ fontSize: 18, letterSpacing: 0.5 }}>AgentGuard</strong>
          <span style={{ fontSize: 11, background: '#1c2941', color: '#8b96ad', padding: '2px 8px', borderRadius: 12 }}>
            AI SOC
          </span>
        </div>

        {/* Live / Polling badge */}
        <span
          style={{
            fontSize: 12,
            padding: '3px 10px',
            borderRadius: 12,
            background: connectionStatus === 'live' ? '#14382c' : '#3d3016',
            color: connectionStatus === 'live' ? '#52d6a0' : '#f5bd67',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
          title={connectionStatus === 'live' ? 'Connected to SSE real-time stream' : 'Falling back to 5s polling'}
        >
          <span style={{ fontSize: 10 }}>●</span>
          {connectionStatus === 'live' ? 'LIVE' : 'POLLING'}
        </span>

        {/* Mode badge */}
        <span
          style={{
            fontSize: 11,
            padding: '3px 8px',
            borderRadius: 6,
            background: demoMode === 'naive' ? '#4a1515' : '#1e2d4d',
            color: demoMode === 'naive' ? '#ff7e86' : '#8b9cff',
            fontWeight: 600,
          }}
        >
          {demoMode.toUpperCase()} MODE
        </span>
      </div>

      {/* Controls & Nav */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {/* Role Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
          <span style={{ color: '#8491aa' }}>Role:</span>
          <select
            value={userRole}
            onChange={(e) => setUserRole(e.target.value as 'staff' | 'approver')}
            style={{
              background: '#0b1020',
              color: '#e8edf8',
              border: '1px solid #3b4965',
              borderRadius: 6,
              padding: '4px 8px',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            <option value="staff">Staff (Analyst)</option>
            <option value="approver">Approver (Lead)</option>
          </select>
        </div>

        {/* Language Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
          <span style={{ color: '#8491aa' }}>Lang:</span>
          <select
            value={currentLang}
            onChange={(e) => setCurrentLang(e.target.value)}
            style={{
              background: '#0b1020',
              color: '#e8edf8',
              border: '1px solid #3b4965',
              borderRadius: 6,
              padding: '4px 8px',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            <option value="en">English (EN)</option>
            <option value="hi" disabled={!allowUnreviewedLangs}>
              Hindi (HI) {!allowUnreviewedLangs ? '(Locked)' : ''}
            </option>
            <option value="kn" disabled={!allowUnreviewedLangs}>
              Kannada (KN) {!allowUnreviewedLangs ? '(Locked)' : ''}
            </option>
          </select>
        </div>

        {/* Demo Tools Button */}
        <button
          onClick={onToggleDemoTools}
          style={{
            background: '#27365b',
            color: '#b8c5ff',
            border: '1px solid #3b4965',
            borderRadius: 6,
            padding: '5px 12px',
            fontSize: 13,
            cursor: 'pointer',
            fontWeight: 600,
          }}
        >
          ⚙ Demo Tools
        </button>
      </div>
    </header>
  )
}
