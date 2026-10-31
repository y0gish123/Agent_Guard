import React, { useEffect, useState } from 'react'
import { api, type ToolState } from '../api/client'

interface DemoToolsModalProps {
  isOpen: boolean
  onClose: () => void
  onRefreshData: () => void
}

export const DemoToolsModal: React.FC<DemoToolsModalProps> = ({ isOpen, onClose, onRefreshData }) => {
  const [toolState, setToolState] = useState<ToolState | null>(null)
  const [message, setMessage] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)

  const loadToolState = async () => {
    try {
      const state = await api.getToolState()
      setToolState(state)
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    if (isOpen) {
      loadToolState()
    }
  }, [isOpen])

  if (!isOpen) return null

  const handleSeed = async (scenario: 'account' | 'filebursts' | 'poisoned' | 'all') => {
    setLoading(true)
    setMessage('')
    try {
      const res = await api.seedDemo(scenario)
      setMessage(`Seeded scenario: ${scenario}. ${res.message || ''}`)
      await loadToolState()
      onRefreshData()
    } catch (err: unknown) {
      setMessage(`Seed error: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setLoading(false)
    }
  }

  const handleReset = async () => {
    setLoading(true)
    setMessage('')
    try {
      const res = await api.resetDemo()
      setMessage(`Reset completed: ${res.message || ''}`)
      await loadToolState()
      onRefreshData()
    } catch (err: unknown) {
      setMessage(`Reset error: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
      }}
    >
      <div
        style={{
          background: '#131c30',
          border: '1px solid #263149',
          borderRadius: 12,
          padding: 24,
          maxWidth: 600,
          width: '90%',
          color: '#e8edf8',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: '#8b9cff' }}>⚙ Demo Tools & Test Environment State</h3>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 0,
              color: '#8491aa',
              fontSize: 18,
              cursor: 'pointer',
            }}
          >
            ✕
          </button>
        </div>

        <p style={{ fontSize: 13, color: '#8491aa', marginBottom: 16 }}>
          Quickly inject simulated scenarios through the ingestion pipeline or reset the mock tool state.
        </p>

        {/* Seed Scenarios */}
        <div style={{ marginBottom: 20 }}>
          <strong style={{ fontSize: 14 }}>Seed Simulated Scenarios:</strong>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 10 }}>
            <button
              onClick={() => handleSeed('account')}
              disabled={loading}
              style={{
                background: '#27365b',
                color: '#b8c5ff',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 12px',
                cursor: 'pointer',
                fontSize: 13,
              }}
            >
              Account Takeover
            </button>
            <button
              onClick={() => handleSeed('filebursts')}
              disabled={loading}
              style={{
                background: '#27365b',
                color: '#b8c5ff',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 12px',
                cursor: 'pointer',
                fontSize: 13,
              }}
            >
              Ransomware Burst
            </button>
            <button
              onClick={() => handleSeed('poisoned')}
              disabled={loading}
              style={{
                background: '#27365b',
                color: '#b8c5ff',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 12px',
                cursor: 'pointer',
                fontSize: 13,
              }}
            >
              Poisoned / Injection
            </button>
            <button
              onClick={() => handleSeed('all')}
              disabled={loading}
              style={{
                background: '#34457a',
                color: '#ffffff',
                border: '1px solid #4f68b3',
                borderRadius: 6,
                padding: '8px 12px',
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              Seed All Scenarios
            </button>
            <button
              onClick={handleReset}
              disabled={loading}
              style={{
                background: '#4a1e1e',
                color: '#ff8b8b',
                border: '1px solid #733030',
                borderRadius: 6,
                padding: '8px 12px',
                cursor: 'pointer',
                fontSize: 13,
              }}
            >
              Reset Environment
            </button>
          </div>
        </div>

        {message && (
          <div
            style={{
              padding: 10,
              background: '#1c2941',
              borderRadius: 6,
              fontSize: 13,
              color: '#52d6a0',
              marginBottom: 16,
            }}
          >
            {message}
          </div>
        )}

        {/* Mock Tool Live State */}
        <div style={{ background: '#0b1020', padding: 14, borderRadius: 8, border: '1px solid #263149' }}>
          <strong style={{ fontSize: 13, color: '#8b9cff' }}>Mock Tool / Enforcement State (Port 8001):</strong>
          <div style={{ marginTop: 8, fontSize: 12, color: '#a4afc5' }}>
            <div>
              <strong>Locked Accounts:</strong>{' '}
              {toolState?.locked_accounts?.length ? toolState.locked_accounts.join(', ') : 'None'}
            </div>
            <div style={{ marginTop: 4 }}>
              <strong>Isolated Hosts:</strong>{' '}
              {toolState?.isolated_hosts?.length ? toolState.isolated_hosts.join(', ') : 'None'}
            </div>
            <div style={{ marginTop: 4 }}>
              <strong>Revoked Sessions:</strong>{' '}
              {toolState?.revoked_sessions?.length ? toolState.revoked_sessions.join(', ') : 'None'}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

