import React, { useEffect, useState } from 'react'
import { api, type AuditRecord, type AuditVerifyResult } from '../api/client'

export const AuditScreen: React.FC = () => {
  const [records, setRecords] = useState<AuditRecord[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string>('')
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null)
  const [verifying, setVerifying] = useState<boolean>(false)

  const loadAudit = async () => {
    setLoading(true)
    setError('')
    try {
      const data = await api.getAudit()
      setRecords(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAudit()
  }, [])

  const handleVerify = async () => {
    setVerifying(true)
    try {
      const res = await api.verifyAudit()
      setVerifyResult(res)
    } catch (err: unknown) {
      setVerifyResult({
        valid: false,
        total_events: records.length,
        message: err instanceof Error ? err.message : String(err),
      })
    } finally {
      setVerifying(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <section
        style={{
          background: '#131c30',
          border: '1px solid #263149',
          borderRadius: 14,
          padding: 22,
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 12,
            marginBottom: 16,
          }}
        >
          <div>
            <h3 style={{ margin: 0, color: '#e8edf8' }}>Cryptographic Tamper-Evident Audit Trail</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 13, color: '#8491aa' }}>
              Every policy evaluation, approval decision, and execution event is committed to a hash-linked audit chain
              (SHA-256). Any modification breaks the chain.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button
              onClick={handleVerify}
              disabled={verifying}
              style={{
                background: '#27365b',
                color: '#b8c5ff',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 16px',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {verifying ? 'Verifying Hash Chain...' : 'Verify Hash Chain 🛡'}
            </button>
            <button
              onClick={loadAudit}
              style={{
                background: 'transparent',
                color: '#8491aa',
                border: '1px solid #263149',
                borderRadius: 6,
                padding: '8px 12px',
                fontSize: 13,
                cursor: 'pointer',
              }}
            >
              ↻ Refresh
            </button>
          </div>
        </div>

        {/* Verification Result Badge */}
        {verifyResult && (
          <div
            style={{
              padding: '12px 16px',
              borderRadius: 8,
              marginBottom: 16,
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              background: verifyResult.valid ? '#14382c' : '#4a1515',
              border: `1px solid ${verifyResult.valid ? '#52d6a0' : '#ff7e86'}`,
            }}
          >
            <span style={{ fontSize: 20 }}>{verifyResult.valid ? '✅' : '❌'}</span>
            <div>
              <strong style={{ color: '#e8edf8', fontSize: 14 }}>
                {verifyResult.valid
                  ? `Verified Hash Chain Integrity (${verifyResult.total_events} blocks valid)`
                  : `Tamper Detected at Block Sequence ${verifyResult.error_at_sequence ?? 'unknown'}`}
              </strong>
              <p style={{ margin: '2px 0 0 0', fontSize: 12, color: '#a4afc5' }}>
                {verifyResult.message}
              </p>
            </div>
          </div>
        )}

        {error && (
          <div style={{ padding: 12, background: '#4a1515', color: '#ff7e86', borderRadius: 8, fontSize: 13, marginBottom: 16 }}>
            {error}
          </div>
        )}

        {/* Audit Table */}
        {loading ? (
          <div style={{ color: '#8491aa', fontSize: 13, padding: 24, textAlign: 'center' }}>
            Loading audit records...
          </div>
        ) : records.length === 0 ? (
          <div style={{ color: '#8491aa', fontSize: 13, padding: 24, textAlign: 'center' }}>
            No audit records yet. Run an incident investigation or action to generate audit events.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #263149', color: '#8491aa' }}>
                  <th style={{ padding: '8px 10px' }}>Seq #</th>
                  <th style={{ padding: '8px 10px' }}>Timestamp (UTC)</th>
                  <th style={{ padding: '8px 10px' }}>Actor</th>
                  <th style={{ padding: '8px 10px' }}>Event Type</th>
                  <th style={{ padding: '8px 10px' }}>Incident / Response</th>
                  <th style={{ padding: '8px 10px' }}>Block Hash (SHA-256)</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.sequence_no} style={{ borderBottom: '1px solid #1c2941' }}>
                    <td style={{ padding: '10px', fontWeight: 700, color: '#8b9cff' }}>
                      #{r.sequence_no}
                    </td>
                    <td style={{ padding: '10px', color: '#8491aa' }}>
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '10px', color: '#e8edf8', fontWeight: 600 }}>
                      {r.actor}
                    </td>
                    <td style={{ padding: '10px' }}>
                      <span
                        style={{
                          background: '#1c2941',
                          color: '#52d6a0',
                          padding: '2px 6px',
                          borderRadius: 4,
                          fontSize: 11,
                        }}
                      >
                        {r.event_type}
                      </span>
                    </td>
                    <td style={{ padding: '10px', color: '#a4afc5', fontFamily: 'monospace' }}>
                      {r.incident_id || '—'}{' '}
                      {r.response_id ? <span style={{ color: '#8491aa' }}>({r.response_id})</span> : ''}
                    </td>
                    <td
                      style={{
                        padding: '10px',
                        fontFamily: 'monospace',
                        color: '#b8c5ff',
                        fontSize: 11,
                      }}
                    >
                      {r.event_hash ? `${r.event_hash.slice(0, 16)}...` : 'genesis'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

