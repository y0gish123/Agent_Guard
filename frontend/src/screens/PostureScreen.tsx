import { useEffect, useState } from 'react'
import { api } from '../api/client'

interface PostureCheck {
  name: string
  status: 'pass' | 'warn' | 'fail' | 'unknown'
  evidence: string
  checked_at: string
  recommendation: string
}

interface PostureData {
  overall: 'pass' | 'warn' | 'fail' | 'unknown'
  summary: { pass: number; warn: number; fail: number; unknown: number }
  checks: PostureCheck[]
  site_url: string
  note: string
}

const STATUS_COLOR: Record<string, string> = {
  pass: '#52d6a0',
  warn: '#f59e0b',
  fail: '#f87171',
  unknown: '#8491aa',
}
const STATUS_ICON: Record<string, string> = {
  pass: '✓',
  warn: '⚠',
  fail: '✗',
  unknown: '?',
}

function CheckRow({ check }: { check: PostureCheck }) {
  const [expanded, setExpanded] = useState(false)
  const color = STATUS_COLOR[check.status] ?? STATUS_COLOR.unknown
  const icon = STATUS_ICON[check.status] ?? '?'
  return (
    <div
      style={{
        marginBottom: 10,
        border: `1px solid #263149`,
        borderLeft: `3px solid ${color}`,
        borderRadius: 8,
        background: '#10172a',
        overflow: 'hidden',
      }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          width: '100%',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          border: 0,
          background: 'transparent',
          color: '#e8edf8',
          cursor: 'pointer',
          textAlign: 'left',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ color, fontWeight: 700, fontSize: 16, minWidth: 18 }}>{icon}</span>
          <span style={{ fontWeight: 600, fontSize: 14 }}>{check.name}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              textTransform: 'uppercase',
              color,
              background: `${color}22`,
              padding: '2px 8px',
              borderRadius: 4,
            }}
          >
            {check.status}
          </span>
          <span style={{ color: '#8491aa', fontSize: 12 }}>{expanded ? '▲' : '▼'}</span>
        </div>
      </button>
      {expanded && (
        <div style={{ padding: '0 16px 14px', borderTop: '1px solid #263149', marginTop: 0 }}>
          <div style={{ marginTop: 10, fontSize: 13, color: '#b0b8cc', lineHeight: 1.6 }}>
            <strong style={{ color: '#e8edf8' }}>Evidence: </strong>
            {/* evidence is bounded server-side to 500 chars */}
            {check.evidence}
          </div>
          {check.recommendation && (
            <div style={{ marginTop: 8, fontSize: 12, color: '#f59e0b' }}>
              <strong>Recommendation: </strong>
              {check.recommendation}
            </div>
          )}
          <div style={{ marginTop: 6, fontSize: 11, color: '#556078' }}>
            Checked: {check.checked_at}
          </div>
        </div>
      )}
    </div>
  )
}

export function PostureScreen() {
  const [data, setData] = useState<PostureData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    api
      .getPosture()
      .then((d) => {
        setData(d as PostureData)
        setLoading(false)
      })
      .catch(() => {
        setError('Could not load posture data. Is the backend running?')
        setLoading(false)
      })
  }, [])

  return (
    <div>
      <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Security Posture</h2>
      <p style={{ color: '#8491aa', fontSize: 13, marginBottom: 24 }}>
        SIMULATION — checks inspect only this machine and the configured localhost site.
      </p>

      {loading && <div style={{ color: '#8491aa' }}>Loading posture checks…</div>}

      {error && (
        <div style={{ color: '#f87171', padding: 16, background: '#1a0e0e', borderRadius: 8 }}>
          {error}
        </div>
      )}

      {data && (
        <>
          {/* Overall summary row */}
          <div
            style={{
              display: 'flex',
              gap: 16,
              marginBottom: 28,
              flexWrap: 'wrap',
            }}
          >
            {(['pass', 'warn', 'fail', 'unknown'] as const).map((s) => (
              <div
                key={s}
                style={{
                  padding: '12px 20px',
                  background: '#10172a',
                  border: `1px solid ${STATUS_COLOR[s]}44`,
                  borderRadius: 10,
                  textAlign: 'center',
                  minWidth: 90,
                }}
              >
                <div style={{ fontSize: 24, color: STATUS_COLOR[s], fontWeight: 700 }}>
                  {data.summary[s]}
                </div>
                <div style={{ fontSize: 11, color: '#8491aa', textTransform: 'uppercase', marginTop: 2 }}>
                  {s}
                </div>
              </div>
            ))}
          </div>

          {/* Checks list */}
          {data.checks.map((c, i) => (
            <CheckRow key={i} check={c} />
          ))}

          <div
            style={{
              marginTop: 20,
              fontSize: 12,
              color: '#556078',
              padding: '10px 14px',
              background: '#10172a',
              borderRadius: 6,
              border: '1px solid #263149',
            }}
          >
            {data.note}
          </div>
        </>
      )}
    </div>
  )
}

