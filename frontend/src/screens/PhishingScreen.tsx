import React, { useState } from 'react'
import { api, type PhishingCheckResult } from '../api/client'

export const PhishingScreen: React.FC = () => {
  const [text, setText] = useState<string>('')
  const [sender, setSender] = useState<string>('security-update@fakelogin-clinic.org')
  const [userId, setUserId] = useState<string>('priya.rec')
  const [loading, setLoading] = useState<boolean>(false)
  const [result, setResult] = useState<PhishingCheckResult | null>(null)
  const [error, setError] = useState<string>('')

  const handleCheck = async () => {
    if (!text.trim()) return
    setLoading(true)
    setError('')
    try {
      const res = await api.checkPhishing(text, sender, undefined, userId)
      setResult(res)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const loadSample = (sampleType: 'phish' | 'safe') => {
    if (sampleType === 'phish') {
      setText(
        'URGENT: Your clinic account has been suspended due to suspicious activity. ' +
          'Click here to verify credentials immediately: https://fakelogin-clinic-portal.org/login ' +
          'Failure to act within 24 hours will result in permanent termination of access.'
      )
      setSender('account-security@fakelogin-clinic-portal.org')
    } else {
      setText(
        'Hi team, please find attached the updated clinic roster for next week. ' +
          'Let me know if you need to trade shifts before Friday afternoon.'
      )
      setSender('clinic.manager@clinic.org')
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
        <div style={{ marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: '#e8edf8' }}>Phishing & Malicious Message Scanner</h3>
          <p style={{ margin: '4px 0 0 0', fontSize: 13, color: '#8491aa' }}>
            Analyzes raw email text, headers, and hyperlinks using the heuristic scoring engine (W1 lookalike regexes,
            urgency cues, and credential requests). Results are ingested as telemetry events.
          </p>
        </div>

        {/* Quick sample buttons */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
          <span style={{ fontSize: 12, color: '#8491aa', alignSelf: 'center' }}>Test Samples:</span>
          <button
            onClick={() => loadSample('phish')}
            style={{
              background: '#3d1c1c',
              color: '#ff8b8b',
              border: '1px solid #733030',
              borderRadius: 6,
              padding: '4px 10px',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            Load Phishing Sample
          </button>
          <button
            onClick={() => loadSample('safe')}
            style={{
              background: '#14382c',
              color: '#52d6a0',
              border: '1px solid #215946',
              borderRadius: 6,
              padding: '4px 10px',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            Load Benign Sample
          </button>
        </div>

        {/* Input Fields */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: 12, color: '#8491aa', marginBottom: 4 }}>
              Sender Email Address
            </label>
            <input
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: '#0b1020',
                color: '#e8edf8',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 10px',
                fontSize: 13,
              }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 12, color: '#8491aa', marginBottom: 4 }}>
              Recipient User ID
            </label>
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: '#0b1020',
                color: '#e8edf8',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 10px',
                fontSize: 13,
              }}
            />
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 12, color: '#8491aa', marginBottom: 4 }}>
            Message Body or URL
          </label>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={5}
            placeholder="Paste raw email body, suspicious URL, or message text here..."
            style={{
              width: '100%',
              boxSizing: 'border-box',
              background: '#0b1020',
              color: '#e8edf8',
              border: '1px solid #3b4965',
              borderRadius: 6,
              padding: '10px',
              fontSize: 13,
              resize: 'vertical',
            }}
          />
        </div>

        <button
          onClick={handleCheck}
          disabled={loading || !text.trim()}
          style={{
            background: '#6679ef',
            color: '#ffffff',
            border: 0,
            borderRadius: 6,
            padding: '10px 20px',
            fontSize: 14,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          {loading ? 'Evaluating Scorer...' : 'Check Phishing Risk →'}
        </button>

        {error && (
          <div style={{ marginTop: 16, padding: 12, background: '#4a1515', color: '#ff7e86', borderRadius: 8, fontSize: 13 }}>
            {error}
          </div>
        )}

        {/* Results Card */}
        {result && (
          <div
            style={{
              marginTop: 20,
              background: '#0b1020',
              border: `1px solid ${
                result.verdict === 'red'
                  ? '#ff7e86'
                  : result.verdict === 'amber'
                    ? '#f5bd67'
                    : '#52d6a0'
              }`,
              borderRadius: 10,
              padding: 18,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span
                  style={{
                    fontSize: 14,
                    fontWeight: 700,
                    padding: '4px 12px',
                    borderRadius: 20,
                    background:
                      result.verdict === 'red'
                        ? '#4a1515'
                        : result.verdict === 'amber'
                          ? '#3d3016'
                          : '#14382c',
                    color:
                      result.verdict === 'red'
                        ? '#ff7e86'
                        : result.verdict === 'amber'
                          ? '#f5bd67'
                          : '#52d6a0',
                  }}
                >
                  {result.verdict === 'red' ? '🔴 RED: HIGH RISK' : result.verdict === 'amber' ? '🟡 AMBER: SUSPICIOUS' : '🟢 GREEN: LOW RISK'}
                </span>
                <span style={{ fontSize: 13, color: '#e8edf8' }}>
                  Risk Score: <strong>{result.score} / 100</strong>
                </span>
              </div>
              <span style={{ fontSize: 11, color: '#8491aa', fontFamily: 'monospace' }}>
                Ingested Event: {result.event_id}
              </span>
            </div>

            {/* Reasons list */}
            {result.reasons && result.reasons.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <strong style={{ fontSize: 13, color: '#8b9cff' }}>Indicators Identified:</strong>
                <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {result.reasons.map((r, i) => (
                    <div
                      key={i}
                      style={{
                        background: '#131c30',
                        padding: '8px 12px',
                        borderRadius: 6,
                        borderLeft: '3px solid #8b9cff',
                        fontSize: 12,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                        <span style={{ fontWeight: 600, color: '#e8edf8' }}>{r.text}</span>
                        <code style={{ color: '#8b9cff' }}>{r.code}</code>
                      </div>
                      {r.snippet && (
                        <div style={{ color: '#8491aa', fontFamily: 'monospace', fontSize: 11, marginTop: 4 }}>
                          "{r.snippet}"
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <p style={{ margin: 0, fontSize: 12, color: '#f5bd67', lineHeight: 1.4 }}>
              Notice: This heuristic scan detects known threat indicators. A green verdict does NOT guarantee a message
              is harmless. Always follow clinic protocol for unexpected requests.
            </p>
          </div>
        )}
      </section>
    </div>
  )
}

