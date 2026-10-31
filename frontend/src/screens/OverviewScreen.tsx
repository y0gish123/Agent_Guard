import React, { useState } from 'react'
import type { FunnelData, IncidentSummary } from '../api/client'

interface OverviewScreenProps {
  funnel: FunnelData
  incidents: IncidentSummary[]
  onSelectIncident: (id: string) => void
}

export const OverviewScreen: React.FC<OverviewScreenProps> = ({ funnel, incidents, onSelectIncident }) => {
  const [categoryFilter, setCategoryFilter] = useState<string>('all')

  const filteredIncidents = incidents.filter((inc) => {
    if (categoryFilter === 'all') return true
    return inc.category === categoryFilter
  })

  const getCategoryBadge = (category: string) => {
    switch (category) {
      case 'account_takeover':
        return { label: 'Account Takeover', bg: '#233554', color: '#8b9cff' }
      case 'ransomware_like_activity':
        return { label: 'Ransomware Activity', bg: '#4a1515', color: '#ff7e86' }
      case 'web_attack':
        return { label: 'Web Attack (SQLi)', bg: '#3d2514', color: '#f5bd67' }
      case 'data_exfiltration_suspected':
        return { label: 'Data Exfiltration', bg: '#3d1633', color: '#f086ff' }
      case 'multi_stage':
        return { label: 'Multi-Stage Attack', bg: '#471b47', color: '#e585ff' }
      default:
        return { label: category, bg: '#1c2941', color: '#a4afc5' }
    }
  }

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return '#ff7e86'
      case 'high':
        return '#f5bd67'
      case 'medium':
        return '#8b9cff'
      default:
        return '#52d6a0'
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Noise Reduction Funnel */}
      <section
        style={{
          background: '#131c30',
          border: '1px solid #263149',
          borderRadius: 14,
          padding: 22,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h3 style={{ margin: 0, color: '#e8edf8' }}>Telemetry Ingestion & Noise Reduction Funnel</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 13, color: '#8491aa' }}>
              Real-time correlation reduces alert fatigue by isolating multi-signal incidents from background noise.
            </p>
          </div>
          <span style={{ fontSize: 12, color: '#52d6a0', background: '#14382c', padding: '4px 10px', borderRadius: 8 }}>
            Funnel Active
          </span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 16,
          }}
        >
          <div style={{ background: '#0b1020', border: '1px solid #263149', borderRadius: 10, padding: 16 }}>
            <span style={{ fontSize: 12, color: '#8491aa' }}>Raw Events Ingested</span>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#8b9cff', marginTop: 4 }}>
              {funnel.raw_events}
            </div>
            <span style={{ fontSize: 11, color: '#5b6a82' }}>Collector / Watcher logs</span>
          </div>

          <div style={{ background: '#0b1020', border: '1px solid #263149', borderRadius: 10, padding: 16 }}>
            <span style={{ fontSize: 12, color: '#8491aa' }}>Noise Filtered (Benign)</span>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#52d6a0', marginTop: 4 }}>
              {funnel.noise_filtered}
            </div>
            <span style={{ fontSize: 11, color: '#5b6a82' }}>Suppressed false alarms</span>
          </div>

          <div style={{ background: '#0b1020', border: '1px solid #263149', borderRadius: 10, padding: 16 }}>
            <span style={{ fontSize: 12, color: '#8491aa' }}>Candidates Evaluated</span>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#f5bd67', marginTop: 4 }}>
              {funnel.candidates}
            </div>
            <span style={{ fontSize: 11, color: '#5b6a82' }}>Rules R1-R4, F1-F3, W1-W2, D1-D2</span>
          </div>

          <div style={{ background: '#0b1020', border: '1px solid #263149', borderRadius: 10, padding: 16 }}>
            <span style={{ fontSize: 12, color: '#8491aa' }}>Actionable Incidents</span>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#ff7e86', marginTop: 4 }}>
              {funnel.incidents}
            </div>
            <span style={{ fontSize: 11, color: '#5b6a82' }}>Verified policy queue</span>
          </div>
        </div>
      </section>

      {/* Incidents Table with Filter */}
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
            <h3 style={{ margin: 0, color: '#e8edf8' }}>Security Incidents</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 13, color: '#8491aa' }}>
              Select an incident to view linked events, AI analysis, and invoke the verified policy gateway.
            </p>
          </div>

          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {[
              { id: 'all', label: 'All Incidents' },
              { id: 'account_takeover', label: 'Account Takeover' },
              { id: 'ransomware_like_activity', label: 'Ransomware' },
              { id: 'web_attack', label: 'Web Attack' },
              { id: 'data_exfiltration_suspected', label: 'Data Exfil' },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setCategoryFilter(f.id)}
                style={{
                  background: categoryFilter === f.id ? '#27365b' : '#0b1020',
                  color: categoryFilter === f.id ? '#b8c5ff' : '#8491aa',
                  border: '1px solid #3b4965',
                  borderRadius: 6,
                  padding: '5px 10px',
                  fontSize: 12,
                  cursor: 'pointer',
                  fontWeight: categoryFilter === f.id ? 600 : 400,
                }}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {filteredIncidents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '36px 0', color: '#8491aa' }}>
            No incidents found in this category. Click <strong>Demo Tools</strong> to seed scenarios.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #263149', color: '#8491aa' }}>
                  <th style={{ padding: '10px 12px' }}>Incident ID</th>
                  <th style={{ padding: '10px 12px' }}>Title</th>
                  <th style={{ padding: '10px 12px' }}>Category</th>
                  <th style={{ padding: '10px 12px' }}>Severity</th>
                  <th style={{ padding: '10px 12px' }}>Confidence</th>
                  <th style={{ padding: '10px 12px' }}>Link Rule</th>
                  <th style={{ padding: '10px 12px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.map((inc) => {
                  const badge = getCategoryBadge(inc.category)
                  return (
                    <tr
                      key={inc.incident_id}
                      style={{
                        borderBottom: '1px solid #1c2941',
                        cursor: 'pointer',
                        transition: 'background 0.15s ease',
                      }}
                      onClick={() => onSelectIncident(inc.incident_id)}
                      onMouseEnter={(e) => (e.currentTarget.style.background = '#18243c')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      <td style={{ padding: '12px', fontFamily: 'monospace', color: '#8b9cff' }}>
                        {inc.incident_id}
                      </td>
                      <td style={{ padding: '12px', fontWeight: 600, color: '#e8edf8' }}>
                        {inc.title}
                      </td>
                      <td style={{ padding: '12px' }}>
                        <span
                          style={{
                            background: badge.bg,
                            color: badge.color,
                            padding: '3px 8px',
                            borderRadius: 6,
                            fontSize: 11,
                            fontWeight: 600,
                          }}
                        >
                          {badge.label}
                        </span>
                      </td>
                      <td
                        style={{
                          padding: '12px',
                          color: getSeverityColor(inc.severity),
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          fontSize: 12,
                        }}
                      >
                        {inc.severity}
                      </td>
                      <td style={{ padding: '12px', color: '#a4afc5', fontSize: 12 }}>
                        {inc.confidence_label || 'likely'}
                      </td>
                      <td style={{ padding: '12px', color: '#8491aa', fontSize: 12 }}>
                        {inc.link_rule && inc.link_rule !== 'NONE' ? (
                          <span style={{ background: '#1c2941', padding: '2px 6px', borderRadius: 4 }}>
                            {inc.link_rule}
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td style={{ padding: '12px' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            onSelectIncident(inc.incident_id)
                          }}
                          style={{
                            background: '#27365b',
                            color: '#b8c5ff',
                            border: 0,
                            borderRadius: 6,
                            padding: '5px 10px',
                            fontSize: 12,
                            cursor: 'pointer',
                          }}
                        >
                          Investigate →
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

