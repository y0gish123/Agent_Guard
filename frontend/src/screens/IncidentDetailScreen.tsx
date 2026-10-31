import React, { useEffect, useState } from 'react'
import {
  api,
  type ApiContext,
  type ExecuteResult,
  type ExplanationResponse,
  type IncidentDetail,
  type PreviewResponse,
} from '../api/client'

interface IncidentDetailScreenProps {
  incidentId: string
  onBack: () => void
  userContext: ApiContext
  currentLang: string
  demoMode: string
}

export const IncidentDetailScreen: React.FC<IncidentDetailScreenProps> = ({
  incidentId,
  onBack,
  userContext,
  currentLang,
  demoMode,
}) => {
  const [detail, setDetail] = useState<IncidentDetail | null>(null)
  const [explanation, setExplanation] = useState<ExplanationResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string>('')

  // Gateway flow state
  const [actionType, setActionType] = useState<string>('lock_account')
  const [targetId, setTargetId] = useState<string>('')
  const [preview, setPreview] = useState<PreviewResponse | null>(null)
  const [previewLoading, setPreviewLoading] = useState<boolean>(false)
  const [previewError, setPreviewError] = useState<string>('')

  const [approvalDecision, setApprovalDecision] = useState<'approve' | 'reject'>('approve')
  const [approvalReason, setApprovalReason] = useState<string>('Risk confirmed by analyst investigation')
  const [isApproved, setIsApproved] = useState<boolean>(false)
  const [approvalMessage, setApprovalMessage] = useState<string>('')

  const [executeResult, setExecuteResult] = useState<ExecuteResult | null>(null)
  const [executeLoading, setExecuteLoading] = useState<boolean>(false)
  const [executeError, setExecuteError] = useState<string>('')

  const loadData = async () => {
    setLoading(true)
    setError('')
    try {
      const data = await api.getIncident(incidentId)
      setDetail(data)
      if (data.incident.affected_users.length > 0) {
        setTargetId(data.incident.affected_users[0])
      } else if (data.incident.affected_hosts.length > 0) {
        setTargetId(data.incident.affected_hosts[0])
      }

      // Load explanation
      try {
        const expl = await api.getExplanation(incidentId, currentLang, demoMode)
        setExplanation(expl)
      } catch {
        // graceful degradation
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [incidentId, currentLang, demoMode])

  if (loading) {
    return <div style={{ padding: 36, color: '#8491aa' }}>Loading incident details...</div>
  }

  if (error || !detail) {
    return (
      <div style={{ padding: 36, color: '#ff7e86' }}>
        <p>Error loading incident: {error || 'Not found'}</p>
        <button onClick={onBack} style={{ background: '#27365b', color: '#b8c5ff', border: 0, padding: '8px 16px', borderRadius: 6, cursor: 'pointer' }}>
          ← Back to Incidents
        </button>
      </div>
    )
  }

  const { incident, events } = detail
  const validEventIds = new Set(events.map((e) => e.event_id))

  // Handle Response Preview
  const handlePreview = async () => {
    setPreviewLoading(true)
    setPreviewError('')
    setPreview(null)
    setIsApproved(false)
    setExecuteResult(null)
    setApprovalMessage('')
    try {
      const res = await api.previewResponse(incident.incident_id, actionType, targetId, userContext)
      setPreview(res)
    } catch (err: unknown) {
      setPreviewError(err instanceof Error ? err.message : String(err))
    } finally {
      setPreviewLoading(false)
    }
  }

  // Handle Approve
  const handleApprove = async () => {
    if (!preview) return
    setApprovalMessage('')
    try {
      const res = await api.approveResponse(preview.response_id, approvalDecision, approvalReason, userContext)
      if (res.approval_state === 'approved') {
        setIsApproved(true)
        setApprovalMessage('Approved: Action is authorized for execution.')
      } else {
        setIsApproved(false)
        setApprovalMessage('Rejected: Action will not be executed.')
      }
    } catch (err: unknown) {
      setApprovalMessage(`Approval failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  // Handle Execute
  const handleExecute = async () => {
    if (!preview) return
    setExecuteLoading(true)
    setExecuteError('')
    try {
      const res = await api.executeResponse(preview.response_id, userContext)
      setExecuteResult(res)
    } catch (err: unknown) {
      setExecuteError(err instanceof Error ? err.message : String(err))
    } finally {
      setExecuteLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Top Navigation */}
      <div>
        <button
          onClick={onBack}
          style={{
            background: 'transparent',
            border: 0,
            color: '#8b9cff',
            fontSize: 14,
            cursor: 'pointer',
            padding: 0,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          ← Back to Incident Queue
        </button>
      </div>

      {/* Incident Header Card */}
      <section
        style={{
          background: '#131c30',
          border: '1px solid #263149',
          borderRadius: 14,
          padding: 22,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontFamily: 'monospace', color: '#8b9cff', fontSize: 14, fontWeight: 700 }}>
                {incident.incident_id}
              </span>
              <span
                style={{
                  background: '#233554',
                  color: '#8b9cff',
                  padding: '3px 8px',
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}
              >
                {incident.category}
              </span>
              <span
                style={{
                  color: incident.severity === 'critical' ? '#ff7e86' : '#f5bd67',
                  fontSize: 12,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                }}
              >
                ● {incident.severity}
              </span>
            </div>
            <h2 style={{ margin: '8px 0 4px 0', fontSize: 22, color: '#e8edf8' }}>
              {incident.title}
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: '#8491aa' }}>
              First seen: {new Date(incident.first_seen).toLocaleString()} | Last seen:{' '}
              {new Date(incident.last_seen).toLocaleString()}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6 }}>
            <span style={{ fontSize: 12, color: '#52d6a0', background: '#14382c', padding: '4px 10px', borderRadius: 8 }}>
              Status: {incident.status.toUpperCase()}
            </span>
            <span style={{ fontSize: 12, color: '#a4afc5' }}>
              Confidence: <strong>{incident.confidence_label || 'likely'}</strong>
            </span>
          </div>
        </div>

        {/* Linked-By Rule Panel */}
        {incident.link_rule && incident.link_rule !== 'NONE' && (
          <div
            style={{
              marginTop: 16,
              padding: '10px 14px',
              background: '#1c2941',
              borderRadius: 8,
              borderLeft: '4px solid #8b9cff',
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <strong style={{ color: '#8b9cff' }}>Correlated By Rule:</strong>
            <span style={{ fontFamily: 'monospace', color: '#e8edf8' }}>{incident.link_rule}</span>
            <span style={{ color: '#8491aa', fontSize: 12 }}>
              (Events connected within temporal correlation window)
            </span>
          </div>
        )}
      </section>

      {/* Grid: Evidence Timeline & AI Explanation */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 20 }}>
        {/* Evidence Events Timeline */}
        <section
          style={{
            background: '#131c30',
            border: '1px solid #263149',
            borderRadius: 14,
            padding: 20,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h3 style={{ margin: 0, color: '#e8edf8' }}>Evidence Events ({events.length})</h3>
            <span style={{ fontSize: 11, color: '#8491aa' }}>Chronological sequence</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 480, overflowY: 'auto' }}>
            {events.map((ev, index) => (
              <div
                key={ev.event_id}
                style={{
                  background: '#0b1020',
                  border: '1px solid #263149',
                  borderRadius: 8,
                  padding: 12,
                  fontSize: 12,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontWeight: 700, color: '#8b9cff' }}>#{index + 1}</span>
                    <span style={{ fontFamily: 'monospace', color: '#a4afc5' }}>{ev.event_id}</span>
                    <span style={{ background: '#1c2941', padding: '2px 6px', borderRadius: 4, color: '#52d6a0' }}>
                      {ev.event_type}
                    </span>
                  </div>
                  <span style={{ color: '#8491aa' }}>
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div style={{ color: '#8491aa', marginBottom: 4 }}>
                  Host: <strong style={{ color: '#e8edf8' }}>{ev.host_id || 'N/A'}</strong> | User:{' '}
                  <strong style={{ color: '#e8edf8' }}>{ev.user_id || 'N/A'}</strong>
                </div>

                {/* Attributes: safely rendered as JSON text, never HTML */}
                <div
                  style={{
                    background: '#131c30',
                    padding: '6px 8px',
                    borderRadius: 4,
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: '#b8c5ff',
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {JSON.stringify(ev.attributes, null, 2)}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* AI Assisted Analysis Panel */}
        <section
          style={{
            background: '#131c30',
            border: '1px solid #263149',
            borderRadius: 14,
            padding: 20,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h3 style={{ margin: 0, color: '#e8edf8' }}>AI Investigation (Gemini Flash)</h3>
            <span
              style={{
                fontSize: 11,
                background: demoMode === 'naive' ? '#4a1515' : '#1e2d4d',
                color: demoMode === 'naive' ? '#ff7e86' : '#8b9cff',
                padding: '3px 8px',
                borderRadius: 6,
                fontWeight: 600,
              }}
            >
              {demoMode.toUpperCase()} PROMPT
            </span>
          </div>

          {explanation ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13 }}>
              {/* Summary */}
              <div>
                <strong style={{ color: '#8b9cff' }}>Summary:</strong>
                <p style={{ margin: '4px 0 0 0', color: '#e8edf8', lineHeight: 1.5 }}>
                  {explanation.summary}
                </p>
              </div>

              {/* Observed Facts with Cited Event Badges */}
              {explanation.observed_facts?.length > 0 && (
                <div>
                  <strong style={{ color: '#8b9cff' }}>Observed Facts & Evidence Links:</strong>
                  <ul style={{ margin: '6px 0 0 0', paddingLeft: 18, color: '#a4afc5' }}>
                    {explanation.observed_facts.map((fact, idx) => (
                      <li key={idx} style={{ marginBottom: 6 }}>
                        <span>{fact.text}</span>
                        <div style={{ display: 'inline-flex', gap: 4, marginLeft: 8 }}>
                          {fact.evidence_event_ids?.map((eid) => {
                            const isValid = validEventIds.has(eid)
                            return (
                              <span
                                key={eid}
                                style={{
                                  fontSize: 10,
                                  padding: '1px 6px',
                                  borderRadius: 4,
                                  background: isValid ? '#14382c' : '#4a1515',
                                  color: isValid ? '#52d6a0' : '#ff7e86',
                                  fontWeight: 600,
                                }}
                                title={isValid ? 'Verified event ID in evidence' : 'Hallucinated or unknown event ID!'}
                              >
                                {eid} {isValid ? '✓' : '⚠'}
                              </span>
                            )
                          })}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Interpretation */}
              <div>
                <strong style={{ color: '#8b9cff' }}>Analyst Interpretation:</strong>
                <p style={{ margin: '4px 0 0 0', color: '#a4afc5', lineHeight: 1.5 }}>
                  {explanation.interpretation}
                </p>
              </div>

              {/* Recommended Actions */}
              {explanation.recommended_actions?.length > 0 && (
                <div style={{ background: '#0b1020', padding: 12, borderRadius: 8, border: '1px solid #263149' }}>
                  <strong style={{ color: '#f5bd67', fontSize: 12 }}>AI Recommended Actions (Unverified Proposals):</strong>
                  <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {explanation.recommended_actions.map((act, i) => (
                      <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: '#e8edf8' }}>
                          ◈ <strong>{act.action_type}</strong> on <code>{act.target_id}</code>
                        </span>
                        <button
                          onClick={() => {
                            setActionType(act.action_type)
                            setTargetId(act.target_id)
                          }}
                          style={{
                            background: '#27365b',
                            color: '#b8c5ff',
                            border: 0,
                            borderRadius: 4,
                            padding: '3px 8px',
                            fontSize: 11,
                            cursor: 'pointer',
                          }}
                        >
                          Fill Gateway Form
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <p style={{ margin: 0, fontSize: 11, color: '#f5bd67', lineHeight: 1.4 }}>
                ⚠️ The AI may only recommend. All actions require deterministic authorization by the policy gateway.
              </p>
            </div>
          ) : (
            <div style={{ color: '#8491aa', fontSize: 13 }}>
              Loading AI analysis...
            </div>
          )}
        </section>
      </div>

      {/* Response Authorization Gateway Flow */}
      <section
        style={{
          background: '#131c30',
          border: '1px solid #263149',
          borderRadius: 14,
          padding: 22,
        }}
      >
        <div style={{ marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: '#e8edf8' }}>Verified Policy Gateway & Response Authorization</h3>
          <p style={{ margin: '4px 0 0 0', fontSize: 13, color: '#8491aa' }}>
            Submit an action proposal through the deterministic policy rules (P1-P6) before any execution token is issued.
          </p>
        </div>

        {/* Step 1: Form */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: 16,
            background: '#0b1020',
            border: '1px solid #263149',
            borderRadius: 10,
            padding: 16,
            marginBottom: 20,
          }}
        >
          <div>
            <label style={{ display: 'block', fontSize: 12, color: '#8491aa', marginBottom: 6 }}>
              Action Type
            </label>
            <select
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
              style={{
                width: '100%',
                background: '#131c30',
                color: '#e8edf8',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 10px',
                fontSize: 13,
              }}
            >
              <option value="lock_account">lock_account (User Account)</option>
              <option value="isolate_host">isolate_host (Endpoint Host)</option>
              <option value="revoke_session">revoke_session (Active Sessions)</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 12, color: '#8491aa', marginBottom: 6 }}>
              Target Identifier
            </label>
            <input
              type="text"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              placeholder="e.g. priya.rec or clinic-pc-01"
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: '#131c30',
                color: '#e8edf8',
                border: '1px solid #3b4965',
                borderRadius: 6,
                padding: '8px 10px',
                fontSize: 13,
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button
              onClick={handlePreview}
              disabled={previewLoading || !targetId.trim()}
              style={{
                width: '100%',
                background: '#6679ef',
                color: '#ffffff',
                border: 0,
                borderRadius: 6,
                padding: '9px 16px',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {previewLoading ? 'Evaluating Policy...' : 'Evaluate Policy Preview →'}
            </button>
          </div>
        </div>

        {previewError && (
          <div style={{ padding: 12, background: '#4a1515', color: '#ff7e86', borderRadius: 8, fontSize: 13, marginBottom: 16 }}>
            Policy Evaluation Error: {previewError}
          </div>
        )}

        {/* Step 2: Policy Preview Decision Card */}
        {preview && (
          <div
            style={{
              background: '#0b1020',
              border: `1px solid ${
                preview.policy_decision === 'ALLOW'
                  ? '#52d6a0'
                  : preview.policy_decision === 'REVIEW'
                    ? '#f5bd67'
                    : '#ff7e86'
              }`,
              borderRadius: 10,
              padding: 18,
              marginBottom: 20,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span
                  style={{
                    fontSize: 13,
                    fontWeight: 700,
                    padding: '4px 10px',
                    borderRadius: 6,
                    background:
                      preview.policy_decision === 'ALLOW'
                        ? '#14382c'
                        : preview.policy_decision === 'REVIEW'
                          ? '#3d3016'
                          : '#4a1515',
                    color:
                      preview.policy_decision === 'ALLOW'
                        ? '#52d6a0'
                        : preview.policy_decision === 'REVIEW'
                          ? '#f5bd67'
                          : '#ff7e86',
                  }}
                >
                  POLICY DECISION: {preview.policy_decision}
                </span>
                <span style={{ fontFamily: 'monospace', color: '#8b9cff', fontSize: 12 }}>
                  {preview.reason_code}
                </span>
              </div>
              <span style={{ fontSize: 12, color: '#8491aa' }}>Response ID: {preview.response_id}</span>
            </div>

            <div style={{ color: '#e8edf8', fontSize: 14, marginBottom: 10 }}>
              <strong>Plain Language Reason:</strong> {preview.plain_reason}
            </div>

            {preview.consequence && (
              <div style={{ color: '#a4afc5', fontSize: 13, marginBottom: 14 }}>
                <strong>Consequence Analysis:</strong> {preview.consequence}
              </div>
            )}

            {/* Step 3: Approval / Rejection (if REVIEW) */}
            {preview.policy_decision === 'REVIEW' && (
              <div style={{ borderTop: '1px solid #263149', paddingTop: 14, marginTop: 14 }}>
                <h4 style={{ margin: '0 0 10px 0', color: '#f5bd67' }}>
                  Human Review Required Before Execution
                </h4>

                {userContext.role !== 'approver' ? (
                  <div style={{ padding: 10, background: '#1c2941', borderRadius: 6, fontSize: 13, color: '#f5bd67' }}>
                    🔒 Approval requires the <strong>Approver (Lead)</strong> role. Switch role in the header to approve.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                      <label style={{ fontSize: 13, color: '#e8edf8' }}>
                        <input
                          type="radio"
                          name="decision"
                          value="approve"
                          checked={approvalDecision === 'approve'}
                          onChange={() => setApprovalDecision('approve')}
                        />{' '}
                        Approve Action
                      </label>
                      <label style={{ fontSize: 13, color: '#e8edf8' }}>
                        <input
                          type="radio"
                          name="decision"
                          value="reject"
                          checked={approvalDecision === 'reject'}
                          onChange={() => setApprovalDecision('reject')}
                        />{' '}
                        Reject Action
                      </label>
                    </div>

                    <input
                      type="text"
                      value={approvalReason}
                      onChange={(e) => setApprovalReason(e.target.value)}
                      placeholder="Reason for decision"
                      style={{
                        width: '100%',
                        boxSizing: 'border-box',
                        background: '#131c30',
                        color: '#e8edf8',
                        border: '1px solid #3b4965',
                        borderRadius: 6,
                        padding: '8px 10px',
                        fontSize: 13,
                      }}
                    />

                    <div>
                      <button
                        onClick={handleApprove}
                        style={{
                          background: approvalDecision === 'approve' ? '#52d6a0' : '#ff7e86',
                          color: '#0b1020',
                          border: 0,
                          borderRadius: 6,
                          padding: '8px 16px',
                          fontSize: 13,
                          fontWeight: 700,
                          cursor: 'pointer',
                        }}
                      >
                        Submit {approvalDecision.toUpperCase()} Decision
                      </button>
                    </div>
                  </div>
                )}

                {approvalMessage && (
                  <div style={{ marginTop: 10, fontSize: 13, color: isApproved ? '#52d6a0' : '#ff7e86' }}>
                    {approvalMessage}
                  </div>
                )}
              </div>
            )}

            {/* Step 4: Execute Action Button */}
            {(preview.policy_decision === 'ALLOW' || isApproved) && (
              <div style={{ borderTop: '1px solid #263149', paddingTop: 14, marginTop: 14 }}>
                <button
                  onClick={handleExecute}
                  disabled={executeLoading}
                  style={{
                    background: '#52d6a0',
                    color: '#0b1020',
                    border: 0,
                    borderRadius: 6,
                    padding: '10px 20px',
                    fontSize: 14,
                    fontWeight: 700,
                    cursor: 'pointer',
                  }}
                >
                  {executeLoading ? 'Issuing HMAC Token & Executing...' : 'Execute Authorized Action via Gateway'}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Step 5: Execution Result Banner (Displayed on EXECUTED_OK) */}
        {executeResult && (
          <div
            style={{
              background: executeResult.execution_status === 'succeeded' ? '#14382c' : '#4a1515',
              border: `1px solid ${executeResult.execution_status === 'succeeded' ? '#52d6a0' : '#ff7e86'}`,
              borderRadius: 10,
              padding: 16,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <span style={{ fontSize: 18 }}>
                {executeResult.execution_status === 'succeeded' ? '✅' : '❌'}
              </span>
              <strong style={{ fontSize: 15, color: '#e8edf8' }}>
                Execution Status: {executeResult.execution_status.toUpperCase()} ({executeResult.reason_code})
              </strong>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: '#e8edf8', lineHeight: 1.5 }}>
              {executeResult.plain_reason}
            </p>
          </div>
        )}

        {executeError && (
          <div style={{ padding: 12, background: '#4a1515', color: '#ff7e86', borderRadius: 8, fontSize: 13, marginTop: 14 }}>
            Execution Error: {executeError}
          </div>
        )}
      </section>
    </div>
  )
}

