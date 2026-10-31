import { MOCK_AUDIT, MOCK_FUNNEL, MOCK_INCIDENTS } from '../fixtures/mockData'

const USE_FIXTURES = import.meta.env.VITE_USE_FIXTURES === 'true'

export interface ApiContext {
  user: string
  role: 'staff' | 'approver'
}

export interface FunnelData {
  raw_events: number
  noise_filtered: number
  candidates: number
  incidents: number
}

export interface IncidentSummary {
  incident_id: string
  title: string
  category: string
  severity: string
  status: string
  first_seen: string
  last_seen: string
  affected_hosts: string[]
  affected_users: string[]
  evidence_event_ids: string[]
  detection_reason: string
  link_rule?: string
  confidence_label?: string
}

export interface IncidentEvent {
  event_id: string
  timestamp: string
  source: string
  host_id: string | null
  user_id: string | null
  event_type: string
  severity: string
  raw_event_ref?: string
  attributes: Record<string, unknown>
}

export interface IncidentDetail {
  incident: IncidentSummary
  events: IncidentEvent[]
}

export interface ExplanationFact {
  text: string
  evidence_event_ids: string[]
}

export interface ActionProposal {
  action_type: string
  target_id: string
  reason: string
}

export interface ExplanationResponse {
  incident_id: string
  lang: string
  summary: string
  observed_facts: ExplanationFact[]
  interpretation: string
  potential_impact: string[]
  confidence_label: string
  recommended_next_steps: string[]
  recommended_actions: ActionProposal[]
  generated_by: string
  mode: string
}

export interface PreviewResponse {
  response_id: string
  incident_id: string
  action_type: string
  target_id: string
  policy_decision: 'ALLOW' | 'REVIEW' | 'BLOCK'
  reason_code: string
  plain_reason: string
  consequence: string
  requires_approval: boolean
}

export interface ApproveResponse {
  response_id: string
  incident_id: string
  action_type: string
  target_id: string
  approval_state: 'approved' | 'rejected'
  policy_decision: string
  reason_code: string
}

export interface ExecuteResult {
  response_id: string
  execution_status: 'succeeded' | 'blocked' | 'rejected_by_tool'
  reason_code: string
  plain_reason: string
  tool_result?: Record<string, unknown>
}

export interface PhishingReasonItem {
  code: string
  text: string
  snippet?: string
}

export interface PhishingCheckResult {
  verdict: 'red' | 'amber' | 'green'
  score: number
  reasons: PhishingReasonItem[]
  event_id: string
}

export interface AuditRecord {
  sequence_no: number
  created_at: string
  actor: string
  event_type: string
  incident_id: string | null
  response_id: string | null
  payload_json?: string
  previous_hash?: string
  event_hash: string
}

export interface AuditVerifyResult {
  valid: boolean
  total_events: number
  error_at_sequence?: number
  message: string
}

export interface ToolState {
  locked_accounts: string[]
  isolated_hosts: string[]
  revoked_sessions: string[]
  site_state?: Record<string, unknown>
}

class ApiClient {
  private getHeaders(ctx: ApiContext): HeadersInit {
    return {
      'Content-Type': 'application/json',
      'X-User': ctx.user || 'anonymous',
      'X-Role': ctx.role || 'staff',
    }
  }

  async getFunnel(): Promise<FunnelData> {
    if (USE_FIXTURES) return MOCK_FUNNEL
    try {
      const res = await fetch('/api/funnel')
      if (!res.ok) throw new Error('Failed to fetch funnel')
      return await res.json()
    } catch {
      return MOCK_FUNNEL
    }
  }

  async getIncidents(): Promise<IncidentSummary[]> {
    if (USE_FIXTURES) return MOCK_INCIDENTS
    try {
      const res = await fetch('/api/incidents')
      if (!res.ok) throw new Error('Failed to fetch incidents')
      const data = await res.json()
      return Array.isArray(data) ? data : data.items || []
    } catch {
      return MOCK_INCIDENTS
    }
  }

  async getIncident(id: string): Promise<IncidentDetail> {
    if (USE_FIXTURES) {
      const inc = MOCK_INCIDENTS.find((i) => i.incident_id === id) || MOCK_INCIDENTS[0]
      return {
        incident: inc,
        events: inc.evidence_event_ids.map((eid, idx) => ({
          event_id: eid,
          timestamp: new Date(Date.now() - (10 - idx) * 60000).toISOString(),
          source: 'collector',
          host_id: inc.affected_hosts[0] || null,
          user_id: inc.affected_users[0] || null,
          event_type: 'authentication_failure',
          severity: 'medium',
          attributes: { ip: '192.168.1.100', reason: 'invalid_credentials' },
        })),
      }
    }
    const res = await fetch(`/api/incidents/${id}`)
    if (!res.ok) throw new Error(`Failed to fetch incident ${id}`)
    return await res.json()
  }

  async getExplanation(id: string, lang = 'en', mode = 'guarded'): Promise<ExplanationResponse> {
    const res = await fetch(`/api/incidents/${id}/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lang, mode }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.plain_message || 'Explanation failed')
    }
    return await res.json()
  }

  async previewResponse(
    incidentId: string,
    actionType: string,
    targetId: string,
    ctx: ApiContext
  ): Promise<PreviewResponse> {
    const res = await fetch(`/api/incidents/${incidentId}/response-preview`, {
      method: 'POST',
      headers: this.getHeaders(ctx),
      body: JSON.stringify({
        action_type: actionType,
        target_id: targetId,
        requested_by: ctx.user,
        proposed_by: 'ai',
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.plain_message || 'Preview failed')
    }
    return await res.json()
  }

  async approveResponse(
    responseId: string,
    decision: 'approve' | 'reject',
    reason: string,
    ctx: ApiContext
  ): Promise<ApproveResponse> {
    const res = await fetch(`/api/responses/${responseId}/approve`, {
      method: 'POST',
      headers: this.getHeaders(ctx),
      body: JSON.stringify({ decision, reason }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.plain_message || 'Approval failed')
    }
    return await res.json()
  }

  async executeResponse(responseId: string, ctx: ApiContext): Promise<ExecuteResult> {
    const res = await fetch(`/api/responses/${responseId}/execute`, {
      method: 'POST',
      headers: this.getHeaders(ctx),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.plain_message || 'Execution failed')
    }
    return await res.json()
  }

  async checkPhishing(
    text: string,
    sender?: string,
    replyTo?: string,
    userId?: string
  ): Promise<PhishingCheckResult> {
    const res = await fetch('/api/phishing/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text,
        sender: sender || 'unknown@domain.com',
        reply_to: replyTo,
        user_id: userId || 'priya.rec',
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.plain_message || 'Phishing check failed')
    }
    return await res.json()
  }

  async getAudit(): Promise<AuditRecord[]> {
    if (USE_FIXTURES) return MOCK_AUDIT
    try {
      const res = await fetch('/api/audit')
      if (!res.ok) throw new Error('Failed to load audit')
      return await res.json()
    } catch {
      return MOCK_AUDIT
    }
  }

  async verifyAudit(): Promise<AuditVerifyResult> {
    const res = await fetch('/api/audit/verify')
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.plain_message || 'Audit verification failed')
    }
    const data = await res.json()
    const isValid = Boolean(data.ok ?? data.valid)
    return {
      valid: isValid,
      total_events: data.checked ?? data.total_events ?? 0,
      error_at_sequence: data.first_bad_sequence_no ?? data.error_at_sequence,
      message: isValid ? 'All cryptographic block hashes valid' : 'Hash chain integrity failure',
    }
  }

  async seedDemo(scenario: 'account' | 'filebursts' | 'poisoned' | 'all'): Promise<{ ok: boolean; message: string }> {
    const res = await fetch(`/api/demo/seed?scenario=${scenario}`, { method: 'POST' })
    if (!res.ok) throw new Error(`Seed scenario ${scenario} failed`)
    return await res.json()
  }

  async resetDemo(): Promise<{ ok: boolean; message: string }> {
    const res = await fetch('/api/demo/reset', { method: 'POST' })
    if (!res.ok) throw new Error('Reset failed')
    return await res.json()
  }

  async getToolState(): Promise<ToolState> {
    const res = await fetch('/api/demo/tool-state')
    if (!res.ok) throw new Error('Failed to fetch tool state')
    return await res.json()
  }
}

export const api = new ApiClient()
