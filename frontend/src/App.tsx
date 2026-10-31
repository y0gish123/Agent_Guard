import { useCallback, useEffect, useState } from 'react'
import { api, type FunnelData, type IncidentSummary } from './api/client'
import { DemoToolsModal } from './components/DemoToolsModal'
import { Header } from './components/Header'
import { useLiveUpdates } from './hooks/useLiveUpdates'
import { AuditScreen } from './screens/AuditScreen'
import { IncidentDetailScreen } from './screens/IncidentDetailScreen'
import { OverviewScreen } from './screens/OverviewScreen'
import { PhishingScreen } from './screens/PhishingScreen'

function App() {
  const [activeTab, setActiveTab] = useState<'Overview' | 'Phishing' | 'Audit'>('Overview')
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null)

  // Roles & Language state
  const [userRole, setUserRole] = useState<'staff' | 'approver'>('staff')
  const [currentLang, setCurrentLang] = useState<string>('en')
  const [allowUnreviewedLangs] = useState<boolean>(false)
  const [demoMode] = useState<string>('guarded')

  // Demo tools modal
  const [isDemoModalOpen, setIsDemoModalOpen] = useState<boolean>(false)

  // Data state
  const [funnel, setFunnel] = useState<FunnelData>({
    raw_events: 0,
    noise_filtered: 0,
    candidates: 0,
    incidents: 0,
  })
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])

  const loadDashboardData = useCallback(async () => {
    try {
      const [fData, iData] = await Promise.all([api.getFunnel(), api.getIncidents()])
      setFunnel(fData)
      setIncidents(iData)
    } catch {
      // fallback handled in client
    }
  }, [])

  // Hook for live SSE updates + polling fallback
  const { status: connectionStatus } = useLiveUpdates({
    onEvent: () => {
      loadDashboardData()
    },
    pollIntervalMs: 5000,
  })

  useEffect(() => {
    loadDashboardData()
  }, [loadDashboardData])

  const userContext = {
    user: userRole === 'approver' ? 'lead.approver' : 'clinic.analyst',
    role: userRole,
  }

  return (
    <div
      style={{
        width: '100%',
        minHeight: '100vh',
        background: '#0b1020',
        color: '#e8edf8',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
        boxSizing: 'border-box',
      }}
    >
      <Header
        connectionStatus={connectionStatus}
        userRole={userRole}
        setUserRole={setUserRole}
        currentLang={currentLang}
        setCurrentLang={setCurrentLang}
        allowUnreviewedLangs={allowUnreviewedLangs}
        demoMode={demoMode}
        onToggleDemoTools={() => setIsDemoModalOpen(true)}
      />

      <div style={{ display: 'flex' }}>
        {/* Navigation Sidebar */}
        <aside
          style={{
            width: 220,
            background: '#10172a',
            borderRight: '1px solid #263149',
            padding: '24px 14px',
            boxSizing: 'border-box',
            minHeight: 'calc(100vh - 61px)',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {[
              { id: 'Overview', icon: '▦', label: 'SOC Overview' },
              { id: 'Phishing', icon: '⌕', label: 'Check Message' },
              { id: 'Audit', icon: '☷', label: 'Audit Trail' },
            ].map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  setSelectedIncidentId(null)
                  setActiveTab(item.id as 'Overview' | 'Phishing' | 'Audit')
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  width: '100%',
                  textAlign: 'left',
                  padding: '10px 14px',
                  borderRadius: 8,
                  border: 0,
                  background:
                    activeTab === item.id && !selectedIncidentId ? '#27365b' : 'transparent',
                  color:
                    activeTab === item.id && !selectedIncidentId ? '#b8c5ff' : '#8491aa',
                  fontWeight: activeTab === item.id && !selectedIncidentId ? 600 : 400,
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                <span>{item.icon}</span>
                {item.label}
              </button>
            ))}
          </div>

          <div
            style={{
              marginTop: 40,
              padding: '14px 12px',
              background: '#0b1020',
              borderRadius: 8,
              border: '1px solid #263149',
              fontSize: 11,
              color: '#8491aa',
              lineHeight: 1.5,
            }}
          >
            <div style={{ color: '#52d6a0', fontWeight: 600, marginBottom: 4 }}>
              ● DEMO SIMULATION
            </div>
            Test environment running against mock enforcement tool on port 8001. No external access.
          </div>
        </aside>

        {/* Main Content Area */}
        <main
          style={{
            flex: 1,
            padding: '28px 36px',
            boxSizing: 'border-box',
            background: '#0b1020',
            maxWidth: 1400,
          }}
        >
          {selectedIncidentId ? (
            <IncidentDetailScreen
              incidentId={selectedIncidentId}
              onBack={() => setSelectedIncidentId(null)}
              userContext={userContext}
              currentLang={currentLang}
              demoMode={demoMode}
            />
          ) : activeTab === 'Overview' ? (
            <OverviewScreen
              funnel={funnel}
              incidents={incidents}
              onSelectIncident={(id) => setSelectedIncidentId(id)}
            />
          ) : activeTab === 'Phishing' ? (
            <PhishingScreen />
          ) : (
            <AuditScreen />
          )}
        </main>
      </div>

      <DemoToolsModal
        isOpen={isDemoModalOpen}
        onClose={() => setIsDemoModalOpen(false)}
        onRefreshData={loadDashboardData}
      />
    </div>
  )
}

export default App
