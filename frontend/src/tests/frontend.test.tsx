import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { Header } from '../components/Header'
import { PhishingScreen } from '../screens/PhishingScreen'
import { OverviewScreen } from '../screens/OverviewScreen'
import { MOCK_FUNNEL, MOCK_INCIDENTS } from '../fixtures/mockData'

describe('AgentGuard Frontend Component Tests', () => {
  it('renders Header with live connection status and guarded mode badge', () => {
    render(
      <Header
        connectionStatus="live"
        userRole="staff"
        setUserRole={() => {}}
        currentLang="en"
        setCurrentLang={() => {}}
        allowUnreviewedLangs={false}
        demoMode="guarded"
        onToggleDemoTools={() => {}}
      />
    )

    expect(screen.getByText('AgentGuard')).toBeInTheDocument()
    expect(screen.getByText('LIVE')).toBeInTheDocument()
    expect(screen.getByText('GUARDED MODE')).toBeInTheDocument()
  })

  it('renders Header with polling badge on fallback', () => {
    render(
      <Header
        connectionStatus="polling"
        userRole="approver"
        setUserRole={() => {}}
        currentLang="en"
        setCurrentLang={() => {}}
        allowUnreviewedLangs={false}
        demoMode="naive"
        onToggleDemoTools={() => {}}
      />
    )

    expect(screen.getByText('POLLING')).toBeInTheDocument()
    expect(screen.getByText('NAIVE MODE')).toBeInTheDocument()
  })

  it('renders OverviewScreen funnel counts and category badges', () => {
    render(
      <OverviewScreen
        funnel={MOCK_FUNNEL}
        incidents={MOCK_INCIDENTS}
        onSelectIncident={() => {}}
      />
    )

    expect(screen.getByText('Raw Events Ingested')).toBeInTheDocument()
    expect(screen.getByText('50')).toBeInTheDocument()
    expect(screen.getByText('38')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()

    // Web attack and data exfiltration categories present
    expect(screen.getByText('Web Attack (SQLi)')).toBeInTheDocument()
    expect(screen.getByText('Data Exfiltration')).toBeInTheDocument()
  })

  it('renders PhishingScreen with safety notice and input controls', () => {
    render(<PhishingScreen />)

    expect(screen.getByText('Phishing & Malicious Message Scanner')).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/Paste raw email body/i)).toBeInTheDocument()
    expect(screen.getByText(/Load Phishing Sample/i)).toBeInTheDocument()
    expect(screen.getByText(/Check Phishing Risk/i)).toBeInTheDocument()
  })
})
