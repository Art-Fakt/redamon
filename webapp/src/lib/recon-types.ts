/**
 * Types for Recon Process Management
 */

export type ReconStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface ReconState {
  project_id: string
  status: ReconStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export interface ReconLogEvent {
  log: string
  timestamp: string
  phase?: string | null
  phaseNumber?: number | null
  isPhaseStart?: boolean
  level: 'info' | 'warning' | 'error' | 'success' | 'action'
}

export interface ReconSSEEvent {
  event: 'log' | 'error' | 'complete'
  data: ReconLogEvent | { error: string } | { status: string; completedAt?: string; error?: string }
}

export const RECON_PHASES = [
  'Domain Discovery',
  'Port Scanning',
  'HTTP Probing',
  'Resource Enumeration',
  'Vulnerability Scanning',
  'MITRE Enrichment',
] as const

export type ReconPhase = typeof RECON_PHASES[number]

// =============================================================================
// GVM Vulnerability Scan Types
// =============================================================================

export type GvmStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface GvmState {
  project_id: string
  status: GvmStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export const GVM_PHASES = [
  'Loading Recon Data',
  'Connecting to GVM',
  'Scanning IPs',
  'Scanning Hostnames',
] as const

export type GvmPhase = typeof GVM_PHASES[number]

// =============================================================================
// GitHub Secret Hunt Types
// =============================================================================

export type GithubHuntStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface GithubHuntState {
  project_id: string
  status: GithubHuntStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export const GITHUB_HUNT_PHASES = [
  'Loading Settings',
  'Scanning Repositories',
  'Complete',
] as const

export type GithubHuntPhase = typeof GITHUB_HUNT_PHASES[number]
