'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { GithubHuntState, GithubHuntStatus } from '@/lib/recon-types'

interface UseGithubHuntStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onStatusChange?: (status: GithubHuntStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

interface UseGithubHuntStatusReturn {
  state: GithubHuntState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startGithubHunt: () => Promise<GithubHuntState | null>
  stopGithubHunt: () => Promise<GithubHuntState | null>
  pauseGithubHunt: () => Promise<GithubHuntState | null>
  resumeGithubHunt: () => Promise<GithubHuntState | null>
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

export function useGithubHuntStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseGithubHuntStatusOptions): UseGithubHuntStatusReturn {
  const [state, setState] = useState<GithubHuntState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const previousStatusRef = useRef<GithubHuntStatus | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)

  const onStatusChangeRef = useRef(onStatusChange)
  const onCompleteRef = useRef(onComplete)
  const onErrorRef = useRef(onError)

  useEffect(() => {
    onStatusChangeRef.current = onStatusChange
    onCompleteRef.current = onComplete
    onErrorRef.current = onError
  }, [onStatusChange, onComplete, onError])

  const fetchStatus = useCallback(async () => {
    if (!projectId) return

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/status`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to fetch GitHub hunt status')
      }

      const data: GithubHuntState = await response.json()
      setState(data)
      setError(null)

      if (previousStatusRef.current !== data.status) {
        onStatusChangeRef.current?.(data.status)

        if (data.status === 'completed') {
          onCompleteRef.current?.()
        } else if (data.status === 'error' && data.error) {
          onErrorRef.current?.(data.error)
        }

        previousStatusRef.current = data.status
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
    }
  }, [projectId])

  const startGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to start GitHub Secret Hunt')
      }

      const data: GithubHuntState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      onErrorRef.current?.(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const stopGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setState(prev => prev ? { ...prev, status: 'stopping' as GithubHuntState['status'] } : prev)

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to stop GitHub Secret Hunt')
      }

      const data: GithubHuntState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const pauseGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to pause GitHub hunt')
      }

      const data: GithubHuntState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const resumeGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to resume GitHub hunt')
      }

      const data: GithubHuntState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  // Initial fetch on mount
  useEffect(() => {
    if (!projectId || !enabled) {
      setState(null)
      return
    }

    fetchStatus()
  }, [projectId, enabled, fetchStatus])

  // Smart polling
  useEffect(() => {
    if (!projectId || !enabled) return

    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    const isRunning = state?.status === 'running' || state?.status === 'starting' || state?.status === 'paused'
    const interval = isRunning ? pollingInterval : IDLE_POLLING_INTERVAL

    pollingRef.current = setInterval(fetchStatus, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [projectId, enabled, pollingInterval, fetchStatus, state?.status])

  return {
    state,
    isLoading,
    error,
    refetch: fetchStatus,
    startGithubHunt,
    stopGithubHunt,
    pauseGithubHunt,
    resumeGithubHunt,
  }
}

export default useGithubHuntStatus
