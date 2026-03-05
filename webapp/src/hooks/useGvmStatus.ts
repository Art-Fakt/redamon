'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { GvmState, GvmStatus } from '@/lib/recon-types'

interface UseGvmStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onStatusChange?: (status: GvmStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

interface UseGvmStatusReturn {
  state: GvmState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startGvm: () => Promise<GvmState | null>
  stopGvm: () => Promise<GvmState | null>
  pauseGvm: () => Promise<GvmState | null>
  resumeGvm: () => Promise<GvmState | null>
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

export function useGvmStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseGvmStatusOptions): UseGvmStatusReturn {
  const [state, setState] = useState<GvmState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const previousStatusRef = useRef<GvmStatus | null>(null)
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
      const response = await fetch(`/api/gvm/${projectId}/status`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to fetch GVM status')
      }

      const data: GvmState = await response.json()
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

  const startGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`/api/gvm/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to start GVM scan')
      }

      const data: GvmState = await response.json()
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

  const stopGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setState(prev => prev ? { ...prev, status: 'stopping' as GvmState['status'] } : prev)

    try {
      const response = await fetch(`/api/gvm/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to stop GVM scan')
      }

      const data: GvmState = await response.json()
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

  const pauseGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/gvm/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to pause GVM scan')
      }

      const data: GvmState = await response.json()
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

  const resumeGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/gvm/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to resume GVM scan')
      }

      const data: GvmState = await response.json()
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
    startGvm,
    stopGvm,
    pauseGvm,
    resumeGvm,
  }
}

export default useGvmStatus
