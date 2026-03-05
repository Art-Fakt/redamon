'use client'

import { useEffect, useRef, useState } from 'react'
import { X, Terminal, CheckCircle, AlertCircle, Pause, Play, Trash2, Square, Loader2 } from 'lucide-react'
import { RECON_PHASES } from '@/lib/recon-types'
import type { ReconLogEvent, ReconStatus } from '@/lib/recon-types'
import styles from './ReconLogsDrawer.module.css'

interface ReconLogsDrawerProps {
  isOpen: boolean
  onClose: () => void
  logs: ReconLogEvent[]
  currentPhase: string | null
  currentPhaseNumber: number | null
  status: ReconStatus
  onClearLogs: () => void
  onPause?: () => void
  onResume?: () => void
  onStop?: () => void
  title?: string
  phases?: readonly string[]
  totalPhases?: number
}

export function ReconLogsDrawer({
  isOpen,
  onClose,
  logs,
  currentPhase,
  currentPhaseNumber,
  status,
  onClearLogs,
  onPause,
  onResume,
  onStop,
  title = 'Reconnaissance Logs',
  phases = RECON_PHASES,
  totalPhases = 7,
}: ReconLogsDrawerProps) {
  const logsEndRef = useRef<HTMLDivElement>(null)
  const logsContainerRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  // Detect manual scroll to disable auto-scroll
  const handleScroll = () => {
    if (!logsContainerRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logsContainerRef.current
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50
    setAutoScroll(isAtBottom)
  }

  const getStatusIcon = () => {
    switch (status) {
      case 'running':
      case 'starting':
        return <div className={styles.runningIndicator} />
      case 'paused':
        return <Pause size={14} className={styles.pausedIcon} />
      case 'stopping':
        return <Loader2 size={14} className={styles.spinner} />
      case 'completed':
        return <CheckCircle size={14} className={styles.successIcon} />
      case 'error':
        return <AlertCircle size={14} className={styles.errorIcon} />
      default:
        return <Terminal size={14} />
    }
  }

  const getStatusText = () => {
    switch (status) {
      case 'starting':
        return 'Starting...'
      case 'running':
        return currentPhase
          ? `Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
          : 'Running...'
      case 'paused':
        return currentPhase
          ? `Paused — Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
          : 'Paused'
      case 'completed':
        return 'Completed'
      case 'error':
        return 'Error'
      case 'stopping':
        return 'Stopping...'
      default:
        return 'Idle'
    }
  }

  const getLogClassName = (level: string) => {
    switch (level) {
      case 'error':
        return styles.logError
      case 'warning':
        return styles.logWarning
      case 'success':
        return styles.logSuccess
      case 'action':
        return styles.logAction
      default:
        return styles.logInfo
    }
  }

  return (
    <div className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.titleContainer}>
          <Terminal size={16} />
          <span>{title}</span>
        </div>
        <button
          className={styles.closeButton}
          onClick={onClose}
          aria-label="Close drawer"
        >
          <X size={16} />
        </button>
      </div>

      {/* Status bar */}
      <div className={styles.statusBar}>
        <div className={styles.statusLeft}>
          {getStatusIcon()}
          <span className={styles.statusText}>{getStatusText()}</span>
        </div>
        <div className={styles.statusActions}>
          {(status === 'running' || status === 'paused') && (
            <button
              className={`${styles.iconButton} ${status === 'paused' ? styles.iconButtonPaused : ''}`}
              onClick={status === 'paused' ? onResume : onPause}
              title={status === 'paused' ? 'Resume pipeline' : 'Pause pipeline'}
            >
              {status === 'paused' ? <Play size={14} /> : <Pause size={14} />}
            </button>
          )}
          {(status === 'running' || status === 'paused') && (
            <button
              className={`${styles.iconButton} ${styles.iconButtonStop}`}
              onClick={onStop}
              title="Stop pipeline"
            >
              <Square size={14} />
            </button>
          )}
          <button
            className={styles.iconButton}
            onClick={onClearLogs}
            title="Clear logs"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Phase progress */}
      <div className={styles.phaseProgress}>
        {phases.map((phase, index) => {
          const phaseNum = index + 1
          const isActive = currentPhaseNumber === phaseNum
          const isCompleted = currentPhaseNumber !== null && phaseNum < currentPhaseNumber
          const isPending = currentPhaseNumber === null || phaseNum > currentPhaseNumber

          return (
            <div
              key={phase}
              className={`${styles.phaseItem} ${isActive ? styles.phaseActive : ''} ${isCompleted ? styles.phaseCompleted : ''} ${isPending ? styles.phasePending : ''}`}
              title={phase}
            >
              <span className={styles.phaseNumber}>{phaseNum}</span>
            </div>
          )
        })}
      </div>

      {/* Logs container */}
      <div
        ref={logsContainerRef}
        className={styles.logsContainer}
        onScroll={handleScroll}
      >
        {logs.length === 0 ? (
          <div className={styles.emptyLogs}>
            <Terminal size={24} />
            <p>Waiting for logs...</p>
          </div>
        ) : (
          <>
            {logs.map((log, index) => (
              <div
                key={index}
                className={`${styles.logLine} ${getLogClassName(log.level)}`}
              >
                <span className={styles.logTimestamp}>
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={styles.logMessage}>{log.log}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </>
        )}
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && (
        <button
          className={styles.scrollToBottom}
          onClick={() => {
            setAutoScroll(true)
            logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
          }}
        >
          Scroll to bottom
        </button>
      )}
    </div>
  )
}

export default ReconLogsDrawer
