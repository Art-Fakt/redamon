'use client'

import { AlertTriangle, ShieldAlert, Play, Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui'
import styles from './GvmConfirmModal.module.css'

interface GvmStats {
  totalGvmNodes: number
  nodesByType: Record<string, number>
}

interface GvmConfirmModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  projectName: string
  targetDomain: string
  stats: GvmStats | null
  isLoading: boolean
  error?: string | null
}

export function GvmConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  projectName,
  targetDomain,
  stats,
  isLoading,
  error,
}: GvmConfirmModalProps) {
  const hasExistingData = stats && stats.totalGvmNodes > 0

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Start GVM Vulnerability Scan"
      size="default"
    >
      <div className={styles.content}>
        <div className={styles.info}>
          <p className={styles.projectInfo}>
            <strong>Project:</strong> {projectName}
          </p>
          <p className={styles.projectInfo}>
            <strong>Target:</strong> {targetDomain}
          </p>
        </div>

        <div className={styles.disclaimer}>
          <ShieldAlert size={18} className={styles.disclaimerIcon} />
          <div className={styles.disclaimerContent}>
            <p className={styles.disclaimerTitle}>Authorization Required</p>
            <p className={styles.disclaimerText}>
              Vulnerability scanning actively probes the target for security weaknesses.
              This operation may trigger security alerts and can impact target system performance.
              By proceeding, you confirm that you <strong>own the target</strong> or have{' '}
              <strong>explicit written permission</strong> from the owner to perform this scan.
              Unauthorized scanning is illegal and may result in criminal penalties.
            </p>
          </div>
        </div>

        {hasExistingData ? (
          <div className={styles.warning}>
            <AlertTriangle size={20} className={styles.warningIcon} />
            <div className={styles.warningContent}>
              <p className={styles.warningTitle}>Existing GVM Data Found</p>
              <p className={styles.warningText}>
                This project has <strong>{stats.totalGvmNodes}</strong> GVM-related nodes.
                Starting a new vulnerability scan will <strong>delete existing GVM data</strong> and
                replace it with fresh scan results. Recon data will not be affected.
              </p>
              <div className={styles.stats}>
                {Object.entries(stats.nodesByType).map(([type, count]) => (
                  <span key={type} className={styles.statBadge}>
                    {type}: {count}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className={styles.ready}>
            <p>No existing GVM data found. Ready to start vulnerability scan.</p>
            <p className={styles.readyNote}>
              This will scan <strong>{targetDomain}</strong> using GVM/OpenVAS and populate
              the graph with detected technologies, vulnerabilities, and CVEs.
            </p>
          </div>
        )}

        {error && (
          <div className={styles.errorBanner}>
            <AlertTriangle size={14} />
            <span>{error}</span>
          </div>
        )}

        <div className={styles.actions}>
          <button
            className={styles.cancelButton}
            onClick={onClose}
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            className={styles.confirmButton}
            onClick={onConfirm}
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                <span>Starting...</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>{hasExistingData ? 'Delete & Scan' : 'Start Scan'}</span>
              </>
            )}
          </button>
        </div>
      </div>
    </Modal>
  )
}

export default GvmConfirmModal
