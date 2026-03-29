'use client'

import { useState } from 'react'
import { ChevronDown, Shield } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface NmapSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function NmapSection({ data, updateField }: NmapSectionProps) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          Nmap Service Detection
          <NodeInfoTooltip section="Nmap" />
          {data.nmapEnabled ? (
            <span className={styles.badgeActive}>Active</span>
          ) : (
            <span className={styles.badgeInactive}>Disabled</span>
          )}
        </h2>
        <div className={styles.sectionHeaderRight}>
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.nmapEnabled}
              onChange={(checked) => updateField('nmapEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Deep service version detection (-sV) and NSE vulnerability scripts (--script vuln).
            Runs after port discovery to identify exact software versions and known CVEs on each open port.
          </p>

          {data.nmapEnabled && (
            <>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Version Detection (-sV)</span>
                  <p className={styles.toggleDescription}>Probe open ports to determine service/version info. Essential for CVE matching.</p>
                </div>
                <Toggle
                  checked={data.nmapVersionDetection}
                  onChange={(checked) => updateField('nmapVersionDetection', checked)}
                />
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>NSE Vulnerability Scripts (--script vuln)</span>
                  <p className={styles.toggleDescription}>Run Nmap Scripting Engine vulnerability checks (vsftpd backdoor, Log4Shell, etc.). Disabled in stealth mode.</p>
                </div>
                <Toggle
                  checked={data.nmapScriptScan}
                  onChange={(checked) => updateField('nmapScriptScan', checked)}
                />
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timing Template</label>
                  <select
                    className="textInput"
                    value={data.nmapTimingTemplate}
                    onChange={(e) => updateField('nmapTimingTemplate', e.target.value)}
                  >
                    <option value="T1">T1 - Sneaky</option>
                    <option value="T2">T2 - Polite</option>
                    <option value="T3">T3 - Normal (default)</option>
                    <option value="T4">T4 - Aggressive</option>
                    <option value="T5">T5 - Insane</option>
                  </select>
                  <span className={styles.fieldHint}>Higher = faster but noisier. Stealth mode forces T2.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Total Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.nmapTimeout}
                    onChange={(e) => updateField('nmapTimeout', parseInt(e.target.value) || 600)}
                    min={60}
                  />
                  <span className={styles.fieldHint}>Maximum total scan duration</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Per-Host Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.nmapHostTimeout}
                    onChange={(e) => updateField('nmapHostTimeout', parseInt(e.target.value) || 300)}
                    min={30}
                  />
                  <span className={styles.fieldHint}>Max time per host before moving on</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
