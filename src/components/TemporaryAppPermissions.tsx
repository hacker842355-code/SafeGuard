import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Camera,
  Check,
  Clock3,
  Code2,
  FileKey2,
  Fingerprint,
  LockKeyhole,
  Mic2,
  Monitor,
  Network,
  Plus,
  ShieldCheck,
  ShieldX,
  Video,
} from 'lucide-react';
import './TemporaryAppPermissions.css';

type Application = {
  id: string;
  label: string;
  shortName: string;
  icon: string;
  enabled: string;
  mechanism: string;
  risk: 'LOW RISK' | 'MODERATE RISK' | 'HIGH RISK';
};

type LedgerEntry = {
  id: string;
  timestamp: string;
  app: string;
  reason: string;
  duration: string;
  status: string;
  hash: string;
};

const applications: Application[] = [
  {
    id: 'zoom',
    label: 'Zoom Meeting (Camera + Microphone)',
    shortName: 'Zoom Meeting',
    icon: '📹',
    enabled: 'Enables video camera and microphone audio capture.',
    mechanism: 'Unlocks OS camera driver (AllowCamera=1) and microphone audio consent store.',
    risk: 'LOW RISK',
  },
  {
    id: 'teams',
    label: 'Microsoft Teams Call (Camera + Microphone)',
    shortName: 'Microsoft Teams Call',
    icon: '📹',
    enabled: 'Enables the webcam and microphone for a Microsoft Teams call.',
    mechanism: 'Grants temporary camera and microphone access through OS privacy controls.',
    risk: 'LOW RISK',
  },
  {
    id: 'meet',
    label: 'Google Meet / WebRTC Browser Conference',
    shortName: 'Google Meet / WebRTC',
    icon: '📹',
    enabled: 'Allows a browser-based WebRTC conference to use camera and microphone.',
    mechanism: 'Temporarily grants browser media-capture permissions to the active origin.',
    risk: 'LOW RISK',
  },
  {
    id: 'scanner',
    label: 'Webcam Photo / ID Document Scanner Only',
    shortName: 'Webcam / ID Scanner',
    icon: '📷',
    enabled: 'Enables webcam image capture only; microphone access remains disabled.',
    mechanism: 'Grants camera driver access without changing microphone consent settings.',
    risk: 'MODERATE RISK',
  },
  {
    id: 'audio',
    label: 'Voice Recording / Discord Audio Only',
    shortName: 'Voice Recording / Discord',
    icon: '🎙️',
    enabled: 'Enables microphone input for voice recording or Discord audio.',
    mechanism: 'Temporarily grants microphone capture permission; camera remains locked.',
    risk: 'MODERATE RISK',
  },
  {
    id: 'vite',
    label: 'VS Code & Vite Web Server (Port 8000 / 5173)',
    shortName: 'VS Code & Vite Web Server',
    icon: '💻',
    enabled: 'Allows a local development server on ports 8000 and 5173.',
    mechanism: 'Adds temporary loopback-only firewall rules for the selected development ports.',
    risk: 'MODERATE RISK',
  },
  {
    id: 'debugger',
    label: 'Node.js Chrome DevTools Debugger (Port 9229)',
    shortName: 'Node.js DevTools Debugger',
    icon: '🛠️',
    enabled: 'Opens the Node.js inspector endpoint on port 9229.',
    mechanism: 'Adds a temporary loopback firewall exception for the Node.js debugger port.',
    risk: 'MODERATE RISK',
  },
  {
    id: 'ssh',
    label: 'Secure Remote IT Shell (SSH Port 22)',
    shortName: 'Secure Remote IT Shell (SSH)',
    icon: '🔒',
    enabled: 'Allows SSH connections over port 22 for remote administration.',
    mechanism: 'Creates a time-limited firewall exception for SSH traffic on port 22.',
    risk: 'HIGH RISK',
  },
  {
    id: 'rdp',
    label: 'Windows Remote Desktop / TeamViewer (Port 3389)',
    shortName: 'Windows Remote Desktop',
    icon: '⚠️',
    enabled: 'Allows remote desktop connectivity over port 3389.',
    mechanism: 'Temporarily opens the remote desktop firewall rule and network listener.',
    risk: 'HIGH RISK',
  },
  {
    id: 'smb',
    label: 'Windows Shared Drive / File Sharing (SMB Port 445)',
    shortName: 'Windows Shared Drive (SMB)',
    icon: '⚠️',
    enabled: 'Allows Windows file-sharing traffic over SMB port 445.',
    mechanism: 'Temporarily opens the SMB firewall rule for file-sharing connections.',
    risk: 'HIGH RISK',
  },
  {
    id: 'custom',
    label: 'Custom Application / Specific Port Number...',
    shortName: 'Custom Application',
    icon: '⚙️',
    enabled: 'Allows the custom application and port described in the audit reason.',
    mechanism: 'Creates a temporary, scoped exception based on the requested application and port.',
    risk: 'HIGH RISK',
  },
];

const initialLedger: LedgerEntry[] = [
  {
    id: 'LOG-8841',
    timestamp: '11:02:14 UTC',
    app: 'Zoom Meeting',
    reason: 'Executive security architecture review call',
    duration: '30 min',
    status: 'ACTIVE',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  {
    id: 'LOG-8840',
    timestamp: '10:15:00 UTC',
    app: 'VS Code & Vite Web Server (Port 8000)',
    reason: 'Frontend UI layout preview',
    duration: '30 min',
    status: 'EXPIRED',
    hash: 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
  },
  {
    id: 'LOG-8839',
    timestamp: '09:12:44 UTC',
    app: 'Windows Shared Drive (Port 445 SMB)',
    reason: 'Automated Windows Update helper',
    duration: '60 min',
    status: 'BLOCKED_SUSPICIOUS',
    hash: '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce',
  },
];

const durationOptions = [
  { minutes: 15, title: '15 Minutes', note: 'Quick Meeting / Scan' },
  { minutes: 30, title: '30 Minutes', note: 'Standard Meeting / Dev' },
  { minutes: 60, title: '60 Minutes', note: 'Maximum Allowed Limit' },
];

const formatRemaining = (seconds: number) => {
  const minutes = Math.floor(seconds / 60).toString().padStart(2, '0');
  const remainder = (seconds % 60).toString().padStart(2, '0');
  return `${minutes}:${remainder}`;
};

const timestampNow = () =>
  new Intl.DateTimeFormat('en-GB', {
    timeZone: 'UTC',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date()) + ' UTC';

const sha256 = async (value: string) => {
  const bytes = new TextEncoder().encode(value);
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
};

export default function TemporaryAppPermissions() {
  const [selectedId, setSelectedId] = useState('zoom');
  const [selectedMinutes, setSelectedMinutes] = useState(30);
  const [reason, setReason] = useState('');
  const [remainingSeconds, setRemainingSeconds] = useState(25 * 60 + 28);
  const [leaseDurationSeconds, setLeaseDurationSeconds] = useState(30 * 60);
  const [leaseActive, setLeaseActive] = useState(true);
  const [leaseApp, setLeaseApp] = useState({ ...applications[0], label: 'Zoom Meeting (Webcam + Microphone)' });
  const [leaseReason, setLeaseReason] = useState('Executive security architecture review call');
  const [ledger, setLedger] = useState(initialLedger);
  const [notice, setNotice] = useState('');
  const nextEventNumber = useRef(8842);

  const selectedApp = applications.find((application) => application.id === selectedId) ?? applications[0];
  const remainingPercent = Math.max(0, Math.round((remainingSeconds / leaseDurationSeconds) * 100));

  useEffect(() => {
    if (!leaseActive || remainingSeconds <= 0) return;
    const timer = window.setInterval(() => {
      setRemainingSeconds((seconds) => Math.max(0, seconds - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [leaseActive, remainingSeconds > 0]);

  useEffect(() => {
    if (remainingSeconds === 0 && leaseActive) setLeaseActive(false);
  }, [leaseActive, remainingSeconds]);

  const appendLedgerEntry = async (entry: Omit<LedgerEntry, 'hash'>) => {
    let hash = 'SHA-256 unavailable';
    if (window.crypto?.subtle) {
      try {
        hash = await sha256(`${entry.id}|${entry.timestamp}|${entry.app}|${entry.reason}|${entry.duration}|${entry.status}`);
      } catch {
        hash = 'SHA-256 unavailable';
      }
    }
    setLedger((entries) => [{ ...entry, hash }, ...entries]);
  };

  const handleAuthorize = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const cleanReason = reason.trim();
    if (!cleanReason) return;

    const eventId = `LOG-${nextEventNumber.current++}`;
    const timestamp = timestampNow();
    const duration = `${selectedMinutes} min`;
    await appendLedgerEntry({
      id: eventId,
      timestamp,
      app: selectedApp.shortName,
      reason: cleanReason,
      duration,
      status: 'ACTIVE',
    });
    setLeaseApp(selectedApp);
    setLeaseReason(cleanReason);
    setLeaseDurationSeconds(selectedMinutes * 60);
    setRemainingSeconds(selectedMinutes * 60);
    setLeaseActive(true);
    setReason('');
    setNotice(`${selectedApp.shortName} authorized for ${selectedMinutes} minutes.`);
  };

  const handleRevoke = async () => {
    if (!leaseActive) return;
    const timestamp = timestampNow();
    const eventId = `LOG-${nextEventNumber.current++}`;
    setLeaseActive(false);
    await appendLedgerEntry({
      id: eventId,
      timestamp,
      app: leaseApp.shortName,
      reason: `Lease revoked: ${leaseReason}`,
      duration: formatRemaining(remainingSeconds),
      status: 'REVOKED',
    });
    setNotice('Access revoked. The lease has been locked.');
  };

  return (
    <main className="tap-shell">
      <header className="tap-header">
        <div className="tap-brand">
          <span className="tap-brand-mark"><ShieldCheck size={21} strokeWidth={1.8} /></span>
          <div>
            <p className="tap-kicker">SURFACEGUARD <span>/</span> ACCESS CONTROL</p>
            <h1>Temporary App Permissions</h1>
          </div>
        </div>
        <div className="tap-header-meta"><span className="tap-live-dot" /> POLICY ENGINE ONLINE <span className="tap-meta-divider" /> DEVICE SG-04</div>
      </header>

      <div className="tap-content">
        <section className="tap-lease" aria-labelledby="tap-lease-title">
          <div className="tap-lease-main">
            <div className="tap-section-label"><span className="tap-section-index">01</span> CURRENT TEMPORARY ACCESS LEASE</div>
            <div className="tap-lease-heading">
              <div>
                <span className={`tap-status-pill ${leaseActive ? 'is-active' : 'is-locked'}`}>
                  {leaseActive ? <Activity size={13} /> : <LockKeyhole size={13} />}
                  {leaseActive ? 'TEMPORARY ACCESS ACTIVE' : 'ACCESS LOCKED'}
                </span>
                <h2 id="tap-lease-title">{leaseApp.shortName}</h2>
                <p className="tap-lease-subtitle">{leaseApp.label}</p>
              </div>
              <div className="tap-countdown" aria-live="polite">
                <span className="tap-countdown-label"><Clock3 size={13} /> REMAINING TIME</span>
                <strong>{formatRemaining(remainingSeconds)}</strong>
                <span className="tap-countdown-note">{remainingPercent}% of lease remaining</span>
              </div>
            </div>
            <div className="tap-progress-track"><span style={{ width: `${remainingPercent}%` }} /></div>
            <div className="tap-lease-reason"><span>JUSTIFICATION</span><p>{leaseReason}</p></div>
          </div>
          <div className="tap-lease-action">
            <div className="tap-lease-action-icon"><ShieldX size={19} /></div>
            <p>End this session immediately and lock the requested resource.</p>
            <button type="button" className="tap-revoke-button" onClick={handleRevoke} disabled={!leaseActive}>
              <LockKeyhole size={15} /> Revoke &amp; Lock Now
            </button>
          </div>
        </section>

        <div className="tap-workspace-grid">
          <section className="tap-panel tap-request-panel" aria-labelledby="tap-request-title">
            <div className="tap-panel-heading">
              <div><div className="tap-section-label"><span className="tap-section-index">02</span> REQUEST ACCESS</div><h2 id="tap-request-title">Authorize an application</h2></div>
              <span className="tap-heading-icon"><FileKey2 size={19} /></span>
            </div>

            <form onSubmit={handleAuthorize}>
              <label className="tap-field-label" htmlFor="tap-app-select">APPLICATION</label>
              <div className="tap-select-wrap">
                <select id="tap-app-select" value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
                  {applications.map((application) => <option key={application.id} value={application.id}>{application.icon}  {application.label}</option>)}
                </select>
                <ArrowUpRight className="tap-select-indicator" size={15} />
              </div>

              <div className="tap-field-label tap-duration-label">TIME WINDOW <span>Maximum 60 minutes</span></div>
              <div className="tap-duration-options" role="group" aria-label="Lease duration">
                {durationOptions.map((option) => (
                  <button
                    className={`tap-duration-option ${selectedMinutes === option.minutes ? 'is-selected' : ''}`}
                    key={option.minutes}
                    type="button"
                    aria-pressed={selectedMinutes === option.minutes}
                    onClick={() => setSelectedMinutes(option.minutes)}
                  >
                    <span className="tap-duration-check">{selectedMinutes === option.minutes && <Check size={11} />}</span>
                    <strong>{option.title}</strong><small>{option.note}</small>
                  </button>
                ))}
              </div>

              <label className="tap-field-label tap-reason-label" htmlFor="tap-reason">REASON FOR ACCESS <span>Mandatory audit trail</span></label>
              <textarea id="tap-reason" value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Describe the business need for this access..." rows={3} required maxLength={240} />

              <button className="tap-authorize-button" type="submit" disabled={!reason.trim()}>
                <Plus size={16} /> Authorize {selectedApp.shortName} ({selectedMinutes} min)
                <ArrowUpRight className="tap-authorize-arrow" size={15} />
              </button>
              {notice && <p className="tap-notice" role="status"><Check size={13} />{notice}</p>}
            </form>
          </section>

          <section className="tap-panel tap-impact-panel" aria-labelledby="tap-impact-title">
            <div className="tap-panel-heading">
              <div><div className="tap-section-label"><span className="tap-section-index">03</span> ACCESS DETAILS</div><h2 id="tap-impact-title">Security impact</h2></div>
              <span className="tap-heading-icon"><Fingerprint size={19} /></span>
            </div>
            <div className="tap-impact-app"><span className="tap-app-symbol">{selectedApp.icon}</span><div><small>SELECTED APPLICATION</small><strong>{selectedApp.shortName}</strong></div></div>
            <div className="tap-impact-detail">
              <span className="tap-detail-icon tap-video-icon"><Video size={15} /></span>
              <div><span>WHAT WILL BE ENABLED</span><p>{selectedApp.enabled}</p></div>
            </div>
            <div className="tap-impact-detail">
              <span className="tap-detail-icon tap-mechanism-icon"><Network size={15} /></span>
              <div><span>UNDERLYING OS MECHANISM</span><p>{selectedApp.mechanism}</p></div>
            </div>
            <div className="tap-risk-row">
              <div><span className="tap-detail-icon tap-risk-icon"><AlertTriangle size={15} /></span><div><span>SECURITY RISK RATING</span><strong className={`tap-risk-value ${selectedApp.risk.toLowerCase().replace(' ', '-')}`}>{selectedApp.risk}</strong></div></div>
              <span className="tap-risk-context">Scoped to this lease</span>
            </div>
            <div className="tap-impact-footnote"><LockKeyhole size={13} /> Permissions automatically expire when the lease ends.</div>
          </section>
        </div>

        <section className="tap-panel tap-ledger-panel" aria-labelledby="tap-ledger-title">
          <div className="tap-panel-heading tap-ledger-heading">
            <div><div className="tap-section-label"><span className="tap-section-index">04</span> IMMUTABLE CRYPTOGRAPHIC AUDIT TRAIL</div><h2 id="tap-ledger-title">SHA-256 access ledger</h2></div>
            <div className="tap-ledger-seal"><Fingerprint size={16} /> SHA-256 EVENT JOURNAL <span className="tap-seal-dot" /></div>
          </div>
          <div className="tap-table-scroll">
            <table>
              <thead><tr><th>EVENT ID</th><th>TIMESTAMP</th><th>AUTHORIZED APPLICATION</th><th>DURATION</th><th>STATUS</th><th>SHA-256 HASH</th></tr></thead>
              <tbody>
                {ledger.slice(0, 3).map((entry) => (
                  <tr key={entry.id}>
                    <td className="tap-event-id">{entry.id}</td>
                    <td className="tap-timestamp">{entry.timestamp}</td>
                    <td className="tap-app-cell"><strong>{entry.app}</strong><span>{entry.reason}</span></td>
                    <td className="tap-duration-cell">{entry.duration}</td>
                    <td><span className={`tap-ledger-status status-${entry.status.toLowerCase()}`}><i />{entry.status}</span></td>
                    <td className="tap-hash-cell" title={entry.hash}>{entry.hash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="tap-ledger-footer"><span><LockKeyhole size={12} /> JOURNAL ENTRIES ARE APPEND-ONLY</span><span>SHOWING LATEST {Math.min(ledger.length, 3).toString().padStart(2, '0')} EVENTS <span className="tap-ledger-footer-divider">/</span> SHA-256</span></div>
        </section>

        <footer className="tap-footer"><span><ShieldCheck size={14} /> TEMPORARY ACCESS CONTROL</span><span>Every request is scoped, time-bound, and recorded <span className="tap-footer-separator">·</span> <Camera size={12} /><Mic2 size={12} /><Monitor size={12} /><Code2 size={12} /></span></footer>
      </div>
    </main>
  );
}