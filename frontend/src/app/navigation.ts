import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  SearchCode,
  Bot,
  ScrollText,
  ListChecks,
  Radio,
  Gauge,
  BarChart3,
  Stethoscope,
  FolderKanban,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  label: string
  path: string
  icon: LucideIcon
  description: string
}

export const primaryNav: NavItem[] = [
  { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard, description: 'Security operations overview' },
  { label: 'Alerts', path: '/alerts', icon: ShieldAlert, description: 'Triaged detection output' },
  { label: 'Events', path: '/events', icon: Activity, description: 'Raw security telemetry' },
  { label: 'Detection Rules', path: '/rules', icon: ListChecks, description: 'Application-controlled detection logic' },
  { label: 'Detection Operations', path: '/operations', icon: Gauge, description: 'Recent detection activity and alert priority' },
  { label: 'SOC Metrics', path: '/metrics', icon: BarChart3, description: 'Operational insights from current telemetry' },
  { label: 'Detection Health', path: '/detection-health', icon: Stethoscope, description: 'Telemetry, rule, and alert observability' },
  { label: 'Telemetry Health', path: '/telemetry', icon: Radio, description: 'Observed telemetry and detection coverage' },
  { label: 'Investigations', path: '/investigations', icon: SearchCode, description: 'Alert-scoped context' },
  { label: 'SOC Cases', path: '/cases', icon: FolderKanban, description: 'Persistent case lifecycle and ownership' },
  { label: 'AI Copilot', path: '/copilot', icon: Bot, description: 'AI-assisted analysis' },
  { label: 'Audit Logs', path: '/audits', icon: ScrollText, description: 'Administrative accountability' },
]
