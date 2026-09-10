import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  SearchCode,
  Bot,
  ScrollText,
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
  { label: 'Investigations', path: '/investigations', icon: SearchCode, description: 'Alert-scoped context' },
  { label: 'AI Copilot', path: '/copilot', icon: Bot, description: 'AI-assisted analysis' },
  { label: 'Audit Logs', path: '/audits', icon: ScrollText, description: 'Administrative accountability' },
]
