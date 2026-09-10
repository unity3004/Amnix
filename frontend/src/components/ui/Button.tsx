import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'
type Size = 'sm' | 'md'

const variantClasses: Record<Variant, string> = {
  primary:
    'bg-accent text-fg-inverse hover:bg-accent-strong border border-transparent shadow-[0_0_0_1px_rgba(45,212,224,0.15)]',
  secondary: 'bg-surface-elevated text-fg border border-border-strong hover:bg-surface-hover hover:border-accent/40',
  ghost: 'bg-transparent text-fg-muted border border-transparent hover:bg-surface-hover hover:text-fg',
  danger: 'bg-danger-dim text-danger border border-danger/30 hover:bg-danger/20',
}

const sizeClasses: Record<Size, string> = {
  sm: 'h-8 px-3 text-sm gap-1.5',
  md: 'h-10 px-4 text-sm gap-2',
}

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size }>(
  ({ variant = 'secondary', size = 'md', className, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center rounded-md font-medium transition-colors duration-fast ease-out-premium disabled:cursor-not-allowed disabled:opacity-50',
          variantClasses[variant],
          sizeClasses[size],
          className,
        )}
        {...props}
      >
        {children}
      </button>
    )
  },
)
Button.displayName = 'Button'
