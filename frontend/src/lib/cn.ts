import { clsx, type ClassValue } from 'clsx'

/** Thin wrapper so every component composes classes the same way. */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs)
}
