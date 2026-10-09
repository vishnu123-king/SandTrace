import React from 'react';
import { Severity } from '../types';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '', size = 'md' }) => {
  const styles: Record<Severity, { bg: string; text: string; border: string }> = {
    CRITICAL: {
      bg: 'bg-rose-950/40',
      text: 'text-rose-400',
      border: 'border-rose-800/60',
    },
    HIGH: {
      bg: 'bg-orange-950/40',
      text: 'text-orange-400',
      border: 'border-orange-800/60',
    },
    MEDIUM: {
      bg: 'bg-amber-950/40',
      text: 'text-amber-400',
      border: 'border-amber-800/60',
    },
    LOW: {
      bg: 'bg-emerald-950/30',
      text: 'text-emerald-400',
      border: 'border-emerald-800/50',
    },
    INFO: {
      bg: 'bg-slate-900/60',
      text: 'text-slate-400',
      border: 'border-slate-800',
    },
  };

  const style = styles[severity] || styles.INFO;
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded border ${style.bg} ${style.text} ${style.border} ${sizeClasses} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
      {severity}
    </span>
  );
};
