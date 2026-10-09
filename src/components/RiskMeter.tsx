import React from 'react';

interface RiskMeterProps {
  score: number;
  rating: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW';
  size?: 'sm' | 'md' | 'lg';
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ score, rating, size = 'md' }) => {
  const getRatingColor = () => {
    switch (rating) {
      case 'CRITICAL':
        return 'text-rose-500 border-rose-500/30 bg-rose-950/20';
      case 'HIGH':
        return 'text-orange-500 border-orange-500/30 bg-orange-950/20';
      case 'ELEVATED':
        return 'text-amber-500 border-amber-500/30 bg-amber-950/20';
      case 'MODERATE':
        return 'text-yellow-500 border-yellow-500/30 bg-yellow-950/20';
      case 'LOW':
        return 'text-emerald-500 border-emerald-500/30 bg-emerald-950/20';
      default:
        return 'text-slate-400 border-slate-700 bg-slate-900';
    }
  };

  const getBarColor = () => {
    if (score >= 80) return 'bg-rose-500';
    if (score >= 60) return 'bg-orange-500';
    if (score >= 40) return 'bg-amber-500';
    if (score >= 20) return 'bg-yellow-500';
    return 'bg-emerald-500';
  };

  if (size === 'sm') {
    return (
      <div className="flex items-center space-x-2">
        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div className={`h-full ${getBarColor()}`} style={{ width: `${score}%` }} />
        </div>
        <span className={`font-mono text-xs font-semibold ${getRatingColor().split(' ')[0]}`}>
          {score}
        </span>
      </div>
    );
  }

  return (
    <div className={`p-4 rounded-lg border ${getRatingColor()}`}>
      <div className="flex items-baseline justify-between mb-2">
        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
          Repository Risk Index
        </span>
        <span className="text-xs font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-900/60 border border-current">
          {rating}
        </span>
      </div>
      <div className="flex items-baseline space-x-2 mb-3">
        <span className="text-4xl font-mono font-bold tracking-tight text-white">{score}</span>
        <span className="text-slate-500 text-sm font-mono">/ 100</span>
      </div>
      <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full ${getBarColor()} transition-all duration-500`}
          style={{ width: `${Math.max(4, score)}%` }}
        />
      </div>
    </div>
  );
};
