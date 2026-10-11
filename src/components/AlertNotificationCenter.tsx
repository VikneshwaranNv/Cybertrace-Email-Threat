import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  X,
  ExternalLink,
  Flame,
} from 'lucide-react';
import { AlertEvent } from '../types/forensics';
import { createAlertStream, fetchAlertHistory } from '../services/api';

interface AlertNotificationCenterProps {
  onNavigate: (page: any) => void;
  onSelectCase?: (caseId: string) => void;
}

export const AlertNotificationCenter: React.FC<AlertNotificationCenterProps> = ({
  onNavigate,
  onSelectCase,
}) => {
  const [activeToasts, setActiveToasts] = useState<AlertEvent[]>([]);

  useEffect(() => {
    // Connect to SSE stream
    const unsubscribe = createAlertStream((alert) => {
      // Add to toast stack
      setActiveToasts((prev) => [alert, ...prev.slice(0, 4)]);

      // Auto-dismiss HIGH/MEDIUM/LOW after 8 seconds (CRITICAL stays until dismissed)
      if (alert.severity !== 'CRITICAL') {
        setTimeout(() => {
          setActiveToasts((prev) => prev.filter((t) => t.id !== alert.id));
        }, 8000);
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const dismissToast = (id: string) => {
    setActiveToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const handleInspectCase = (alert: AlertEvent) => {
    dismissToast(alert.id);
    if (alert.caseId && onSelectCase) {
      onSelectCase(alert.caseId);
    }
    onNavigate('investigation');
  };

  return (
    <>
      {/* Floating Toast Notification Stack (Top-Right) */}
      <div className="fixed top-20 right-6 z-50 flex flex-col gap-3 max-w-sm w-full pointer-events-none font-sans select-none">
        {activeToasts.map((toast) => {
          const isCritical = toast.severity === 'CRITICAL';
          const isHigh = toast.severity === 'HIGH';

          return (
            <div
              key={toast.id}
              className={`pointer-events-auto rounded-xl border p-4 shadow-xl transition-all animate-in fade-in slide-in-from-top-4 duration-300 ${
                isCritical
                  ? 'bg-red-50 border-red-300 text-red-950 shadow-red-500/10'
                  : isHigh
                  ? 'bg-amber-50 border-amber-300 text-amber-950 shadow-amber-500/10'
                  : 'bg-blue-50 border-blue-200 text-blue-950 shadow-blue-500/10'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  {isCritical ? (
                    <Flame className="w-5 h-5 text-red-600 animate-pulse flex-shrink-0" />
                  ) : (
                    <ShieldAlert className="w-5 h-5 text-amber-600 flex-shrink-0" />
                  )}
                  <span
                    className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                      isCritical
                        ? 'bg-red-200/80 text-red-800'
                        : isHigh
                        ? 'bg-amber-200/80 text-amber-800'
                        : 'bg-blue-200/80 text-blue-800'
                    }`}
                  >
                    {toast.severity} THREAT
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {new Date(toast.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <button
                  onClick={() => dismissToast(toast.id)}
                  className="text-slate-400 hover:text-slate-700 p-0.5 rounded cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="mt-2 text-xs font-bold text-slate-900 leading-snug">
                {toast.title}
              </div>
              <p className="mt-1 text-[11px] text-slate-600 leading-relaxed line-clamp-2">
                {toast.description}
              </p>

              <div className="mt-3 pt-2.5 border-t border-slate-200/60 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 font-mono">
                  Src: {toast.source}
                </span>
                {toast.caseId ? (
                  <button
                    onClick={() => handleInspectCase(toast)}
                    className="text-xs font-semibold text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
                  >
                    <span>Inspect Case</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                ) : (
                  <button
                    onClick={() => {
                      dismissToast(toast.id);
                      onNavigate('gmail-monitor');
                    }}
                    className="text-xs font-semibold text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
                  >
                    <span>View Monitor</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
};
