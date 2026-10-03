import React from "react";
import { Shield, AlertTriangle, Lock, FileWarning, XCircle, CheckCircle2 } from "lucide-react";
import { SecurityPostureSummary } from "../../types/api";

interface SecurityPostureGridProps {
  posture: SecurityPostureSummary;
}

export const SecurityPostureGrid: React.FC<SecurityPostureGridProps> = ({ posture }) => {
  const items = [
    {
      title: "Plaintext / Encryption Upgrade Not Offered",
      rule: "EMAIL-PLAINTEXT-NOT-OFFERED-001",
      count: posture.plaintext_not_offered_sessions,
      icon: AlertTriangle,
      color: "text-amber-400 border-amber-800/60 bg-amber-950/20",
    },
    {
      title: "STARTTLS Offered But Not Used",
      rule: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
      count: posture.starttls_offered_not_used_sessions,
      icon: Shield,
      color: "text-red-400 border-red-800/60 bg-red-950/20",
    },
    {
      title: "Weak Static RSA Key Exchange (No PFS)",
      rule: "TLS-WEAK-STATIC-RSA-001",
      count: posture.weak_static_rsa_sessions,
      icon: Lock,
      color: "text-amber-400 border-amber-800/60 bg-amber-950/20",
    },
    {
      title: "Certificate Alert Observations",
      rule: "TLS-ALERT-CERT-OBSERVED-001",
      count: posture.certificate_alert_sessions,
      icon: FileWarning,
      color: "text-amber-400 border-amber-800/60 bg-amber-950/20",
    },
    {
      title: "TLS Handshake Abort / TCP Reset",
      rule: "TLS-HANDSHAKE-FAILED-001",
      count: posture.handshake_failed_sessions,
      icon: XCircle,
      color: "text-blue-400 border-blue-800/60 bg-blue-950/20",
    },
    {
      title: "Verified Secure TLS Baselines",
      rule: "TLS-SECURE-BASELINE-001",
      count: posture.secure_baseline_sessions,
      icon: CheckCircle2,
      color: "text-emerald-400 border-emerald-800/60 bg-emerald-950/20",
    },
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-sans">
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" /> Cryptographic Security Posture Breakdown
        </h3>
        <span className="text-[10px] font-mono text-slate-500">Affected Sessions Count</span>
      </div>

      <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
        {items.map((item) => {
          const IconComp = item.icon;
          return (
            <div
              key={item.rule}
              className={`p-3 rounded border flex items-center justify-between transition-colors ${item.color}`}
            >
              <div className="space-y-1 pr-2">
                <div className="font-bold text-slate-200 text-xs flex items-center gap-1.5">
                  <IconComp className="w-3.5 h-3.5 flex-shrink-0" />
                  <span className="truncate" title={item.title}>{item.title}</span>
                </div>
                <div className="text-[10px] text-slate-400 font-mono">{item.rule}</div>
              </div>
              <div className="text-lg font-bold pl-2 flex-shrink-0">
                {item.count}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
