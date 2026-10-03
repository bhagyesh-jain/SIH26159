import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, Activity, HardDrive, CheckCircle2, XCircle } from "lucide-react";
import { getHealthStatus } from "../../api/health";
import { HealthResponse } from "../../types/api";

interface SOCLayoutProps {
  children: React.ReactNode;
}

export const SOCLayout: React.FC<SOCLayoutProps> = ({ children }) => {
  const location = useLocation();
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    getHealthStatus()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans">
      {/* Top SOC Navbar */}
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <Link to="/" className="flex items-center gap-2.5 group">
              <div className="p-1.5 bg-cyan-950/80 border border-cyan-700/60 rounded text-cyan-400 group-hover:border-cyan-500 transition-colors">
                <Shield className="w-5 h-5" />
              </div>
              <span className="font-mono font-bold text-base tracking-wider text-slate-100">
                SecureMailScope
              </span>
              <span className="text-[10px] font-mono uppercase bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded border border-slate-700">
                v0.1.0 SOC
              </span>
            </Link>

            <nav className="flex items-center gap-1">
              <Link
                to="/investigations"
                className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors ${
                  location.pathname.startsWith("/investigations") || location.pathname === "/"
                    ? "bg-slate-800 text-cyan-400 border border-slate-700"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                }`}
              >
                Investigations
              </Link>
            </nav>
          </div>

          {/* System Health Indicator */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded">
              <Activity className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">Backend:</span>
              {health ? (
                <span className="flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="w-3 h-3" /> Healthy
                </span>
              ) : (
                <span className="flex items-center gap-1 text-red-400">
                  <XCircle className="w-3 h-3" /> Offline
                </span>
              )}
            </div>

            <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded hidden sm:flex">
              <HardDrive className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">TShark:</span>
              <span className="text-slate-300">
                {health?.tshark.available ? health.tshark.version : "N/A"}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-3 text-center text-xs font-mono text-slate-500">
        SecureMailScope — Passive Network Forensic Application for Email Cryptographic Assessment (SIH 26159)
      </footer>
    </div>
  );
};
