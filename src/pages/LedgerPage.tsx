import React, { useState, useEffect } from 'react';
import {
  Link2,
  CheckCircle2,
  AlertOctagon,
  ShieldCheck,
  RefreshCw,
  Zap,
  Wrench,
  Info,
  Hash,
  Clock,
  UserCheck,
  ArrowDown,
} from 'lucide-react';
import { EvidenceBlock, LedgerVerificationResult } from '../types/forensics';
import {
  fetchLedger,
  resealLedger,
  simulateLedgerTamper,
  verifyLedgerIntegrity,
} from '../services/api';

export const LedgerPage: React.FC = () => {
  const [blocks, setBlocks] = useState<EvidenceBlock[]>([]);
  const [verification, setVerification] = useState<LedgerVerificationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchLedger();
      setBlocks(data.chain || []);
      setVerification(data.verification);
    } catch (err: any) {
      console.error('Failed to fetch ledger:', err);
      setError(err?.message || 'Failed to retrieve evidence ledger');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleVerify = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await verifyLedgerIntegrity();
      setVerification(res);
      setActionMessage(res.isValid ? 'Ledger verified: All SHA-256 hashes intact.' : 'Warning: Integrity check detected broken hash link!');
    } catch (err: any) {
      console.error(err);
      setError(err?.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleTamper = async () => {
    try {
      setLoading(true);
      setError(null);
      const targetIndex = blocks.length > 1 ? 1 : 0;
      await simulateLedgerTamper(targetIndex);
      await loadData();
      setActionMessage(`Tamper simulation executed on Block #${targetIndex}. Bitstream payload altered.`);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || 'Tamper simulation failed (Admin role required)');
    } finally {
      setLoading(false);
    }
  };

  const handleReseal = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await resealLedger();
      setVerification(res);
      await loadData();
      setActionMessage('Cryptographic chain repaired and resealed by Forensic Officer.');
    } catch (err: any) {
      console.error(err);
      setError(err?.message || 'Reseal failed (Admin role required)');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="evidence-ledger-view" className="space-y-6 pb-12">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-800 rounded-xl p-4 flex items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-red-600 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={loadData}
            className="px-3 py-1 bg-red-600 text-white rounded-md hover:bg-red-700 cursor-pointer font-medium"
          >
            Retry
          </button>
        </div>
      )}
      {/* Top Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center flex-shrink-0">
              <Link2 className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Evidence Integrity Blockchain Ledger
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Private tamper-evident cryptographic hash-chain securing digital forensic evidence records for court admissibility
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              id="btn-verify-ledger"
              onClick={handleVerify}
              disabled={loading}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white flex items-center gap-2 shadow-xs transition-colors cursor-pointer disabled:opacity-50"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Verify Integrity</span>
            </button>

            <button
              id="btn-tamper-ledger"
              onClick={handleTamper}
              disabled={loading}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 flex items-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
            >
              <Zap className="w-4 h-4 text-red-600" />
              <span>Simulate Tamper</span>
            </button>

            <button
              id="btn-reseal-ledger"
              onClick={handleReseal}
              disabled={loading}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 flex items-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
            >
              <Wrench className="w-4 h-4 text-blue-600" />
              <span>Repair & Reseal</span>
            </button>
          </div>
        </div>

        {/* Action message flash */}
        {actionMessage && (
          <div className="p-3 rounded-lg bg-blue-50 border border-blue-200 text-xs font-semibold text-blue-800 flex items-center gap-2">
            <span>›</span>
            <span>{actionMessage}</span>
          </div>
        )}

        {/* Verification Status Banner */}
        {verification && (
          <div
            className={`p-4 rounded-xl border flex flex-wrap items-center justify-between gap-3 ${
              verification.isValid
                ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                : 'bg-red-50 border-red-200 text-red-900'
            }`}
          >
            <div className="flex items-center gap-3">
              {verification.isValid ? (
                <div className="w-8 h-8 rounded-full bg-emerald-100 flex items-center justify-center flex-shrink-0">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                </div>
              ) : (
                <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center flex-shrink-0 animate-pulse">
                  <AlertOctagon className="w-5 h-5 text-red-600" />
                </div>
              )}
              <div>
                <div className="text-sm font-bold">
                  {verification.statusMessage}
                </div>
                <div className="text-xs opacity-90 mt-0.5">
                  {verification.isValid
                    ? `Cryptographic mathematical verification succeeded across ${verification.totalBlocks} sealed blocks.`
                    : `INTEGRITY COMPROMISED: Block #${verification.invalidBlockIndex} failed hash recomputation audit!`}
                </div>
              </div>
            </div>

            <span className="text-xs text-slate-500 font-medium">
              Verified: {verification.verifiedAt}
            </span>
          </div>
        )}

        {/* Broken Link Warning Details if Tampered */}
        {verification && !verification.isValid && verification.brokenLinkDetails && (
          <div className="p-4 rounded-xl bg-red-50/80 border border-red-200 text-xs space-y-2 text-red-900">
            <div className="font-bold uppercase text-red-800 text-xs tracking-wider">Forensic Anomaly Audit Trail:</div>
            <div className="text-xs text-red-700">{verification.brokenLinkDetails.reason}</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1 font-mono">
              <div className="p-2.5 rounded-lg bg-white border border-red-200">
                <span className="text-slate-500 block text-[11px] font-sans uppercase font-semibold mb-1">Expected SHA-256</span>
                <span className="text-slate-800 select-all break-all text-[11px]">{verification.brokenLinkDetails.expectedHash}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-white border border-red-300">
                <span className="text-red-600 block text-[11px] font-sans uppercase font-semibold mb-1">Recorded In Block</span>
                <span className="text-red-700 select-all font-bold break-all text-[11px]">{verification.brokenLinkDetails.actualHash}</span>
              </div>
            </div>
          </div>
        )}

        {/* Educational Notice */}
        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 flex items-start gap-2.5">
          <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
          <span className="leading-relaxed">
            <strong className="text-slate-800">Digital Forensics Note:</strong> This is an evidence-integrity demonstration satisfying ISO/IEC 27037 chain-of-custody standards, proving that ingested email bitstreams remain cryptographically unmanipulated.
          </span>
        </div>
      </div>

      {/* Block Sequence Visualizer */}
      <div className="space-y-4">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
          Chain of Custody Blocks ({blocks.length})
        </h3>

        <div className="space-y-4">
          {blocks.map((block, idx) => {
            const isGenesis = block.blockIndex === 0;
            const isInvalid = verification && !verification.isValid && verification.invalidBlockIndex === block.blockIndex;

            return (
              <React.Fragment key={block.blockId}>
                <div
                  className={`p-6 rounded-xl border transition-all shadow-xs ${
                    block.isTampered || isInvalid
                      ? 'bg-red-50/50 border-red-300 ring-1 ring-red-300'
                      : 'bg-white border-slate-200'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between pb-3.5 border-b border-slate-100 gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="px-3 py-1 rounded-lg bg-slate-100 border border-slate-200 text-xs font-bold text-slate-800 font-mono">
                        {block.blockId} (Index #{block.blockIndex})
                      </span>
                      {isGenesis && (
                        <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-semibold">
                          GENESIS ANCHOR
                        </span>
                      )}
                      {block.isTampered && (
                        <span className="px-2.5 py-0.5 rounded-full bg-red-100 text-red-700 border border-red-200 text-[11px] font-bold">
                          UNAUTHORIZED MODIFICATION
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-slate-500 font-medium">
                      <Clock className="w-3.5 h-3.5" />
                      <span>{block.timestamp}</span>
                    </div>
                  </div>

                  {/* Block Hash Data Grid */}
                  <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs font-mono">
                    {/* Previous Hash */}
                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-[11px] text-slate-500 font-sans uppercase font-semibold block">Previous Block Hash</span>
                      <span className="text-slate-700 text-[11px] break-all select-all block">
                        {block.prevBlockHash}
                      </span>
                    </div>

                    {/* Current Block Hash */}
                    <div className="p-3 rounded-lg bg-blue-50/40 border border-blue-200 space-y-1">
                      <span className="text-[11px] text-blue-800 font-sans uppercase font-bold block">
                        Current Block SHA-256 Hash
                      </span>
                      <span className="text-blue-900 text-[11px] break-all select-all font-bold block">
                        {block.blockHash}
                      </span>
                    </div>

                    {/* Email SHA-256 */}
                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-[11px] text-slate-500 font-sans uppercase font-semibold block">Email Raw Payload SHA-256</span>
                      <span
                        className={`text-[11px] break-all select-all block ${
                          block.isTampered ? 'text-red-700 font-bold' : 'text-slate-700'
                        }`}
                      >
                        {block.emailSha256}
                      </span>
                    </div>

                    {/* Analysis Hash */}
                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                      <span className="text-[11px] text-slate-500 font-sans uppercase font-semibold block">Forensic Analysis State SHA-256</span>
                      <span className="text-slate-700 text-[11px] break-all select-all block">
                        {block.analysisSha256}
                      </span>
                    </div>
                  </div>

                  {/* Metadata Footer */}
                  <div className="mt-4 pt-3.5 border-t border-slate-100 flex flex-wrap items-center justify-between text-xs text-slate-500 gap-3">
                    <div className="flex items-center gap-2">
                      <UserCheck className="w-4 h-4 text-blue-600" />
                      <span>Investigator: <strong className="text-slate-800">{block.metadata.investigator}</strong></span>
                    </div>
                    <div>
                      <span>Action: <strong className="text-slate-800">{block.metadata.action}</strong></span>
                    </div>
                    <div>
                      <span>Node Fingerprint: <strong className="text-slate-700 font-mono text-[11px]">{block.metadata.clientFingerprint}</strong></span>
                    </div>
                  </div>
                </div>

                {/* Chain Link Down Arrow */}
                {idx < blocks.length - 1 && (
                  <div className="flex justify-center -my-2 text-emerald-500">
                    <ArrowDown className="w-5 h-5" />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};
