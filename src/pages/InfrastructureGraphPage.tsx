import React, { useState, useRef } from 'react';
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Info,
  Maximize2,
  ExternalLink,
  ShieldAlert,
  Server,
  Globe,
  Mail,
  Fingerprint,
  FileCode,
  Hash,
  Shield,
  Search,
  CheckCircle2,
} from 'lucide-react';
import { GraphEdge, GraphNode, InvestigationGraphData } from '../types/forensics';

interface InfrastructureGraphPageProps {
  graphData: InvestigationGraphData | null;
  onSelectCase?: (caseId: string) => void;
}

export const InfrastructureGraphPage: React.FC<InfrastructureGraphPageProps> = ({
  graphData,
  onSelectCase,
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const containerRef = useRef<HTMLDivElement | null>(null);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-sm">
        <Network className="w-12 h-12 text-slate-300 mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-800">No Graph Data Available</h3>
        <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
          Please ingest or select an email case to generate the evidence-grounded relational graph.
        </p>
      </div>
    );
  }

  // Canvas dimensions
  const width = 850;
  const height = 550;
  const centerX = width / 2;
  const centerY = height / 2;

  // Compute layout positions for 9 node types
  const nodePositions: Record<string, { x: number; y: number }> = {};
  const totalNodes = graphData.nodes.length;

  graphData.nodes.forEach((node, idx) => {
    const normType = node.type.toLowerCase();
    if (normType === 'email') {
      nodePositions[node.id] = { x: centerX, y: centerY };
    } else {
      let radius = 180;
      if (normType === 'campaign' || normType === 'technique') {
        radius = 240;
      } else if (normType === 'domain' || normType === 'ip') {
        radius = 190;
      } else if (normType === 'hash' || normType === 'ioc') {
        radius = 150;
      }

      const angle = ((idx - 1) / (totalNodes - 1)) * Math.PI * 2;
      nodePositions[node.id] = {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
      };
    }
  });

  const getNodeColor = (type: GraphNode['type'], risk?: string) => {
    if (risk === 'CRITICAL') return { fill: '#dc2626', border: '#b91c1c', glow: 'rgba(220,38,38,0.15)' };
    if (risk === 'HIGH') return { fill: '#f59e0b', border: '#d97706', glow: 'rgba(245,158,11,0.15)' };

    const normType = type.toLowerCase();
    switch (normType) {
      case 'email':
        return { fill: '#0284c7', border: '#0369a1', glow: 'rgba(2,132,199,0.15)' };
      case 'sender':
        return { fill: '#2563eb', border: '#1d4ed8', glow: 'rgba(37,99,235,0.15)' };
      case 'domain':
        return { fill: '#7c3aed', border: '#6d28d9', glow: 'rgba(124,58,237,0.15)' };
      case 'ip':
        return { fill: '#059669', border: '#047857', glow: 'rgba(5,150,105,0.15)' };
      case 'url':
        return { fill: '#9333ea', border: '#7e22ce', glow: 'rgba(147,51,234,0.15)' };
      case 'hash':
        return { fill: '#d97706', border: '#b45309', glow: 'rgba(217,119,6,0.15)' };
      case 'ioc':
        return { fill: '#ea580c', border: '#c2410c', glow: 'rgba(234,88,12,0.15)' };
      case 'campaign':
        return { fill: '#c026d3', border: '#a21caf', glow: 'rgba(192,38,211,0.15)' };
      case 'technique':
        return { fill: '#db2777', border: '#be185d', glow: 'rgba(219,39,119,0.15)' };
      default:
        return { fill: '#64748b', border: '#475569', glow: 'rgba(100,116,139,0.15)' };
    }
  };

  return (
    <div id="infrastructure-graph-view" className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Evidence-Grounded Investigation Graph
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Interactive relational topology connecting Email, Senders, Domains, IPs, URLs, Hashes, IOCs, Campaigns, and MITRE Techniques
            </p>
          </div>
        </div>

        {/* Zoom and Reset Controls */}
        <div className="flex items-center gap-1.5 bg-slate-100 border border-slate-200 p-1.5 rounded-lg">
          <button
            onClick={() => setZoom(z => Math.min(1.8, z + 0.15))}
            className="p-1.5 rounded-md text-slate-600 hover:bg-white hover:text-slate-900 transition-colors cursor-pointer"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoom(z => Math.max(0.6, z - 0.15))}
            className="p-1.5 rounded-md text-slate-600 hover:bg-white hover:text-slate-900 transition-colors cursor-pointer"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoom(1)}
            className="p-1.5 rounded-md text-slate-600 hover:bg-white hover:text-slate-900 text-xs font-medium transition-colors cursor-pointer"
            title="Reset Zoom"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Canvas & Inspector Drawer Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph SVG Canvas */}
        <div
          ref={containerRef}
          className="lg:col-span-2 bg-slate-50/70 border border-slate-200 rounded-xl overflow-hidden relative min-h-[520px] flex items-center justify-center select-none shadow-sm"
        >
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-full"
            style={{ transform: `scale(${zoom})`, transformOrigin: 'center center', transition: 'transform 0.2s ease-out' }}
          >
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
              </marker>
            </defs>

            {/* Edges with relationships */}
            {graphData.edges.map(edge => {
              const srcPos = nodePositions[edge.source];
              const tgtPos = nodePositions[edge.target];
              if (!srcPos || !tgtPos) return null;

              const midX = (srcPos.x + tgtPos.x) / 2;
              const midY = (srcPos.y + tgtPos.y) / 2;

              return (
                <g key={edge.id}>
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke="#cbd5e1"
                    strokeWidth="1.5"
                    strokeDasharray={edge.label === 'CORRELATED_WITH' ? '4,4' : undefined}
                    markerEnd="url(#arrow)"
                  />
                  <text
                    x={midX}
                    y={midY - 4}
                    fill="#64748b"
                    fontSize="9"
                    fontFamily="sans-serif"
                    fontWeight="600"
                    textAnchor="middle"
                    className="select-none pointer-events-none"
                  >
                    {edge.label}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {graphData.nodes.map(node => {
              const pos = nodePositions[node.id];
              if (!pos) return null;
              const isSelected = selectedNode?.id === node.id;
              const colors = getNodeColor(node.type, node.risk);

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  className="cursor-pointer group"
                  onClick={() => setSelectedNode(node)}
                >
                  <circle
                    r={isSelected ? 26 : 20}
                    fill={colors.glow}
                    className="transition-all duration-300"
                  />
                  <circle
                    r={isSelected ? 18 : 14}
                    fill={colors.fill}
                    stroke={isSelected ? '#0f172a' : colors.border}
                    strokeWidth={isSelected ? 3 : 2}
                    className="transition-all duration-200"
                  />
                  <text
                    y={isSelected ? 30 : 26}
                    fill="#0f172a"
                    fontSize="10"
                    fontFamily="sans-serif"
                    fontWeight="700"
                    textAnchor="middle"
                    className="select-none pointer-events-none drop-shadow-sm"
                  >
                    {node.label.length > 22 ? node.label.substring(0, 22) + '...' : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Legend Overlay in Bottom Left */}
          <div className="absolute bottom-3 left-3 bg-white/95 border border-slate-200 p-3 rounded-xl text-[11px] space-y-1.5 text-slate-700 shadow-sm backdrop-blur-xs">
            <div className="font-bold text-slate-900 uppercase text-[10px] tracking-wider mb-1">Entity Legend:</div>
            <div className="flex flex-wrap gap-2.5 max-w-sm">
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-sky-600" /> Email</span>
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-blue-600" /> Sender</span>
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-purple-600" /> Domain</span>
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-emerald-600" /> IP</span>
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-fuchsia-600" /> URL</span>
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-amber-600" /> Hash</span>
              <span className="flex items-center gap-1 font-medium"><span className="w-2.5 h-2.5 rounded-full bg-pink-600" /> Campaign</span>
            </div>
          </div>
        </div>

        {/* Node Evidence Inspector Drawer */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-5">
          <div className="border-b border-slate-100 pb-3">
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 uppercase tracking-wider">
              Evidence Inspector
            </span>
            <h3 className="text-base font-bold text-slate-900 mt-2 break-words">
              {selectedNode ? selectedNode.label : 'Select an Entity Node'}
            </h3>
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-slate-500 font-medium">Node Type:</span>
                  <span className="font-bold text-blue-700 uppercase">{selectedNode.type}</span>
                </div>
                {selectedNode.risk && (
                  <div className="flex justify-between items-center">
                    <span className="text-slate-500 font-medium">Risk Severity:</span>
                    <span className="font-bold text-red-600">{selectedNode.risk}</span>
                  </div>
                )}
                <div className="flex justify-between items-center">
                  <span className="text-slate-500 font-medium">Entity ID:</span>
                  <span className="text-slate-800 font-mono text-[11px] truncate max-w-[150px]">{selectedNode.id}</span>
                </div>
              </div>

              {/* Explicit Evidence Grounding */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Grounded Evidence Details
                </span>
                <div className="p-3 rounded-xl bg-blue-50/40 border border-blue-100 text-slate-800 text-xs leading-relaxed">
                  {selectedNode.evidenceDetails || 'Forensic artifact observed in ingested RFC-822 bitstream.'}
                </div>
              </div>

              {/* Evidence References */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                  Supporting Evidence References
                </span>
                <div className="space-y-1">
                  {selectedNode.evidenceReferences && selectedNode.evidenceReferences.length > 0 ? (
                    selectedNode.evidenceReferences.map((ref, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded-lg bg-slate-50 border border-slate-200 text-slate-800 font-mono text-[11px] flex items-center gap-2"
                      >
                        <Shield className="w-3 h-3 text-blue-600 flex-shrink-0" />
                        <span className="truncate">{ref}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-400 italic">MIME bitstream source</div>
                  )}
                </div>
              </div>

              {/* Connected Relationships with Evidence */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                  Verified Relational Edges
                </span>
                <div className="space-y-2 text-xs max-h-48 overflow-y-auto">
                  {graphData.edges
                    .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map(e => (
                      <div
                        key={e.id}
                        className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-blue-700 font-bold">{e.label}</span>
                          <span className="text-[10px] font-medium text-slate-400 uppercase">{e.source === selectedNode.id ? 'Outgoing' : 'Incoming'}</span>
                        </div>
                        <div className="text-xs text-slate-600">{e.evidence}</div>
                        <div className="text-[11px] text-slate-400 font-mono">Ref: {e.evidenceReference}</div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-400 text-center py-14 space-y-2">
              <Network className="w-10 h-10 text-slate-300 mx-auto" />
              <p className="text-slate-600 font-medium">Click on any entity in the network canvas to inspect its grounded evidence and forensic references.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
