import React, { useEffect, useRef, useState, useMemo } from 'react';
import { Shield, Globe, Radio, AlertOctagon, Info, CheckCircle2, Layers } from 'lucide-react';
import { GeolocationResult } from '../types/forensics';
import { renderWorldMapBase, projectCoordinates } from './worldLandmassData';
import { RealWorldMap } from './RealWorldMap';

interface WorldMapCanvasProps {
  geolocations: GeolocationResult[];
  originConfidence?: number;
  originatingIp?: string;
  onSelectGeo?: (geo: GeolocationResult) => void;
}

export const WorldMapCanvas: React.FC<WorldMapCanvasProps> = ({
  geolocations = [],
  originConfidence = 85,
  originatingIp,
  onSelectGeo,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Filter routable IPs for geographic plotting
  const safeGeolocations = useMemo(() => Array.isArray(geolocations) ? geolocations : [], [geolocations]);

  const routableGeos = useMemo(
    () =>
      safeGeolocations.filter(
        g =>
          g &&
          g.geolocatable !== false &&
          typeof g.latitude === 'number' &&
          typeof g.longitude === 'number' &&
          Number.isFinite(g.latitude) &&
          Number.isFinite(g.longitude) &&
          (g.latitude !== 0 || g.longitude !== 0)
      ),
    [safeGeolocations]
  );

  const nonRoutableGeos = useMemo(
    () =>
      safeGeolocations.filter(
        g =>
          !g ||
          g.geolocatable === false ||
          typeof g.latitude !== 'number' ||
          typeof g.longitude !== 'number' ||
          !Number.isFinite(g.latitude) ||
          !Number.isFinite(g.longitude) ||
          (g.latitude === 0 && g.longitude === 0)
      ),
    [safeGeolocations]
  );

  const [selectedGeo, setSelectedGeo] = useState<GeolocationResult | null>(null);
  const [mapMode, setMapMode] = useState<'real' | 'outline'>('real');

  // Sync selected node when geolocations or originatingIp changes
  useEffect(() => {
    if (safeGeolocations.length > 0) {
      const match =
        routableGeos.find(g => g.isOriginating || g.ip === originatingIp) ||
        routableGeos[0] ||
        safeGeolocations[0] ||
        null;
      setSelectedGeo(match);
    } else {
      setSelectedGeo(null);
    }
  }, [safeGeolocations, originatingIp, routableGeos]);

  // Convert lat/lng to canvas x, y (Equirectangular projection)
  const project = (lat: number, lng: number, width: number, height: number) => {
    return projectCoordinates(lat, lng, width, height);
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let pulseOffset = 0;

    const render = () => {
      const width = canvas.width;
      const height = canvas.height;

      // Render Authentic High-Fidelity World Map (Continents, Graticules & Oceans)
      renderWorldMapBase(ctx, width, height, {
        theme: 'light',
        showGraticules: true,
      });

      // Draw MTA Relay Hop Connecting Lines for routable nodes only
      if (routableGeos.length > 1) {
        ctx.lineWidth = 2;
        ctx.setLineDash([5, 4]);

        for (let i = 0; i < routableGeos.length - 1; i++) {
          const from = project(routableGeos[i].latitude, routableGeos[i].longitude, width, height);
          const to = project(routableGeos[i + 1].latitude, routableGeos[i + 1].longitude, width, height);

          const grad = ctx.createLinearGradient(from.x, from.y, to.x, to.y);
          grad.addColorStop(0, routableGeos[i].isOriginating ? '#DC2626' : '#2563EB');
          grad.addColorStop(1, '#059669');

          ctx.strokeStyle = grad;
          ctx.beginPath();
          ctx.moveTo(from.x, from.y);

          const midX = (from.x + to.x) / 2;
          const midY = Math.min(from.y, to.y) - 25;
          ctx.quadraticCurveTo(midX, midY, to.x, to.y);
          ctx.stroke();
        }

        ctx.setLineDash([]);
      }

      // Draw IP Nodes
      pulseOffset = (pulseOffset + 0.05) % (Math.PI * 2);

      routableGeos.forEach(geo => {
        const { x, y } = project(geo.latitude, geo.longitude, width, height);
        const isOrigin = geo.isOriginating || geo.ip === originatingIp;
        const isSelected = selectedGeo?.ip === geo.ip;
        const isTor = geo.vpnTorProxy?.isTor || geo.isTor;

        // Draw Accuracy Radius circle (scaled to map bounds)
        if (geo.accuracyRadiusKm) {
          const radiusPixels = Math.max(12, Math.min(50, (geo.accuracyRadiusKm / 100) * 20));
          ctx.beginPath();
          ctx.arc(x, y, radiusPixels, 0, Math.PI * 2);
          ctx.fillStyle = isOrigin ? 'rgba(220, 38, 38, 0.08)' : 'rgba(37, 99, 235, 0.08)';
          ctx.fill();
          ctx.strokeStyle = isOrigin ? 'rgba(220, 38, 38, 0.3)' : 'rgba(37, 99, 235, 0.3)';
          ctx.lineWidth = 1;
          ctx.setLineDash([3, 3]);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // Radiating pulse for Originating or Tor IP
        if (isOrigin || isTor) {
          const pulseRadius = 10 + Math.sin(pulseOffset) * 6;
          ctx.beginPath();
          ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
          ctx.fillStyle = isOrigin ? 'rgba(220, 38, 38, 0.2)' : 'rgba(217, 119, 6, 0.2)';
          ctx.fill();
        }

        // Main Node Circle
        ctx.beginPath();
        ctx.arc(x, y, isSelected ? 8 : 6, 0, Math.PI * 2);
        ctx.fillStyle = isOrigin ? '#DC2626' : isTor ? '#D97706' : '#2563EB';
        ctx.fill();
        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = isSelected ? 2.5 : 1.5;
        ctx.stroke();

        // Node Label
        ctx.font = 'bold 11px Inter, sans-serif';
        ctx.fillStyle = '#0F172A';
        ctx.fillText(`${geo.city || geo.country} (${geo.ip})`, x + 10, y + 4);

        if (isOrigin) {
          ctx.fillStyle = '#DC2626';
          ctx.font = 'bold 9px Inter, sans-serif';
          ctx.fillText('ORIGIN INFRASTRUCTURE', x + 10, y + 16);
        } else if (isTor) {
          ctx.fillStyle = '#D97706';
          ctx.font = 'bold 9px Inter, sans-serif';
          ctx.fillText('TOR EXIT NODE', x + 10, y + 16);
        }
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [routableGeos, originatingIp, selectedGeo]);

  // Handle Canvas Resize with ResizeObserver
  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current && canvasRef.current) {
        const clientWidth = containerRef.current.clientWidth;
        const clientHeight = containerRef.current.clientHeight;
        canvasRef.current.width = Math.max(300, clientWidth || 600);
        canvasRef.current.height = Math.max(280, clientHeight || 320);
      }
    };
    handleResize();

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined' && containerRef.current) {
      resizeObserver = new ResizeObserver(() => {
        handleResize();
      });
      resizeObserver.observe(containerRef.current);
    }

    window.addEventListener('resize', handleResize);
    return () => {
      if (resizeObserver) resizeObserver.disconnect();
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <div id="geolocation-intelligence-widget" className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
      {/* Top Header */}
      <div className="p-4 bg-slate-50/80 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <Globe className="w-5 h-5 text-blue-600" />
          <div>
            <h3 className="text-base font-bold text-slate-900">
              MTA Relay Geolocation & Transit Map
            </h3>
            <p className="text-xs text-slate-500">
              Interactive hop-by-hop server localization across autonomous systems
            </p>
          </div>
        </div>

        {/* Origin Confidence Metric & Map Mode Toggle */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Mode Switcher */}
          <div className="flex items-center p-0.5 bg-slate-200/80 rounded-lg border border-slate-300">
            <button
              onClick={() => setMapMode('real')}
              className={`px-3 py-1 text-xs font-bold rounded-md transition-all cursor-pointer flex items-center gap-1.5 ${
                mapMode === 'real'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-300/50'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Real World Map</span>
            </button>
            <button
              onClick={() => setMapMode('outline')}
              className={`px-3 py-1 text-xs font-bold rounded-md transition-all cursor-pointer flex items-center gap-1.5 ${
                mapMode === 'outline'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-300/50'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Vector Outline</span>
            </button>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 flex items-center gap-2 text-xs font-semibold shadow-xs">
            <span className="text-slate-500 font-medium">Origin Confidence:</span>
            <span className="text-emerald-700 font-bold">{originConfidence}%</span>
            <span className="text-slate-400 font-normal">(High Reliability)</span>
          </div>
        </div>
      </div>

      {/* Map Display: Real Interactive Map (Default) vs Vector Canvas */}
      {mapMode === 'real' ? (
        <RealWorldMap
          geolocations={safeGeolocations}
          originConfidence={originConfidence}
          originatingIp={originatingIp}
          onSelectGeo={geo => {
            setSelectedGeo(geo);
            if (onSelectGeo) onSelectGeo(geo);
          }}
          height={500}
        />
      ) : (
        /* Canvas Outline Area */
        <div ref={containerRef} className="relative w-full h-80 bg-slate-50">
          <canvas
            ref={canvasRef}
            className="w-full h-full cursor-crosshair"
            onClick={e => {
              const canvas = canvasRef.current;
              if (!canvas) return;
              const rect = canvas.getBoundingClientRect();
              const clickX = e.clientX - rect.left;
              const clickY = e.clientY - rect.top;

              // Find closest geo node
              let closest: GeolocationResult | null = null;
              let minDist = 25;

              geolocations.forEach(g => {
                const pt = project(g.latitude, g.longitude, canvas.width, canvas.height);
                const dist = Math.hypot(clickX - pt.x, clickY - pt.y);
                if (dist < minDist) {
                  minDist = dist;
                  closest = g;
                }
              });

              if (closest) {
                setSelectedGeo(closest);
                if (onSelectGeo) onSelectGeo(closest);
              }
            }}
          />

          {/* Floating Relay Hop Selector Pill Bar on Canvas */}
          <div className="absolute top-3 left-3 flex flex-wrap gap-1.5 z-10 max-w-full">
            {geolocations.map((geo, idx) => {
              const isSelected = selectedGeo?.ip === geo.ip;
              const isOrigin = geo.isOriginating || geo.ip === originatingIp;
              const isTor = geo.isTor || geo.vpnTorProxy?.isTor;
              const isUnresolvable = geo.geolocatable === false;

              return (
                <button
                  key={geo.ip}
                  onClick={() => {
                    setSelectedGeo(geo);
                    if (onSelectGeo) onSelectGeo(geo);
                  }}
                  className={`text-xs font-semibold px-2.5 py-1 rounded-lg border transition-all flex items-center gap-1.5 cursor-pointer shadow-xs ${
                    isSelected
                      ? 'bg-blue-600 text-white border-blue-600'
                      : 'bg-white/90 backdrop-blur-xs text-slate-700 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  <span
                    className={`w-2 h-2 rounded-full ${
                      isUnresolvable
                        ? 'bg-slate-400'
                        : isOrigin
                        ? 'bg-red-500'
                        : isTor
                        ? 'bg-amber-500'
                        : 'bg-blue-500'
                    }`}
                  />
                  <span>
                    Hop #{idx + 1}: {isUnresolvable ? 'Internal/Private' : geo.country || 'Unknown'} ({geo.ip})
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Non-Routable Excluded IP Notice if any */}
      {nonRoutableGeos.length > 0 && (
        <div className="px-4 py-2 bg-amber-50/70 border-t border-amber-200/60 flex items-center justify-between text-xs text-amber-800">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-3.5 h-3.5 text-amber-600 flex-shrink-0" />
            <span>
              <strong>Private / Non-Routable IP Notice:</strong>{' '}
              {nonRoutableGeos.map(g => `${g.ip} (${g.reason || 'RFC 1918 / Internal'})`).join(', ')} — correctly excluded from external geolocation mapping.
            </span>
          </div>
        </div>
      )}

      {/* Selected IP Forensic Telemetry Card */}
      {selectedGeo && (
        <div className="p-4 bg-white border-t border-slate-200">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs mb-3">
            <div>
              <span className="text-slate-500 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Observed IP</span>
              <span className="font-bold text-slate-900 text-sm">{selectedGeo.ip}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Approximate Location</span>
              <span className="font-semibold text-slate-800">
                {selectedGeo.geolocatable === false
                  ? 'Private / Internal (RFC 1918)'
                  : `${selectedGeo.city ? selectedGeo.city + ', ' : ''}${selectedGeo.region ? selectedGeo.region + ', ' : ''}${selectedGeo.country || 'Unknown'} ${selectedGeo.countryCode ? `(${selectedGeo.countryCode})` : ''}`}
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Organization / ISP</span>
              <span className="font-semibold text-slate-800 truncate block">
                {selectedGeo.organization || selectedGeo.isp || 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Autonomous System</span>
              <span className="font-semibold text-slate-800 truncate block">{selectedGeo.asn || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Accuracy Radius & Confidence</span>
              <span className="font-semibold text-slate-800 flex items-center gap-1.5">
                <span>{selectedGeo.accuracyRadiusKm ? `±${selectedGeo.accuracyRadiusKm} km` : '±50 km'}</span>
                <span className="text-slate-400">|</span>
                <span className={`${(selectedGeo.confidence || 75) >= 70 ? 'text-emerald-700' : 'text-amber-700'} font-bold`}>
                  {selectedGeo.confidence || 75}% conf
                </span>
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase tracking-wider block font-semibold text-[11px] mb-0.5">Infrastructure Profile</span>
              <span className="inline-flex items-center gap-1 font-semibold flex-wrap">
                {(selectedGeo.isTor || selectedGeo.vpnTorProxy?.isTor) ? (
                  <span className="text-red-700 bg-red-50 px-2 py-0.5 rounded border border-red-200">Tor Exit Node</span>
                ) : (selectedGeo.isVpn || selectedGeo.vpnTorProxy?.isVpn) ? (
                  <span className="text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">VPN Node</span>
                ) : (selectedGeo.isProxy || selectedGeo.vpnTorProxy?.isProxy) ? (
                  <span className="text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">Proxy</span>
                ) : (selectedGeo.isHosting || selectedGeo.vpnTorProxy?.isDatacenter) ? (
                  <span className="text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">Hosting / Cloud DC</span>
                ) : selectedGeo.geolocatable === false ? (
                  <span className="text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">Private Subnet</span>
                ) : (
                  <span className="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">Residential / Transit</span>
                )}
              </span>
            </div>
          </div>

          {/* Forensic Attribution Note */}
          <div className="text-[11px] text-slate-500 bg-slate-50 rounded-lg p-2.5 border border-slate-200/80 flex items-start gap-2">
            <Radio className="w-3.5 h-3.5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-700">Forensic Interpretation: </span>
              {selectedGeo.attributionNote ||
                'IP geolocation provides an approximate location of network infrastructure. It does not identify a person’s exact physical location.'}
              {selectedGeo.evidenceProvenance && (
                <span className="text-slate-400 ml-2">
                  [Source: {selectedGeo.evidenceProvenance.provider}]
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Mandatory Disclaimer */}
      <div className="p-3 bg-slate-50 border-t border-slate-200 flex items-center gap-2 text-xs text-slate-600">
        <Info className="w-4 h-4 text-blue-600 flex-shrink-0" />
        <span>
          <strong>Forensic Notice:</strong> IP geolocation provides an approximate location of network infrastructure. It does not identify a person's exact physical location.
        </span>
      </div>
    </div>
  );
};
