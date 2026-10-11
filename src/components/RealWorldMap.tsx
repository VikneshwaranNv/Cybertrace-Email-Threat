import React, { useEffect, useRef, useState, useMemo } from 'react';
import L from 'leaflet';
import {
  Globe,
  Radio,
  Layers,
  Crosshair,
  Maximize2,
  Minimize2,
  ExternalLink,
  ShieldAlert,
  Server,
  Zap,
  Navigation,
  Info,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { GeolocationResult } from '../types/forensics';

export type MapTileTheme = 'dark' | 'street' | 'satellite' | 'light';

interface RealWorldMapProps {
  geolocations: GeolocationResult[];
  originConfidence?: number;
  originatingIp?: string;
  onSelectGeo?: (geo: GeolocationResult) => void;
  height?: string | number;
  className?: string;
}

const TILE_PROVIDERS: Record<MapTileTheme, { name: string; url: string; attribution: string; subdomains?: string; maxZoom: number }> = {
  dark: {
    name: 'Cyber Dark (SOC)',
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    subdomains: 'abcd',
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    maxZoom: 19,
  },
  street: {
    name: 'OpenStreetMap',
    url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; OpenStreetMap contributors',
    maxZoom: 19,
  },
  satellite: {
    name: 'Satellite (Aerial)',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    attribution: 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics',
    maxZoom: 18,
  },
  light: {
    name: 'Carto Light',
    url: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
    subdomains: 'abcd',
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    maxZoom: 19,
  },
};

export const RealWorldMap: React.FC<RealWorldMapProps> = ({
  geolocations = [],
  originConfidence = 85,
  originatingIp,
  onSelectGeo,
  height = 520,
  className = '',
}) => {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const markersLayerRef = useRef<L.LayerGroup | null>(null);
  const linesLayerRef = useRef<L.LayerGroup | null>(null);

  const [activeTheme, setActiveTheme] = useState<MapTileTheme>('dark');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GeolocationResult | null>(null);

  // Filter valid geographic coordinates
  const safeGeolocations = useMemo(() => (Array.isArray(geolocations) ? geolocations : []), [geolocations]);

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
          (g.latitude !== 0 || g.longitude !== 0) &&
          g.latitude >= -90 &&
          g.latitude <= 90 &&
          g.longitude >= -180 &&
          g.longitude <= 180
      ),
    [safeGeolocations]
  );

  const originNode = useMemo(
    () =>
      routableGeos.find(g => g.isOriginating || g.ip === originatingIp) ||
      routableGeos[0] ||
      null,
    [routableGeos, originatingIp]
  );

  // Initialize Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Clean up any stale instances
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const map = L.map(mapContainerRef.current, {
      center: [20, 0],
      zoom: 2,
      minZoom: 2,
      maxZoom: 18,
      zoomControl: false, // We'll render custom top-right controls
      attributionControl: true,
    });

    // Custom compact attribution placement
    map.attributionControl.setPosition('bottomright');

    const provider = TILE_PROVIDERS[activeTheme];
    const tileLayer = L.tileLayer(provider.url, {
      attribution: provider.attribution,
      subdomains: provider.subdomains || 'abc',
      maxZoom: provider.maxZoom,
    }).addTo(map);

    const markersGroup = L.layerGroup().addTo(map);
    const linesGroup = L.layerGroup().addTo(map);

    mapInstanceRef.current = map;
    tileLayerRef.current = tileLayer;
    markersLayerRef.current = markersGroup;
    linesLayerRef.current = linesGroup;

    // Small timeout to allow container rendering to settle
    const resizeTimer = setTimeout(() => {
      map.invalidateSize();
    }, 150);

    return () => {
      clearTimeout(resizeTimer);
      map.remove();
      mapInstanceRef.current = null;
      tileLayerRef.current = null;
      markersLayerRef.current = null;
      linesLayerRef.current = null;
    };
  }, []); // Run on mount

  // Update Tile Theme
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current);
    }

    const provider = TILE_PROVIDERS[activeTheme];
    const newTileLayer = L.tileLayer(provider.url, {
      attribution: provider.attribution,
      subdomains: provider.subdomains || 'abc',
      maxZoom: provider.maxZoom,
    }).addTo(map);

    tileLayerRef.current = newTileLayer;
  }, [activeTheme]);

  // Update Markers, Hops, and Polyline
  useEffect(() => {
    const map = mapInstanceRef.current;
    const markersGroup = markersLayerRef.current;
    const linesGroup = linesLayerRef.current;
    if (!map || !markersGroup || !linesGroup) return;

    markersGroup.clearLayers();
    linesGroup.clearLayers();

    if (routableGeos.length === 0) {
      map.setView([20, 0], 2);
      return;
    }

    const latLngs: [number, number][] = [];

    // Chronological relay transit lines
    routableGeos.forEach((geo, index) => {
      const lat = geo.latitude;
      const lng = geo.longitude;
      latLngs.push([lat, lng]);

      const isOrigin = geo.isOriginating || geo.ip === originatingIp;

      // Custom HTML Marker Icon
      let iconHtml = '';
      let iconSize: [number, number] = [32, 32];
      let iconAnchor: [number, number] = [16, 16];

      if (isOrigin) {
        iconSize = [44, 44];
        iconAnchor = [22, 22];
        iconHtml = `
          <div class="relative flex items-center justify-center w-11 h-11 cursor-pointer group">
            <span class="absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75 animate-ping"></span>
            <div class="relative flex items-center justify-center w-8 h-8 rounded-full bg-red-600 text-white shadow-lg border-2 border-white">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10" stroke-width="2"/>
                <circle cx="12" cy="12" r="4" fill="currentColor"/>
              </svg>
            </div>
            <div class="absolute -top-7 px-2 py-0.5 bg-red-950 text-red-200 text-[10px] font-mono font-bold rounded shadow border border-red-700 whitespace-nowrap">
              ORIGIN MTA
            </div>
          </div>
        `;
      } else {
        iconSize = [32, 32];
        iconAnchor = [16, 16];
        iconHtml = `
          <div class="relative flex items-center justify-center w-8 h-8 cursor-pointer group">
            <div class="flex items-center justify-center w-7 h-7 rounded-full bg-blue-600 text-white font-mono font-bold text-xs shadow-md border-2 border-white hover:scale-110 transition-transform">
              ${index + 1}
            </div>
            <div class="absolute -top-6 px-1.5 py-0.5 bg-slate-900 text-slate-200 text-[9px] font-mono rounded shadow border border-slate-700 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity">
              Hop #${index + 1}
            </div>
          </div>
        `;
      }

      const customIcon = L.divIcon({
        html: iconHtml,
        className: 'custom-leaflet-marker',
        iconSize: iconSize,
        iconAnchor: iconAnchor,
      });

      const marker = L.marker([lat, lng], { icon: customIcon });

      // Rich Forensic Popup
      const popupHtml = `
        <div style="font-family: ui-sans-serif, system-ui, sans-serif; min-width: 240px; padding: 2px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px;">
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: ${isOrigin ? '#b91c1c' : '#2563eb'};">
              ${isOrigin ? '🔴 Originating MTA Sender' : `🔵 Transit Hop #${index + 1}`}
            </span>
            <span style="font-size: 10px; font-weight: 600; color: #64748b; background: #f1f5f9; padding: 2px 6px; border-radius: 4px;">
              ${geo.countryCode || geo.country}
            </span>
          </div>
          <div style="font-size: 13px; font-weight: 700; font-family: monospace; color: #0f172a; margin-bottom: 4px;">
            ${geo.ip}
          </div>
          <div style="font-size: 11px; color: #334155; margin-bottom: 3px;">
            📍 <strong>Location:</strong> ${[geo.city, geo.region, geo.country].filter(Boolean).join(', ') || 'Unknown Location'}
          </div>
          <div style="font-size: 11px; color: #334155; margin-bottom: 3px;">
            🏢 <strong>ISP / Org:</strong> ${geo.organization || geo.isp || 'Unknown ISP'}
          </div>
          <div style="font-size: 11px; color: #334155; margin-bottom: 3px;">
            🌐 <strong>ASN:</strong> ${geo.asn || 'N/A'}
          </div>
          <div style="font-size: 10px; color: #64748b; margin-top: 6px; padding-top: 4px; border-top: 1px dashed #cbd5e1;">
            Coordinates: ${lat.toFixed(4)}°, ${lng.toFixed(4)}°
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml, { maxWidth: 300 });

      marker.on('click', () => {
        setSelectedNode(geo);
        if (onSelectGeo) {
          onSelectGeo(geo);
        }
      });

      markersGroup.addLayer(marker);
    });

    // Draw Transit Polyline Connecting Sequential Hops
    if (latLngs.length > 1) {
      // Glow background line
      const glowLine = L.polyline(latLngs, {
        color: '#0284c7',
        weight: 6,
        opacity: 0.35,
        smoothFactor: 1,
      });
      linesGroup.addLayer(glowLine);

      // Dash foreground line
      const routeLine = L.polyline(latLngs, {
        color: '#38bdf8',
        weight: 3,
        opacity: 0.9,
        dashArray: '8, 6',
        smoothFactor: 1,
      });
      linesGroup.addLayer(routeLine);
    }

    // Auto-fit bounds
    if (latLngs.length > 1) {
      const bounds = L.latLngBounds(latLngs);
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 10 });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 6);
    }
  }, [routableGeos, originatingIp, onSelectGeo]);

  // Handle Focus Origin
  const handleFocusOrigin = () => {
    const map = mapInstanceRef.current;
    if (!map || !originNode) return;
    map.flyTo([originNode.latitude, originNode.longitude], 8, { duration: 1.2 });
    setSelectedNode(originNode);
  };

  // Handle Fit All Bounds
  const handleFitRoute = () => {
    const map = mapInstanceRef.current;
    if (!map || routableGeos.length === 0) return;
    if (routableGeos.length === 1) {
      map.flyTo([routableGeos[0].latitude, routableGeos[0].longitude], 6);
      return;
    }
    const latLngs: [number, number][] = routableGeos.map(g => [g.latitude, g.longitude]);
    map.fitBounds(L.latLngBounds(latLngs), { padding: [50, 50], maxZoom: 10 });
  };

  // Handle Fullscreen Toggle
  const toggleFullscreen = () => {
    setIsFullscreen(prev => !prev);
    setTimeout(() => {
      mapInstanceRef.current?.invalidateSize();
    }, 200);
  };

  return (
    <div
      className={`relative bg-slate-900 rounded-xl overflow-hidden border border-slate-700 shadow-md transition-all ${
        isFullscreen ? 'fixed inset-4 z-50 rounded-2xl border-2 border-blue-500 shadow-2xl' : className
      }`}
      style={{ height: isFullscreen ? 'calc(100vh - 32px)' : height }}
    >
      {/* Top Floating Map Controls Bar */}
      <div className="absolute top-3 left-3 right-3 z-[400] flex flex-wrap items-center justify-between gap-2 pointer-events-none">
        {/* Left: Origin IP Forensic Badge */}
        <div className="flex items-center gap-2 bg-slate-900/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-slate-700/80 shadow-lg pointer-events-auto">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500"></span>
            </span>
            <span className="text-xs font-bold text-white tracking-wide">
              REAL WORLD GEOLOCATION
            </span>
          </div>
          <div className="h-3.5 w-px bg-slate-700 mx-1"></div>
          <div className="text-[11px] text-slate-300 font-mono">
            {routableGeos.length} Routable MTA {routableGeos.length === 1 ? 'Hop' : 'Hops'}
          </div>
          {originConfidence !== undefined && (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
              {originConfidence}% Confidence
            </span>
          )}
        </div>

        {/* Right: Map Theme Switcher & Actions */}
        <div className="flex items-center gap-1.5 bg-slate-900/90 backdrop-blur-md p-1 rounded-lg border border-slate-700/80 shadow-lg pointer-events-auto">
          {/* Layer Selector */}
          {(['dark', 'street', 'satellite', 'light'] as MapTileTheme[]).map(theme => (
            <button
              key={theme}
              onClick={() => setActiveTheme(theme)}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded transition-all cursor-pointer ${
                activeTheme === theme
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
              title={`Switch to ${TILE_PROVIDERS[theme].name}`}
            >
              {theme === 'dark' && 'Cyber Dark'}
              {theme === 'street' && 'Street Map'}
              {theme === 'satellite' && 'Satellite'}
              {theme === 'light' && 'Light'}
            </button>
          ))}

          <div className="h-4 w-px bg-slate-700 mx-1"></div>

          {/* Fit Route */}
          <button
            onClick={handleFitRoute}
            className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors cursor-pointer"
            title="Fit All Hops in View"
          >
            <Navigation className="w-3.5 h-3.5" />
          </button>

          {/* Focus Origin */}
          {originNode && (
            <button
              onClick={handleFocusOrigin}
              className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-950/60 rounded transition-colors cursor-pointer"
              title="Focus Originating MTA IP"
            >
              <Crosshair className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Fullscreen Toggle */}
          <button
            onClick={toggleFullscreen}
            className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors cursor-pointer"
            title={isFullscreen ? 'Exit Fullscreen' : 'Expand Fullscreen'}
          >
            {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Main Leaflet Map Container */}
      <div ref={mapContainerRef} className="w-full h-full z-0" />

      {/* Bottom Floating Info Card for Selected Node */}
      {selectedNode && (
        <div className="absolute bottom-3 left-3 right-3 md:right-auto md:max-w-md z-[400] bg-slate-900/95 backdrop-blur-md p-3.5 rounded-xl border border-slate-700 shadow-xl text-white pointer-events-auto">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-2">
            <div className="flex items-center gap-2">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  selectedNode.isOriginating || selectedNode.ip === originatingIp
                    ? 'bg-red-500 animate-pulse'
                    : 'bg-blue-400'
                }`}
              ></span>
              <span className="font-mono font-bold text-xs text-white">{selectedNode.ip}</span>
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {selectedNode.countryCode || selectedNode.country}
              </span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white text-xs px-1 cursor-pointer"
            >
              ✕
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
            <div>
              <span className="text-slate-500 block text-[10px]">Location:</span>
              <span className="font-medium">
                {[selectedNode.city, selectedNode.region, selectedNode.country].filter(Boolean).join(', ') || 'Unknown'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Network / ISP:</span>
              <span className="font-medium truncate block">{selectedNode.organization || selectedNode.isp || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Role:</span>
              <span className="font-medium">{selectedNode.infrastructureRole || 'Relay Node'}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Autonomous System:</span>
              <span className="font-mono text-[10px]">{selectedNode.asn || 'Unassigned'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Empty State Overlay if No Routable IPs */}
      {routableGeos.length === 0 && (
        <div className="absolute inset-0 z-[400] flex items-center justify-center bg-slate-950/80 backdrop-blur-xs p-6 text-center">
          <div className="max-w-sm">
            <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center">
              <Globe className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-bold text-white mb-1">Internal / RFC 1918 Private Transit</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Observed mail hops belong to private, non-routable address space (e.g. 10.x, 172.16-31.x, 192.168.x).
              Physical geographic coordinates cannot be pinpointed for internal LAN relays.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
