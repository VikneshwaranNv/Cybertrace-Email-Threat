import {
  CampaignMatch,
  GeolocationResult,
  GraphEdge,
  GraphNode,
  InvestigationGraphData,
  NormalizedIOC,
  MitreTechniqueMapping,
  RiskLevel,
} from '../../src/types/forensics';

export function buildInvestigationGraph(params: {
  caseId: string;
  emailSubject: string;
  senderAddress: string;
  fromDomain: string;
  replyTo?: string;
  rawSha256?: string;
  iocs: NormalizedIOC[];
  geolocations: GeolocationResult[];
  campaignMatches: CampaignMatch[];
  mitreMappings?: MitreTechniqueMapping[];
  overallRisk: RiskLevel;
}): InvestigationGraphData {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenNodeIds = new Set<string>();

  const addNode = (node: GraphNode) => {
    if (!seenNodeIds.has(node.id)) {
      seenNodeIds.add(node.id);
      nodes.push(node);
    }
  };

  const addEdge = (
    source: string,
    target: string,
    label: GraphEdge['label'],
    evidence: string,
    evidenceReference: string,
    confidence = 90
  ) => {
    const edgeId = `${source}->${target}:${label}`;
    edges.push({
      id: edgeId,
      source,
      target,
      label,
      relationship: label,
      evidence,
      evidenceReference,
      confidence,
    });
  };

  // 1. Email Root Node
  const emailNodeId = `node-email-${params.caseId}`;
  addNode({
    id: emailNodeId,
    label: params.emailSubject.length > 28 ? params.emailSubject.substring(0, 28) + '...' : params.emailSubject,
    type: 'Email',
    risk: params.overallRisk,
    evidenceReferences: [`Case: ${params.caseId}`, 'Message-ID Header', 'Raw Email Buffer'],
    evidenceDetails: `Primary investigation target. Subject: "${params.emailSubject}". Forensic SHA-256 integrity verified.`,
    properties: {
      caseId: params.caseId,
      subject: params.emailSubject,
    },
  });

  // 2. Sender Node
  const senderNodeId = `node-sender-${params.senderAddress}`;
  addNode({
    id: senderNodeId,
    label: params.senderAddress,
    type: 'Sender',
    risk: params.overallRisk === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
    evidenceReferences: ['Header: RFC-5322 From'],
    evidenceDetails: `Declared envelope sender in From header: ${params.senderAddress}`,
    properties: {
      address: params.senderAddress,
    },
  });
  addEdge(
    emailNodeId,
    senderNodeId,
    'SENT_FROM',
    'RFC-5322 From header specifies declared sender of the message.',
    'Header: From address',
    95
  );

  // 3. Sender Domain Node
  if (params.fromDomain) {
    const domainNodeId = `node-domain-${params.fromDomain.toLowerCase()}`;
    addNode({
      id: domainNodeId,
      label: params.fromDomain,
      type: 'Domain',
      evidenceReferences: ['Header: From Domain', `DNS: ${params.fromDomain}`],
      evidenceDetails: `Domain infrastructure parsed from sender address: ${params.fromDomain}`,
      properties: {
        domain: params.fromDomain,
      },
    });
    addEdge(
      senderNodeId,
      domainNodeId,
      'RESOLVES_TO',
      'Sender mail address syntactically routes through this domain infrastructure.',
      `Domain: ${params.fromDomain}`,
      95
    );
  }

  // 4. File Hash Nodes (Raw Email SHA-256 and Attachment Hashes)
  if (params.rawSha256) {
    const hashNodeId = `node-hash-raw`;
    addNode({
      id: hashNodeId,
      label: `SHA-256: ${params.rawSha256.substring(0, 10)}...`,
      type: 'Hash',
      evidenceReferences: ['Ledger: Raw Email SHA-256'],
      evidenceDetails: `Cryptographic SHA-256 digest of original MIME byte stream: ${params.rawSha256}`,
      properties: {
        hash: params.rawSha256,
        type: 'SHA-256',
      },
    });
    addEdge(
      emailNodeId,
      hashNodeId,
      'CONTAINS',
      'Immutable cryptographic hash computed directly from raw evidentiary byte buffer.',
      'Ledger: Evidence Sealing Block',
      100
    );
  }

  // 5. IPs, ASNs, and Geolocation Nodes
  params.geolocations.forEach(geo => {
    const ipNodeId = `node-ip-${geo.ip}`;
    addNode({
      id: ipNodeId,
      label: geo.ip,
      type: 'IP',
      risk: geo.vpnTorProxy.isTor ? 'CRITICAL' : geo.vpnTorProxy.isVpn ? 'HIGH' : undefined,
      evidenceReferences: [
        geo.isOriginating ? 'Header: Originating Received Hop' : 'Header: Intermediate Transit Hop',
        `Network: BGP ${geo.asn}`,
      ],
      evidenceDetails: `Network transit address ${geo.ip} located in ${geo.country} (${geo.isp}). Originating: ${geo.isOriginating ? 'YES' : 'NO'}.`,
      properties: {
        ip: geo.ip,
        country: geo.country,
        city: geo.city,
        isp: geo.isp,
        isOriginating: geo.isOriginating,
      },
    });

    if (geo.isOriginating) {
      addEdge(
        senderNodeId,
        ipNodeId,
        'SENT_FROM',
        'Earliest external transit MTA observed in Received header trace.',
        'Header: Originating Received Hop IP',
        90
      );
    } else {
      addEdge(
        emailNodeId,
        ipNodeId,
        'CONTAINS',
        'Intermediate transit relay recorded in Received trace sequence.',
        'Header: Received hop',
        92
      );
    }
  });

  // 6. Extracted URLs and Destination IOCs
  params.iocs
    .filter(ioc => ioc.type === 'url')
    .slice(0, 4)
    .forEach(urlIoc => {
      const urlNodeId = `node-url-${urlIoc.id}`;
      let displayUrl = urlIoc.value;
      try {
        const u = new URL(urlIoc.value);
        displayUrl = u.hostname + (u.pathname.length > 10 ? u.pathname.substring(0, 10) + '...' : u.pathname);
      } catch {
        displayUrl = urlIoc.value.substring(0, 20);
      }

      addNode({
        id: urlNodeId,
        label: displayUrl,
        type: 'URL',
        risk: urlIoc.reputation === 'MALICIOUS' ? 'CRITICAL' : urlIoc.reputation === 'SUSPICIOUS' ? 'HIGH' : undefined,
        evidenceReferences: ['Body: Extracted Hyperlink Anchor', `Reputation: ${urlIoc.reputation}`],
        evidenceDetails: `Embedded hyperlink URL: ${urlIoc.value}. Reputation: ${urlIoc.reputation}. Confidence: ${urlIoc.confidence}%.`,
        properties: {
          fullUrl: urlIoc.value,
          reputation: urlIoc.reputation,
        },
      });
      addEdge(
        emailNodeId,
        urlNodeId,
        'CONTAINS',
        'Hyperlink URL parsed directly from email body anchor tags.',
        'Body: Hyperlink Anchor',
        99
      );
    });

  // 7. Attachment Hash IOCs
  params.iocs
    .filter(ioc => ioc.type === 'hash_sha256')
    .slice(0, 2)
    .forEach(hashIoc => {
      const hashNodeId = `node-hash-${hashIoc.id}`;
      addNode({
        id: hashNodeId,
        label: `SHA-256: ${hashIoc.value.substring(0, 10)}...`,
        type: 'Hash',
        risk: hashIoc.reputation === 'MALICIOUS' ? 'CRITICAL' : 'HIGH',
        evidenceReferences: [`Attachment Hash: ${hashIoc.value}`, `Provider: ${hashIoc.source}`],
        evidenceDetails: `Attachment payload SHA-256: ${hashIoc.value}. Threat status: ${hashIoc.reputation}.`,
        properties: {
          hash: hashIoc.value,
        },
      });
      addEdge(
        emailNodeId,
        hashNodeId,
        'CONTAINS',
        'Physical attachment extracted from MIME multipart container.',
        'MIME: Multipart Attachment',
        99
      );
    });

  // 8. Campaign Nodes
  if (params.campaignMatches.length > 0) {
    const topCamp = params.campaignMatches[0];
    const campNodeId = `node-camp-${topCamp.campaignId}`;
    addNode({
      id: campNodeId,
      label: topCamp.campaignCode,
      type: 'Campaign',
      risk: topCamp.severity,
      evidenceReferences: [
        `Campaign ID: ${topCamp.campaignId}`,
        `Threat Actor: ${topCamp.threatActorGroup}`,
        `Similarity: ${topCamp.similarityScore}%`,
      ],
      evidenceDetails: `Campaign cluster: ${topCamp.name} (${topCamp.threatActorGroup}). Statistical similarity: ${topCamp.similarityScore}%.`,
      properties: {
        campaignCode: topCamp.campaignCode,
        actor: topCamp.threatActorGroup,
        similarity: `${topCamp.similarityScore}%`,
      },
    });
    addEdge(
      emailNodeId,
      campNodeId,
      'CORRELATED_WITH',
      `Statistical feature correlation (${topCamp.similarityScore}%) matching historical threat cluster indicators.`,
      `Campaign: ${topCamp.campaignId}`,
      topCamp.campaignConfidence
    );
  }

  // 9. MITRE ATT&CK Technique Nodes
  if (params.mitreMappings && params.mitreMappings.length > 0) {
    params.mitreMappings.slice(0, 4).forEach(tech => {
      const techNodeId = `node-tech-${tech.techniqueId.replace('.', '-')}`;
      addNode({
        id: techNodeId,
        label: `${tech.techniqueId}: ${tech.techniqueName}`,
        type: 'Technique',
        risk: 'HIGH',
        evidenceReferences: tech.evidenceReferences,
        evidenceDetails: `MITRE ATT&CK ${tech.techniqueId} (${tech.techniqueName}) - Tactic: ${tech.tactic}. Grounding: ${tech.supportingEvidence.join('; ')}`,
        properties: {
          techniqueId: tech.techniqueId,
          techniqueName: tech.techniqueName,
          tactic: tech.tactic,
        },
      });
      addEdge(
        emailNodeId,
        techNodeId,
        'USES_TECHNIQUE',
        `Forensic evidence supports technique execution: ${tech.supportingEvidence[0]}`,
        tech.evidenceReferences[0] || 'Forensic Mapping Engine',
        90
      );
    });
  }

  return { nodes, edges };
}
