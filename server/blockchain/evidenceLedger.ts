import crypto from 'crypto';
import { EvidenceBlock, LedgerVerificationResult } from '../../src/types/forensics';

/**
 * Local / Private Tamper-Evident Hash-Chain Ledger
 * Designed specifically for SIH 2026 digital forensics evidence integrity verification.
 * Note: This is an internal cryptographic hash-chain ledger, not a public mainnet blockchain.
 */

export function computeBlockHash(params: {
  blockIndex: number;
  blockId: string;
  evidenceId: string;
  caseId: string;
  timestamp: string;
  emailSha256: string;
  analysisSha256: string;
  prevBlockHash: string;
  nonce: number;
  metadata: { investigator: string; action: string; clientFingerprint: string; toolVersion: string };
}): string {
  const payload = [
    params.blockIndex,
    params.blockId,
    params.evidenceId,
    params.caseId,
    params.timestamp,
    params.emailSha256,
    params.analysisSha256,
    params.prevBlockHash,
    params.nonce,
    params.metadata.investigator,
    params.metadata.action,
    params.metadata.clientFingerprint,
    params.metadata.toolVersion,
  ].join('|');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

class EvidenceLedger {
  private chain: EvidenceBlock[] = [];

  constructor() {
    this.initializeGenesisBlock();
  }

  private initializeGenesisBlock() {
    const timestamp = '2026-09-01T00:00:00.000Z';
    const genesisMetadata = {
      investigator: 'SYSTEM_BOOTSTRAP',
      action: 'GENESIS_BLOCK_CREATION',
      clientFingerprint: 'SIH-2026-LEGAL-ANCHOR-0000',
      toolVersion: 'SIH-Forensics-v2.6.0',
    };
    const prevBlockHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const blockId = 'BLK-0000';
    const evidenceId = 'EVID-GENESIS-ANCHOR';
    const caseId = 'CASE-0000-GENESIS';
    const emailSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const analysisSha256 = '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b';
    const nonce = 0;

    const blockHash = computeBlockHash({
      blockIndex: 0,
      blockId,
      evidenceId,
      caseId,
      timestamp,
      emailSha256,
      analysisSha256,
      prevBlockHash,
      nonce,
      metadata: genesisMetadata,
    });

    this.chain = [
      {
        blockIndex: 0,
        blockId,
        evidenceId,
        caseId,
        timestamp,
        emailSha256,
        analysisSha256,
        prevBlockHash,
        blockHash,
        nonce,
        metadata: genesisMetadata,
      },
    ];
  }

  public getChain(): EvidenceBlock[] {
    return [...this.chain];
  }

  public appendEvidence(params: {
    evidenceId: string;
    caseId?: string;
    emailSha256: string;
    analysisSha256: string;
    investigator?: string;
    action?: string;
  }): EvidenceBlock {
    const prevBlock = this.chain[this.chain.length - 1];
    const blockIndex = this.chain.length;
    const blockId = `BLK-${String(blockIndex).padStart(4, '0')}`;
    const timestamp = new Date().toISOString();
    const prevBlockHash = prevBlock.blockHash;
    const caseId = params.caseId || `CASE-2026-${String(blockIndex).padStart(3, '0')}`;
    const nonce = Math.floor(Math.random() * 100000);

    const metadata = {
      investigator: params.investigator || 'SOC_ANALYST_AUTO',
      action: params.action || 'EVIDENCE_INGESTION_AND_CRYPTOGRAPHIC_SEALING',
      clientFingerprint: 'FORENSIC-ENV-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      toolVersion: 'SIH-Forensics-v2.6.0',
    };

    const blockHash = computeBlockHash({
      blockIndex,
      blockId,
      evidenceId: params.evidenceId,
      caseId,
      timestamp,
      emailSha256: params.emailSha256,
      analysisSha256: params.analysisSha256,
      prevBlockHash,
      nonce,
      metadata,
    });

    const block: EvidenceBlock = {
      blockIndex,
      blockId,
      evidenceId: params.evidenceId,
      caseId,
      timestamp,
      emailSha256: params.emailSha256,
      analysisSha256: params.analysisSha256,
      prevBlockHash,
      blockHash,
      nonce,
      metadata,
      isTampered: false,
    };

    this.chain.push(block);
    return block;
  }

  public verifyIntegrity(): LedgerVerificationResult {
    const verifiedAt = new Date().toISOString();

    for (let i = 0; i < this.chain.length; i++) {
      const current = this.chain[i];

      // 1. Recalculate block hash
      const computed = computeBlockHash({
        blockIndex: current.blockIndex,
        blockId: current.blockId,
        evidenceId: current.evidenceId,
        caseId: current.caseId || 'CASE-0000-GENESIS',
        timestamp: current.timestamp,
        emailSha256: current.emailSha256,
        analysisSha256: current.analysisSha256,
        prevBlockHash: current.prevBlockHash,
        nonce: current.nonce ?? 0,
        metadata: current.metadata,
      });

      if (computed !== current.blockHash) {
        return {
          isValid: false,
          statusMessage: 'INTEGRITY VERIFICATION FAILED',
          totalBlocks: this.chain.length,
          verifiedAt,
          invalidBlockIndex: current.blockIndex,
          brokenLinkDetails: {
            blockIndex: current.blockIndex,
            expectedHash: computed,
            actualHash: current.blockHash,
            reason: `Data payload in Block #${current.blockIndex} (${current.blockId}) was modified without recomputing the SHA-256 hash.`,
          },
        };
      }

      // 2. Check link to previous block
      if (i > 0) {
        const prev = this.chain[i - 1];
        if (current.prevBlockHash !== prev.blockHash) {
          return {
            isValid: false,
            statusMessage: 'INTEGRITY VERIFICATION FAILED',
            totalBlocks: this.chain.length,
            verifiedAt,
            invalidBlockIndex: current.blockIndex,
            brokenLinkDetails: {
              blockIndex: current.blockIndex,
              expectedHash: prev.blockHash,
              actualHash: current.prevBlockHash,
              reason: `Cryptographic chain link broken at Block #${current.blockIndex}: prevBlockHash does not match parent Block #${prev.blockIndex} hash.`,
            },
          };
        }
      }
    }

    return {
      isValid: true,
      statusMessage: 'CHAIN VERIFIED — NO MODIFICATION DETECTED',
      totalBlocks: this.chain.length,
      verifiedAt,
    };
  }

  public simulateTamper(targetIndex: number): { success: boolean; modifiedBlock?: EvidenceBlock } {
    if (targetIndex <= 0 || targetIndex >= this.chain.length) {
      return { success: false };
    }

    const block = this.chain[targetIndex];
    // Tamper with email sha256 to simulate an unauthorized modification of evidence
    block.emailSha256 = 'f7c3bc1d808e04732adf679965ccc34ca7ae3441b4e9f506e5782782b53b7086';
    block.metadata.action = 'UNAUTHORIZED_RECORD_ALTERATION_ATTEMPT';
    block.isTampered = true;

    return { success: true, modifiedBlock: block };
  }

  public verifyChain(): LedgerVerificationResult & { compromisedBlockIndex: number | null } {
    const res = this.verifyIntegrity();
    return {
      ...res,
      compromisedBlockIndex: res.invalidBlockIndex ?? null,
    };
  }

  public tamperBlock(targetIndex: number, _changes?: any): boolean {
    if (this.chain.length <= 1) {
      this.appendEvidence({
        evidenceId: 'EVID-TEST-001',
        caseId: 'CASE-2026-001',
        emailSha256: 'a'.repeat(64),
        analysisSha256: 'b'.repeat(64),
        investigator: 'TEST',
        action: 'INIT',
      });
    }
    const res = this.simulateTamper(targetIndex);
    return res.success;
  }

  public resealChain(): LedgerVerificationResult {
    return this.repairAndReseal();
  }

  public repairAndReseal(): LedgerVerificationResult {
    // Recalculates all hashes in sequence to reseal the chain
    for (let i = 1; i < this.chain.length; i++) {
      const prev = this.chain[i - 1];
      const cur = this.chain[i];
      cur.prevBlockHash = prev.blockHash;
      cur.isTampered = false;
      cur.metadata.action = 'RESEALED_BY_FORENSIC_OFFICER';
      cur.blockHash = computeBlockHash({
        blockIndex: cur.blockIndex,
        blockId: cur.blockId,
        evidenceId: cur.evidenceId,
        caseId: cur.caseId || `CASE-2026-${String(cur.blockIndex).padStart(3, '0')}`,
        timestamp: cur.timestamp,
        emailSha256: cur.emailSha256,
        analysisSha256: cur.analysisSha256,
        prevBlockHash: cur.prevBlockHash,
        nonce: cur.nonce ?? 0,
        metadata: cur.metadata,
      });
    }

    return this.verifyIntegrity();
  }
}

export const evidenceLedger = new EvidenceLedger();
