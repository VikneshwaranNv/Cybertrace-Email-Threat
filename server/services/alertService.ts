import { Response } from "express";
import { AlertEvent } from "../../src/types/forensics";

export class AlertService {
  private static instance: AlertService;
  private clients: Set<Response> = new Set();
  private recentAlerts: AlertEvent[] = [];
  private readonly MAX_RECENT_ALERTS = 50;

  private constructor() {}

  public static getInstance(): AlertService {
    if (!AlertService.instance) {
      AlertService.instance = new AlertService();
    }
    return AlertService.instance;
  }

  public addClient(res: Response): void {
    this.clients.add(res);
  }

  public removeClient(res: Response): void {
    this.clients.delete(res);
  }

  public getClientCount(): number {
    return this.clients.size;
  }

  public broadcast(alertData: Omit<AlertEvent, "id" | "timestamp"> & { id?: string; timestamp?: string }): AlertEvent {
    const alert: AlertEvent = {
      id: alertData.id || `ALERT-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: alertData.timestamp || new Date().toISOString(),
      severity: alertData.severity,
      title: alertData.title,
      description: alertData.description,
      caseId: alertData.caseId,
      threatType: alertData.threatType,
      source: alertData.source,
    };

    this.recentAlerts.unshift(alert);
    if (this.recentAlerts.length > this.MAX_RECENT_ALERTS) {
      this.recentAlerts.pop();
    }

    const payload = `event: alert\ndata: ${JSON.stringify(alert)}\n\n`;

    for (const client of this.clients) {
      try {
        client.write(payload);
      } catch {
        this.clients.delete(client);
      }
    }

    return alert;
  }

  public getRecentAlerts(limit = 20): AlertEvent[] {
    return this.recentAlerts.slice(0, limit);
  }

  public clearAlerts(): void {
    this.recentAlerts = [];
  }
}

export const alertService = AlertService.getInstance();