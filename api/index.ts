import type { IncomingMessage, ServerResponse } from 'http';
import { createExpressApp } from '../server';

let appInstance: any = null;

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  if (!appInstance) {
    appInstance = await createExpressApp();
  }
  return appInstance(req, res);
}
