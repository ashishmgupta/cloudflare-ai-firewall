import { Hono } from 'hono';
import type { Env } from './env.js';
import { adminAuth } from './middleware/admin-auth.js';
import profilesRouter from './routes/profiles.js';
import apiKeysRouter from './routes/api-keys.js';
import signaturesRouter from './routes/signatures.js';
import templatesRouter from './routes/templates.js';
import auditRouter from './routes/audit.js';

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error('[policy-manager] error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

app.get('/', async c => {
  const html = await import('./ui/index.js');
  return c.html(html.default);
});

app.get('/health', c => c.json({ status: 'ok', version: 2 }));

// Public: template listing (no admin auth — used by UI on load)
app.route('/api/templates', templatesRouter);

const api = new Hono<{ Bindings: Env }>();
api.use('*', adminAuth);
api.route('/profiles', profilesRouter);
api.route('/keys', apiKeysRouter);
api.route('/signatures', signaturesRouter);
api.route('/audit', auditRouter);

app.route('/api', api);

export default app;
