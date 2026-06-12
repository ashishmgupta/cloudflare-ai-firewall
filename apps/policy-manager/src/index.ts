import { Hono } from 'hono';
import type { Env } from './env.js';
import { adminAuth } from './middleware/admin-auth.js';
import tenantsRouter from './routes/tenants.js';
import apiKeysRouter from './routes/api-keys.js';
import policiesRouter from './routes/policies.js';
import signaturesRouter from './routes/signatures.js';
import auditRouter from './routes/audit.js';

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: 'Internal server error' }, 500);
});

// Serve the admin UI from root
app.get('/', async c => {
  const html = await import('./ui/index.js');
  return c.html(html.default);
});

app.get('/health', c => c.json({ status: 'ok' }));

// All /api/* routes require admin auth
const api = new Hono<{ Bindings: Env }>();
api.use('*', adminAuth);
api.route('/tenants', tenantsRouter);
api.route('/keys', apiKeysRouter);
api.route('/policies', policiesRouter);
api.route('/signatures', signaturesRouter);
api.route('/audit', auditRouter);

app.route('/api', api);

export default app;
