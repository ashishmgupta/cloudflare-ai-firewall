// Stub classes kept only for Cloudflare's migration validation.
// The deleted_classes migration in wrangler.toml removes all live instances.
// These can be dropped in the next deploy once the migration has been applied.

export class KeyRevocation {
  async fetch(_req: Request): Promise<Response> {
    return new Response('removed', { status: 410 });
  }
}

export class RateLimiter {
  async fetch(_req: Request): Promise<Response> {
    return new Response('removed', { status: 410 });
  }
}
