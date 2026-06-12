export class RateLimiter implements DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState) {
    this.storage = state.storage;
  }

  async fetch(request: Request): Promise<Response> {
    const body = await request.json<{
      windowMs: number;
      limit: number;
    }>();

    const now = Date.now();
    const windowStart = now - body.windowMs;
    const stored = await this.storage.get<number[]>('ts') ?? [];
    const inWindow = stored.filter(t => t > windowStart);

    const allowed = inWindow.length < body.limit;
    if (allowed) {
      inWindow.push(now);
      await this.storage.put('ts', inWindow);
    }

    return Response.json({ allowed, count: inWindow.length });
  }
}
