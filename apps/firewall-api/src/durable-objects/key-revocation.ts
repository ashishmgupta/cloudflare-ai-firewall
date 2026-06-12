export class KeyRevocation implements DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState) {
    this.storage = state.storage;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const keyHash = url.pathname.replace(/^\/+/, '');

    if (request.method === 'GET') {
      const revoked = (await this.storage.get<boolean>(`r:${keyHash}`)) ?? false;
      return Response.json({ revoked });
    }

    if (request.method === 'POST') {
      await this.storage.put(`r:${keyHash}`, true);
      return Response.json({ ok: true });
    }

    if (request.method === 'DELETE') {
      await this.storage.delete(`r:${keyHash}`);
      return Response.json({ ok: true });
    }

    return new Response('Method Not Allowed', { status: 405 });
  }
}
