const ALLOWED_IPS = new Set([
  "208.104.66.199",   // replace with your IP
]);

export interface Env {
  AI: Ai;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const clientIP = request.headers.get("CF-Connecting-IP") ?? "";

    if (!ALLOWED_IPS.has(clientIP)) {
      return new Response("Forbidden", { status: 403 });
    }

    const url = new URL(request.url);

    if (url.pathname === "/ai" && request.method === "POST") {
      const body = await request.json<{ prompt: string }>();

      const response = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
        messages: [
          { role: "system", content: "You are a helpful assistant." },
          { role: "user", content: body.prompt },
        ],
      });

      return Response.json(response);
    }

    return new Response("AI Firewall Worker is running", { status: 200 });
  },
};
