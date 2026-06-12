const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI Firewall — Policy Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    [x-cloak] { display: none !important; }
    .tab-active { @apply border-b-2 border-indigo-600 text-indigo-600; }
  </style>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen" x-data="app()" x-init="init()">

<nav class="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
  <div class="flex items-center gap-3">
    <span class="text-xl font-bold text-indigo-600">AI Firewall</span>
    <span class="text-xs text-gray-400 font-mono">Policy Manager</span>
  </div>
  <div class="flex items-center gap-2">
    <input x-model="adminToken" type="password" placeholder="Admin token" class="text-sm border rounded px-3 py-1 w-56" />
    <button @click="loadAll()" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">Connect</button>
  </div>
</nav>

<!-- Tabs -->
<div class="bg-white border-b border-gray-200 px-6">
  <nav class="flex gap-6 text-sm font-medium">
    <button @click="tab='policies'" :class="tab==='policies' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'" class="py-3 border-b-2 border-transparent">Policies</button>
    <button @click="tab='keys'" :class="tab==='keys' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'" class="py-3 border-b-2 border-transparent">API Keys</button>
    <button @click="tab='tenants'" :class="tab==='tenants' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'" class="py-3 border-b-2 border-transparent">Tenants</button>
    <button @click="tab='signatures'" :class="tab==='signatures' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'" class="py-3 border-b-2 border-transparent">Attack Signatures</button>
    <button @click="tab='playground'" :class="tab==='playground' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'" class="py-3 border-b-2 border-transparent">Playground</button>
    <button @click="tab='audit'" :class="tab==='audit' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'" class="py-3 border-b-2 border-transparent">Audit Log</button>
  </nav>
</div>

<main class="max-w-6xl mx-auto px-6 py-8">

  <!-- Status banner -->
  <div x-show="message" x-cloak :class="messageType === 'error' ? 'bg-red-50 border-red-200 text-red-700' : 'bg-green-50 border-green-200 text-green-700'" class="mb-4 border rounded px-4 py-3 text-sm flex justify-between">
    <span x-text="message"></span>
    <button @click="message=''" class="font-bold">×</button>
  </div>

  <!-- ── Policies ── -->
  <div x-show="tab === 'policies'">
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Policies</h2>
      <button @click="showCreatePolicy = !showCreatePolicy" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">+ New Policy</button>
    </div>

    <div x-show="showCreatePolicy" x-cloak class="bg-white border rounded p-4 mb-6">
      <h3 class="font-medium mb-3">Create Policy</h3>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="text-xs text-gray-500">Name *</label>
          <input x-model="newPolicy.name" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="default-strict" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Tenant ID *</label>
          <input x-model="newPolicy.tenantId" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="tenant-uuid" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Description</label>
          <input x-model="newPolicy.description" class="w-full border rounded px-3 py-1.5 text-sm mt-1" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Fail Behavior</label>
          <select x-model="newPolicy.failOpen" class="w-full border rounded px-3 py-1.5 text-sm mt-1">
            <option :value="true">Fail Open (pass on error)</option>
            <option :value="false">Fail Closed (block on error)</option>
          </select>
        </div>
      </div>
      <div class="mt-3 flex gap-2">
        <button @click="createPolicy()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded hover:bg-indigo-700">Create</button>
        <button @click="showCreatePolicy = false" class="text-sm border px-4 py-1.5 rounded hover:bg-gray-50">Cancel</button>
      </div>
    </div>

    <div class="bg-white border rounded overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr>
            <th class="px-4 py-3 text-left">Name</th>
            <th class="px-4 py-3 text-left">Tenant</th>
            <th class="px-4 py-3 text-left">Layers</th>
            <th class="px-4 py-3 text-left">Fail</th>
            <th class="px-4 py-3 text-left">Updated</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <template x-for="p in policies" :key="p.id">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-3 font-medium" x-text="p.name"></td>
              <td class="px-4 py-3 text-gray-500 font-mono text-xs" x-text="p.tenantId?.slice(0,8)+'...'"></td>
              <td class="px-4 py-3">
                <span x-show="p.layers?.layer0?.enabled" class="inline-block bg-blue-100 text-blue-700 text-xs px-1.5 py-0.5 rounded mr-1">L0</span>
                <span x-show="p.layers?.layer1?.enabled" class="inline-block bg-green-100 text-green-700 text-xs px-1.5 py-0.5 rounded mr-1">L1</span>
                <span x-show="p.layers?.layer2?.enabled" class="inline-block bg-yellow-100 text-yellow-700 text-xs px-1.5 py-0.5 rounded mr-1">L2</span>
                <span x-show="p.layers?.layer3?.enabled" class="inline-block bg-red-100 text-red-700 text-xs px-1.5 py-0.5 rounded">L3</span>
              </td>
              <td class="px-4 py-3">
                <span :class="p.failOpen ? 'text-green-600' : 'text-red-600'" x-text="p.failOpen ? 'Open' : 'Closed'"></span>
              </td>
              <td class="px-4 py-3 text-gray-400 text-xs" x-text="p.updatedAt?.slice(0,10)"></td>
              <td class="px-4 py-3">
                <button @click="deletePolicy(p.id)" class="text-red-500 hover:text-red-700 text-xs">Delete</button>
              </td>
            </tr>
          </template>
          <tr x-show="policies.length === 0"><td colspan="6" class="px-4 py-8 text-center text-gray-400">No policies yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── API Keys ── -->
  <div x-show="tab === 'keys'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">API Keys</h2>
      <button @click="showCreateKey = !showCreateKey" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">+ New Key</button>
    </div>

    <div x-show="newKeyResult" x-cloak class="bg-green-50 border border-green-200 rounded p-4 mb-4">
      <p class="text-sm font-medium text-green-800 mb-1">API Key created — save it now, it will not be shown again:</p>
      <code class="text-xs font-mono bg-green-100 px-2 py-1 rounded block break-all" x-text="newKeyResult?.rawKey"></code>
      <button @click="newKeyResult = null" class="mt-2 text-xs text-green-700 underline">Dismiss</button>
    </div>

    <div x-show="showCreateKey" x-cloak class="bg-white border rounded p-4 mb-6">
      <h3 class="font-medium mb-3">Create API Key</h3>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="text-xs text-gray-500">Key Name *</label>
          <input x-model="newKey.name" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="production-app" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Tenant ID *</label>
          <input x-model="newKey.tenantId" class="w-full border rounded px-3 py-1.5 text-sm mt-1" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Default Policy ID *</label>
          <input x-model="newKey.defaultPolicyId" class="w-full border rounded px-3 py-1.5 text-sm mt-1" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Policy IDs (comma-separated) *</label>
          <input x-model="newKey.policyIdsRaw" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="id1,id2" />
        </div>
      </div>
      <div class="mt-3 flex gap-2">
        <button @click="createKey()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded">Create</button>
        <button @click="showCreateKey = false" class="text-sm border px-4 py-1.5 rounded">Cancel</button>
      </div>
    </div>

    <div class="bg-white border rounded overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr>
            <th class="px-4 py-3 text-left">Name</th>
            <th class="px-4 py-3 text-left">Tenant</th>
            <th class="px-4 py-3 text-left">Status</th>
            <th class="px-4 py-3 text-left">Last Used</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <template x-for="k in apiKeys" :key="k.id">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-3 font-medium" x-text="k.name"></td>
              <td class="px-4 py-3 text-gray-500 font-mono text-xs" x-text="k.tenantId?.slice(0,8)+'...'"></td>
              <td class="px-4 py-3">
                <span :class="k.active ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'" class="text-xs px-2 py-0.5 rounded-full" x-text="k.active ? 'Active' : 'Revoked'"></span>
              </td>
              <td class="px-4 py-3 text-gray-400 text-xs" x-text="k.lastUsedAt?.slice(0,16) ?? 'Never'"></td>
              <td class="px-4 py-3 flex gap-3">
                <button x-show="k.active" @click="revokeKey(k.id)" class="text-yellow-600 hover:text-yellow-800 text-xs">Revoke</button>
                <button x-show="k.active" @click="rotateKey(k.id)" class="text-blue-600 hover:text-blue-800 text-xs">Rotate</button>
              </td>
            </tr>
          </template>
          <tr x-show="apiKeys.length === 0"><td colspan="5" class="px-4 py-8 text-center text-gray-400">No API keys yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Tenants ── -->
  <div x-show="tab === 'tenants'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Tenants</h2>
      <button @click="showCreateTenant = !showCreateTenant" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded">+ New Tenant</button>
    </div>
    <div x-show="showCreateTenant" x-cloak class="bg-white border rounded p-4 mb-6">
      <div class="grid grid-cols-2 gap-4">
        <div><label class="text-xs text-gray-500">Name</label><input x-model="newTenant.name" class="w-full border rounded px-3 py-1.5 text-sm mt-1" /></div>
        <div><label class="text-xs text-gray-500">Email</label><input x-model="newTenant.email" type="email" class="w-full border rounded px-3 py-1.5 text-sm mt-1" /></div>
      </div>
      <div class="mt-3 flex gap-2">
        <button @click="createTenant()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded">Create</button>
        <button @click="showCreateTenant = false" class="text-sm border px-4 py-1.5 rounded">Cancel</button>
      </div>
    </div>
    <div class="bg-white border rounded overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr><th class="px-4 py-3 text-left">Name</th><th class="px-4 py-3 text-left">Email</th><th class="px-4 py-3 text-left">Created</th><th class="px-4 py-3"></th></tr>
        </thead>
        <tbody>
          <template x-for="t in tenants" :key="t.id">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-3 font-medium" x-text="t.name"></td>
              <td class="px-4 py-3 text-gray-500" x-text="t.email"></td>
              <td class="px-4 py-3 text-gray-400 text-xs" x-text="t.createdAt?.slice(0,10)"></td>
              <td class="px-4 py-3"><button @click="deleteTenant(t.id)" class="text-red-500 text-xs">Delete</button></td>
            </tr>
          </template>
          <tr x-show="tenants.length === 0"><td colspan="4" class="px-4 py-8 text-center text-gray-400">No tenants yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Attack Signatures ── -->
  <div x-show="tab === 'signatures'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Attack Signatures</h2>
      <button @click="showAddSig = !showAddSig" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded">+ Add Signature</button>
    </div>
    <div x-show="showAddSig" x-cloak class="bg-white border rounded p-4 mb-6">
      <div class="grid grid-cols-2 gap-4">
        <div class="col-span-2"><label class="text-xs text-gray-500">Attack Text *</label><textarea x-model="newSig.text" rows="3" class="w-full border rounded px-3 py-1.5 text-sm mt-1 font-mono" placeholder="Ignore all previous instructions and..."></textarea></div>
        <div><label class="text-xs text-gray-500">Category *</label><input x-model="newSig.category" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="injection" /></div>
        <div><label class="text-xs text-gray-500">MITRE ATLAS ID</label><input x-model="newSig.mitreAtlasId" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="AML.T0051" /></div>
        <div class="col-span-2"><label class="text-xs text-gray-500">Description</label><input x-model="newSig.description" class="w-full border rounded px-3 py-1.5 text-sm mt-1" /></div>
      </div>
      <div class="mt-3 flex gap-2">
        <button @click="addSignature()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded">Add & Embed</button>
        <button @click="showAddSig = false" class="text-sm border px-4 py-1.5 rounded">Cancel</button>
      </div>
    </div>
    <div class="bg-white border rounded overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr><th class="px-4 py-3 text-left">Text</th><th class="px-4 py-3 text-left">Category</th><th class="px-4 py-3 text-left">ATLAS</th><th class="px-4 py-3"></th></tr>
        </thead>
        <tbody>
          <template x-for="s in signatures" :key="s.id">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-3 font-mono text-xs max-w-xs truncate" x-text="s.text"></td>
              <td class="px-4 py-3"><span class="bg-orange-100 text-orange-700 text-xs px-2 py-0.5 rounded-full" x-text="s.category"></span></td>
              <td class="px-4 py-3 text-xs text-gray-500" x-text="s.mitreAtlasId"></td>
              <td class="px-4 py-3"><button @click="deleteSig(s.id)" class="text-red-500 text-xs">Delete</button></td>
            </tr>
          </template>
          <tr x-show="signatures.length === 0"><td colspan="4" class="px-4 py-8 text-center text-gray-400">No signatures yet. Add known attack prompts to seed the vector index.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Playground ── -->
  <div x-show="tab === 'playground'" x-cloak>
    <h2 class="text-lg font-semibold mb-4">Prompt Playground</h2>
    <div class="bg-white border rounded p-6">
      <div class="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label class="text-xs text-gray-500">Firewall API URL</label>
          <input x-model="playground.apiUrl" class="w-full border rounded px-3 py-1.5 text-sm mt-1" placeholder="https://firewall-api.*.workers.dev" />
        </div>
        <div>
          <label class="text-xs text-gray-500">API Key</label>
          <input x-model="playground.apiKey" type="password" class="w-full border rounded px-3 py-1.5 text-sm mt-1" />
        </div>
        <div>
          <label class="text-xs text-gray-500">Policy Name (optional)</label>
          <input x-model="playground.policyName" class="w-full border rounded px-3 py-1.5 text-sm mt-1" />
        </div>
      </div>
      <label class="text-xs text-gray-500">Prompt</label>
      <textarea x-model="playground.prompt" rows="4" class="w-full border rounded px-3 py-2 text-sm mt-1 font-mono" placeholder="Enter a prompt to test..."></textarea>
      <button @click="testPrompt()" :disabled="playground.loading" class="mt-3 bg-indigo-600 text-white text-sm px-4 py-2 rounded hover:bg-indigo-700 disabled:opacity-50">
        <span x-text="playground.loading ? 'Inspecting...' : 'Inspect Prompt'"></span>
      </button>

      <div x-show="playground.result" x-cloak class="mt-6">
        <div :class="{
          'bg-green-50 border-green-200': playground.result?.verdict === 'pass',
          'bg-yellow-50 border-yellow-200': playground.result?.verdict === 'flag',
          'bg-red-50 border-red-200': playground.result?.verdict === 'block'
        }" class="border rounded p-4">
          <div class="flex items-center gap-3 mb-3">
            <span :class="{
              'bg-green-600': playground.result?.verdict === 'pass',
              'bg-yellow-500': playground.result?.verdict === 'flag',
              'bg-red-600': playground.result?.verdict === 'block'
            }" class="text-white text-sm font-bold px-3 py-1 rounded-full uppercase" x-text="playground.result?.verdict"></span>
            <span class="text-sm font-medium">Score: <span x-text="playground.result?.score"></span>/100</span>
            <span class="text-xs text-gray-500">Latency: <span x-text="playground.result?.latencyMs?.total"></span>ms</span>
            <span x-show="playground.result?.cached" class="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">Cached</span>
          </div>
          <template x-if="playground.result?.violations?.length">
            <div>
              <p class="text-xs font-semibold text-gray-600 mb-2">Violations:</p>
              <template x-for="v in playground.result?.violations" :key="v.category">
                <div class="text-xs bg-white border rounded px-3 py-2 mb-1 flex justify-between">
                  <span><strong x-text="v.categoryName"></strong> <span class="text-gray-400">(<span x-text="v.layer"></span>)</span></span>
                  <span class="text-gray-500"><span x-text="v.mitreAtlas?.techniqueId"></span> · <span x-text="Math.round(v.confidence * 100)"></span>%</span>
                </div>
              </template>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Audit Log ── -->
  <div x-show="tab === 'audit'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Audit Log</h2>
      <button @click="loadAudit()" class="text-sm border px-3 py-1 rounded hover:bg-gray-50">Refresh</button>
    </div>
    <div class="bg-white border rounded overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr><th class="px-4 py-3 text-left">Timestamp</th><th class="px-4 py-3 text-left">Action</th><th class="px-4 py-3 text-left">Resource</th><th class="px-4 py-3 text-left">ID</th></tr>
        </thead>
        <tbody>
          <template x-for="e in auditLog" :key="e.id ?? e.timestamp">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-3 text-xs font-mono text-gray-500" x-text="e.timestamp?.slice(0,19)?.replace('T',' ')"></td>
              <td class="px-4 py-3"><span class="bg-blue-100 text-blue-700 text-xs px-2 py-0.5 rounded-full" x-text="e.action"></span></td>
              <td class="px-4 py-3 text-xs" x-text="e.resourceType"></td>
              <td class="px-4 py-3 font-mono text-xs text-gray-400" x-text="e.resourceId?.slice(0,16)+'...'"></td>
            </tr>
          </template>
          <tr x-show="auditLog.length === 0"><td colspan="4" class="px-4 py-8 text-center text-gray-400">No audit entries</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</main>

<script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
<script>
function app() {
  return {
    tab: 'policies',
    adminToken: '',
    message: '',
    messageType: 'success',

    policies: [],
    apiKeys: [],
    tenants: [],
    signatures: [],
    auditLog: [],

    showCreatePolicy: false,
    showCreateKey: false,
    showCreateTenant: false,
    showAddSig: false,
    newKeyResult: null,

    newPolicy: { name: '', tenantId: '', description: '', failOpen: true },
    newKey: { name: '', tenantId: '', defaultPolicyId: '', policyIdsRaw: '' },
    newTenant: { name: '', email: '' },
    newSig: { text: '', category: 'injection', description: '', mitreAtlasId: 'AML.T0051' },

    playground: { apiUrl: '', apiKey: '', policyName: '', prompt: '', result: null, loading: false },

    headers() {
      return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + this.adminToken };
    },

    async api(method, path, body) {
      const res = await fetch('/api' + path, { method, headers: this.headers(), body: body ? JSON.stringify(body) : undefined });
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error ?? res.statusText); }
      return res.json();
    },

    notify(msg, type = 'success') { this.message = msg; this.messageType = type; setTimeout(() => this.message = '', 4000); },

    async init() {},

    async loadAll() {
      try {
        await Promise.all([this.loadPolicies(), this.loadKeys(), this.loadTenants(), this.loadSignatures()]);
        this.notify('Connected');
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async loadPolicies() { this.policies = await this.api('GET', '/policies'); },
    async loadKeys() {
      // Load keys for all tenants — simplified: list first tenant or all
      try { this.apiKeys = await this.api('GET', '/keys/tenant/all').catch(() => []); } catch { this.apiKeys = []; }
    },
    async loadTenants() { this.tenants = await this.api('GET', '/tenants'); },
    async loadSignatures() { this.signatures = await this.api('GET', '/signatures'); },
    async loadAudit() { this.auditLog = await this.api('GET', '/audit'); },

    async createPolicy() {
      try {
        const p = await this.api('POST', '/policies', { ...this.newPolicy });
        this.policies.unshift(p);
        this.showCreatePolicy = false;
        this.newPolicy = { name: '', tenantId: '', description: '', failOpen: true };
        this.notify('Policy created: ' + p.id);
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async deletePolicy(id) {
      if (!confirm('Delete policy ' + id + '?')) return;
      try {
        await this.api('DELETE', '/policies/' + id);
        this.policies = this.policies.filter(p => p.id !== id);
        this.notify('Policy deleted');
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async createKey() {
      try {
        const policyIds = this.newKey.policyIdsRaw.split(',').map(s => s.trim()).filter(Boolean);
        const result = await this.api('POST', '/keys', { ...this.newKey, policyIds });
        this.newKeyResult = result;
        this.showCreateKey = false;
        this.newKey = { name: '', tenantId: '', defaultPolicyId: '', policyIdsRaw: '' };
        this.notify('API key created');
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async revokeKey(id) {
      if (!confirm('Revoke this key?')) return;
      try { await this.api('POST', '/keys/' + id + '/revoke'); this.notify('Key revoked'); await this.loadKeys(); }
      catch (e) { this.notify(e.message, 'error'); }
    },

    async rotateKey(id) {
      try {
        const result = await this.api('POST', '/keys/' + id + '/rotate');
        this.newKeyResult = result;
        this.notify('Key rotated — save the new key');
        await this.loadKeys();
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async createTenant() {
      try {
        const t = await this.api('POST', '/tenants', { ...this.newTenant, active: true });
        this.tenants.unshift(t);
        this.showCreateTenant = false;
        this.newTenant = { name: '', email: '' };
        this.notify('Tenant created: ' + t.id);
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async deleteTenant(id) {
      if (!confirm('Delete tenant ' + id + '?')) return;
      try { await this.api('DELETE', '/tenants/' + id); this.tenants = this.tenants.filter(t => t.id !== id); this.notify('Tenant deleted'); }
      catch (e) { this.notify(e.message, 'error'); }
    },

    async addSignature() {
      try {
        const s = await this.api('POST', '/signatures', { ...this.newSig });
        this.signatures.unshift(s);
        this.showAddSig = false;
        this.newSig = { text: '', category: 'injection', description: '', mitreAtlasId: 'AML.T0051' };
        this.notify('Signature added and embedded');
      } catch (e) { this.notify(e.message, 'error'); }
    },

    async deleteSig(id) {
      try { await this.api('DELETE', '/signatures/' + id); this.signatures = this.signatures.filter(s => s.id !== id); this.notify('Signature deleted'); }
      catch (e) { this.notify(e.message, 'error'); }
    },

    async testPrompt() {
      this.playground.loading = true;
      this.playground.result = null;
      try {
        const headers = { 'Content-Type': 'application/json', 'X-API-Key': this.playground.apiKey };
        if (this.playground.policyName) headers['X-Policy-Name'] = this.playground.policyName;
        const res = await fetch(this.playground.apiUrl + '/v1/inspect', {
          method: 'POST',
          headers,
          body: JSON.stringify({ prompt: this.playground.prompt }),
        });
        this.playground.result = await res.json();
      } catch (e) { this.notify(e.message, 'error'); }
      finally { this.playground.loading = false; }
    },
  };
}
</script>
</body>
</html>`;

export default html;
