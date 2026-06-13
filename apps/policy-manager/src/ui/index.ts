const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI Firewall — Policy Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
  <style>
    [x-cloak] { display: none !important; }
    .tab-active { border-bottom-color: #4f46e5; color: #4f46e5; }
    details > summary { cursor: pointer; list-style: none; }
    details > summary::before { content: '▶ '; font-size: 0.65rem; color: #9ca3af; }
    details[open] > summary::before { content: '▼ '; }
  </style>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen" x-data="app()" x-init="init()">

<nav class="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
  <div class="flex items-center gap-3">
    <span class="text-xl font-bold text-indigo-600">AI Firewall</span>
    <span class="text-xs text-gray-400 font-mono">v2 · Policy Manager</span>
  </div>
  <div class="flex items-center gap-2">
    <input x-model="adminToken" type="password" placeholder="Admin token" class="text-sm border rounded px-3 py-1 w-56" />
    <button @click="loadAll()" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">Connect</button>
  </div>
</nav>

<div class="bg-white border-b border-gray-200 px-6">
  <nav class="flex gap-6 text-sm font-medium">
    <template x-for="t in ['profiles','keys','signatures','audit']">
      <button @click="tab=t" :class="tab===t ? 'tab-active' : 'text-gray-500 hover:text-gray-700'"
        class="py-3 border-b-2 border-transparent capitalize" x-text="t === 'keys' ? 'API Keys' : t === 'audit' ? 'Audit Log' : t"></button>
    </template>
  </nav>
</div>

<main class="max-w-6xl mx-auto px-6 py-8">

  <div x-show="message" x-cloak :class="msgErr ? 'bg-red-50 border-red-200 text-red-700' : 'bg-green-50 border-green-200 text-green-700'"
    class="mb-4 border rounded px-4 py-3 text-sm flex justify-between">
    <span x-text="message"></span>
    <button @click="message=''" class="font-bold ml-4">×</button>
  </div>

  <!-- ── Profiles ── -->
  <div x-show="tab==='profiles'">
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Security Profiles</h2>
      <div class="flex gap-2">
        <button @click="showAddFromTemplate=!showAddFromTemplate" class="text-sm border border-indigo-600 text-indigo-600 px-3 py-1 rounded hover:bg-indigo-50">+ From Template</button>
        <button @click="openCreateProfile()" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">+ New Profile</button>
      </div>
    </div>

    <!-- Add-from-template panel -->
    <div x-show="showAddFromTemplate" x-cloak class="mb-6 bg-indigo-50 border border-indigo-200 rounded-lg p-4">
      <p class="text-sm font-medium text-indigo-800 mb-3">Create a profile with built-in template policies</p>
      <div class="flex gap-3 flex-wrap">
        <template x-for="tpl in templates" :key="tpl">
          <button @click="createFromTemplate(tpl)"
            class="text-sm bg-white border border-indigo-300 px-3 py-2 rounded hover:bg-indigo-100 capitalize"
            x-text="tpl.replace(/-/g,' ')"></button>
        </template>
      </div>
    </div>

    <!-- Create/Edit profile form -->
    <div x-show="showProfileForm" x-cloak class="mb-6 bg-white border rounded-lg p-4">
      <h3 class="font-semibold mb-3" x-text="editingProfile ? 'Edit Profile' : 'New Profile'"></h3>
      <div class="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label class="block text-xs text-gray-500 mb-1">Name *</label>
          <input x-model="profileForm.name" type="text" class="w-full border rounded px-3 py-1.5 text-sm" placeholder="e.g. Production Strict" />
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">Rate Limit (req/min, blank = 60)</label>
          <input x-model.number="profileForm.rateLimit" type="number" class="w-full border rounded px-3 py-1.5 text-sm" placeholder="60" />
        </div>
      </div>
      <div class="mb-3">
        <label class="block text-xs text-gray-500 mb-1">Description</label>
        <input x-model="profileForm.description" type="text" class="w-full border rounded px-3 py-1.5 text-sm" />
      </div>
      <div class="flex items-center gap-4 mb-3 text-sm">
        <label class="flex items-center gap-2">
          <input x-model="profileForm.failOpen" type="checkbox" class="rounded" />
          Fail-open on AI errors
        </label>
        <div class="flex items-center gap-2">
          <span class="text-gray-500">Cache TTL (s):</span>
          <input x-model.number="profileForm.cacheTtlSeconds" type="number" class="border rounded px-2 py-1 text-sm w-24" />
        </div>
      </div>
      <div class="flex gap-2">
        <button @click="saveProfile()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded hover:bg-indigo-700">Save</button>
        <button @click="showProfileForm=false;editingProfile=null" class="text-sm text-gray-500 px-4 py-1.5">Cancel</button>
      </div>
    </div>

    <div x-show="profiles.length === 0" x-cloak class="text-sm text-gray-400 py-8 text-center">
      No profiles yet. Connect with your admin token to load, or create one above.
    </div>

    <div class="space-y-4">
      <template x-for="profile in profiles" :key="profile.id">
        <div class="bg-white border rounded-lg overflow-hidden">
          <!-- Profile header -->
          <div class="flex items-center justify-between px-5 py-3 border-b bg-gray-50">
            <div>
              <span class="font-semibold" x-text="profile.name"></span>
              <span class="ml-2 text-xs text-gray-400" x-text="profile.id"></span>
            </div>
            <div class="flex items-center gap-2">
              <span class="text-xs text-gray-500" x-text="(profile.policies?.length ?? 0) + ' policies'"></span>
              <button @click="openEditProfile(profile)" class="text-xs text-indigo-600 hover:underline">Edit</button>
              <button @click="confirmDeleteProfile(profile.id)" class="text-xs text-red-500 hover:underline">Delete</button>
            </div>
          </div>
          <!-- Policies within profile -->
          <div class="px-5 py-3">
            <template x-for="policy in (profile.policies ?? [])" :key="policy.id">
              <details class="mb-2">
                <summary class="text-sm font-medium py-1">
                  <span x-text="policy.name"></span>
                  <span class="text-xs text-gray-400 ml-2" x-text="'(' + (policy.categories?.length ?? 0) + ' categories)'"></span>
                </summary>
                <div class="ml-4 mt-1 space-y-1">
                  <template x-for="cat in (policy.categories ?? [])" :key="cat.id">
                    <details class="bg-gray-50 rounded p-2">
                      <summary class="text-xs font-medium text-gray-700">
                        <span x-text="cat.name"></span>
                        <span class="text-gray-400 ml-1" x-text="'(' + (cat.detections?.length ?? 0) + ')'"></span>
                      </summary>
                      <div class="ml-3 mt-1 space-y-1">
                        <template x-for="det in (cat.detections ?? [])" :key="det.id">
                          <div class="flex items-start gap-2 text-xs py-1">
                            <span :class="det.mode==='block' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'"
                              class="px-1.5 py-0.5 rounded font-mono text-[10px] shrink-0" x-text="det.mode"></span>
                            <div>
                              <span class="font-medium" x-text="det.name"></span>
                              <div class="text-gray-400 mt-0.5" x-text="(det.settings ?? []).filter(s=>s.enabled).map(s=>s.name).join(', ')"></div>
                            </div>
                          </div>
                        </template>
                      </div>
                    </details>
                  </template>
                </div>
              </details>
            </template>
            <div x-show="(profile.policies ?? []).length === 0" class="text-xs text-gray-400 py-2">No policies embedded yet.</div>
          </div>
        </div>
      </template>
    </div>
  </div>

  <!-- ── API Keys ── -->
  <div x-show="tab==='keys'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">API Keys</h2>
      <button @click="showKeyForm=!showKeyForm" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">+ New Key</button>
    </div>

    <div x-show="showKeyForm" x-cloak class="mb-6 bg-white border rounded-lg p-4">
      <h3 class="font-semibold mb-3">Create API Key</h3>
      <div class="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label class="block text-xs text-gray-500 mb-1">Name *</label>
          <input x-model="keyForm.name" type="text" class="w-full border rounded px-3 py-1.5 text-sm" placeholder="e.g. prod-backend" />
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">Bind to Profile *</label>
          <select x-model="keyForm.profileId" class="w-full border rounded px-3 py-1.5 text-sm">
            <option value="">Select profile…</option>
            <template x-for="p in profiles" :key="p.id">
              <option :value="p.id" x-text="p.name"></option>
            </template>
          </select>
        </div>
      </div>
      <div class="flex gap-2">
        <button @click="createKey()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded hover:bg-indigo-700">Generate</button>
        <button @click="showKeyForm=false" class="text-sm text-gray-500 px-4 py-1.5">Cancel</button>
      </div>
    </div>

    <!-- Newly created key banner -->
    <div x-show="newRawKey" x-cloak class="mb-4 bg-amber-50 border border-amber-300 rounded-lg p-4">
      <p class="text-sm font-semibold text-amber-800 mb-1">Save this key — it will not be shown again</p>
      <code class="text-sm font-mono break-all text-amber-900" x-text="newRawKey"></code>
      <button @click="newRawKey=''" class="ml-3 text-xs text-amber-600 hover:underline">Dismiss</button>
    </div>

    <div class="bg-white border rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr>
            <th class="px-4 py-2 text-left">Name</th>
            <th class="px-4 py-2 text-left">Profile</th>
            <th class="px-4 py-2 text-left">Status</th>
            <th class="px-4 py-2 text-left">Created</th>
            <th class="px-4 py-2 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          <template x-for="key in apiKeys" :key="key.id">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-2 font-medium" x-text="key.name"></td>
              <td class="px-4 py-2 text-gray-500 text-xs font-mono" x-text="key.profileId?.slice(0,8)+'…'"></td>
              <td class="px-4 py-2">
                <span :class="key.active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'"
                  class="px-2 py-0.5 rounded text-xs" x-text="key.active ? 'active' : 'revoked'"></span>
              </td>
              <td class="px-4 py-2 text-gray-500 text-xs" x-text="key.createdAt?.slice(0,10)"></td>
              <td class="px-4 py-2 flex gap-2">
                <button x-show="key.active" @click="rotateKey(key.id)" class="text-xs text-blue-600 hover:underline">Rotate</button>
                <button x-show="key.active" @click="revokeKey(key.id)" class="text-xs text-red-500 hover:underline">Revoke</button>
                <button @click="deleteKey(key.id)" class="text-xs text-gray-400 hover:underline">Delete</button>
              </td>
            </tr>
          </template>
          <tr x-show="apiKeys.length===0" class="border-t">
            <td colspan="5" class="px-4 py-6 text-center text-gray-400 text-sm">No keys yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Signatures ── -->
  <div x-show="tab==='signatures'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Attack Signatures <span class="text-xs text-gray-400">(Vectorize)</span></h2>
      <button @click="showSigForm=!showSigForm" class="text-sm bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700">+ Add Signature</button>
    </div>
    <div x-show="showSigForm" x-cloak class="mb-4 bg-white border rounded-lg p-4">
      <div class="space-y-2 mb-3">
        <input x-model="sigForm.text" type="text" placeholder="Attack text *" class="w-full border rounded px-3 py-1.5 text-sm" />
        <input x-model="sigForm.category" type="text" placeholder="Category (e.g. injection)" class="w-full border rounded px-3 py-1.5 text-sm" />
        <input x-model="sigForm.description" type="text" placeholder="Description" class="w-full border rounded px-3 py-1.5 text-sm" />
      </div>
      <div class="flex gap-2">
        <button @click="addSignature()" class="text-sm bg-indigo-600 text-white px-4 py-1.5 rounded">Add</button>
        <button @click="showSigForm=false" class="text-sm text-gray-500 px-4 py-1.5">Cancel</button>
      </div>
    </div>
    <div class="bg-white border rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr>
            <th class="px-4 py-2 text-left">Text</th>
            <th class="px-4 py-2 text-left">Category</th>
            <th class="px-4 py-2 text-left">Created</th>
            <th class="px-4 py-2 text-left"></th>
          </tr>
        </thead>
        <tbody>
          <template x-for="sig in signatures" :key="sig.id">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-2 text-gray-700 max-w-xs truncate" x-text="sig.text"></td>
              <td class="px-4 py-2 text-gray-500 text-xs" x-text="sig.category"></td>
              <td class="px-4 py-2 text-gray-400 text-xs" x-text="sig.createdAt?.slice(0,10)"></td>
              <td class="px-4 py-2"><button @click="deleteSig(sig.id)" class="text-xs text-red-500 hover:underline">Delete</button></td>
            </tr>
          </template>
          <tr x-show="signatures.length===0" class="border-t">
            <td colspan="4" class="px-4 py-6 text-center text-gray-400 text-sm">No signatures yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Audit ── -->
  <div x-show="tab==='audit'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Audit Log</h2>
      <button @click="loadAudit()" class="text-sm text-indigo-600 hover:underline">Refresh</button>
    </div>
    <div class="bg-white border rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 text-xs text-gray-500 uppercase">
          <tr>
            <th class="px-4 py-2 text-left">Time</th>
            <th class="px-4 py-2 text-left">Action</th>
            <th class="px-4 py-2 text-left">Type</th>
            <th class="px-4 py-2 text-left">Resource ID</th>
          </tr>
        </thead>
        <tbody>
          <template x-for="(evt, i) in auditEvents" :key="i">
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-2 text-gray-400 text-xs" x-text="evt.timestamp?.slice(0,19)?.replace('T',' ')"></td>
              <td class="px-4 py-2 font-medium" x-text="evt.action"></td>
              <td class="px-4 py-2 text-gray-500" x-text="evt.resourceType"></td>
              <td class="px-4 py-2 font-mono text-xs text-gray-500" x-text="evt.resourceId"></td>
            </tr>
          </template>
          <tr x-show="auditEvents.length===0" class="border-t">
            <td colspan="4" class="px-4 py-6 text-center text-gray-400 text-sm">No events yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

</main>

<script>
function app() {
  return {
    adminToken: '',
    tab: 'profiles',
    message: '',
    msgErr: false,
    profiles: [],
    apiKeys: [],
    signatures: [],
    auditEvents: [],
    templates: [],
    newRawKey: '',
    showProfileForm: false,
    showAddFromTemplate: false,
    showKeyForm: false,
    showSigForm: false,
    editingProfile: null,
    profileForm: { name: '', description: '', rateLimit: null, failOpen: true, cacheTtlSeconds: 3600 },
    keyForm: { name: '', profileId: '' },
    sigForm: { text: '', category: 'injection', description: '' },

    async init() {
      const res = await fetch('/api/templates');
      if (res.ok) this.templates = await res.json();
    },

    async loadAll() {
      await Promise.all([this.loadProfiles(), this.loadKeys(), this.loadSigs(), this.loadAudit()]);
    },

    headers() {
      return { 'Authorization': 'Bearer ' + this.adminToken, 'Content-Type': 'application/json' };
    },

    notify(msg, err = false) { this.message = msg; this.msgErr = err; },

    async loadProfiles() {
      const r = await fetch('/api/profiles', { headers: this.headers() });
      if (r.ok) this.profiles = await r.json();
      else this.notify('Failed to load profiles', true);
    },

    async loadKeys() {
      const r = await fetch('/api/keys', { headers: this.headers() });
      if (r.ok) this.apiKeys = await r.json();
    },

    async loadSigs() {
      const r = await fetch('/api/signatures', { headers: this.headers() });
      if (r.ok) this.signatures = await r.json();
    },

    async loadAudit() {
      const r = await fetch('/api/audit', { headers: this.headers() });
      if (r.ok) this.auditEvents = await r.json();
    },

    openCreateProfile() {
      this.editingProfile = null;
      this.profileForm = { name: '', description: '', rateLimit: null, failOpen: true, cacheTtlSeconds: 3600 };
      this.showProfileForm = true;
    },

    openEditProfile(profile) {
      this.editingProfile = profile;
      this.profileForm = {
        name: profile.name,
        description: profile.description,
        rateLimit: profile.rateLimit?.requestsPerMinute ?? null,
        failOpen: profile.failOpen,
        cacheTtlSeconds: profile.cacheTtlSeconds,
      };
      this.showProfileForm = true;
    },

    async saveProfile() {
      const body = {
        name: this.profileForm.name,
        description: this.profileForm.description,
        rateLimit: this.profileForm.rateLimit ? { requestsPerMinute: Number(this.profileForm.rateLimit) } : null,
        failOpen: this.profileForm.failOpen,
        cacheTtlSeconds: Number(this.profileForm.cacheTtlSeconds) || 3600,
        policies: this.editingProfile ? (this.editingProfile.policies ?? []) : [],
      };
      if (!body.name) return this.notify('Name is required', true);

      let r;
      if (this.editingProfile) {
        r = await fetch('/api/profiles/' + this.editingProfile.id, { method: 'PUT', headers: this.headers(), body: JSON.stringify(body) });
      } else {
        r = await fetch('/api/profiles', { method: 'POST', headers: this.headers(), body: JSON.stringify(body) });
      }
      if (r.ok) {
        this.notify(this.editingProfile ? 'Profile updated' : 'Profile created');
        this.showProfileForm = false;
        this.editingProfile = null;
        await this.loadProfiles();
      } else {
        this.notify('Save failed: ' + (await r.text()), true);
      }
    },

    async createFromTemplate(slug) {
      const tplRes = await fetch('/api/templates/' + slug);
      if (!tplRes.ok) return this.notify('Template not found', true);
      const tpl = await tplRes.json();
      const now = new Date().toISOString().slice(0,10);
      const body = {
        name: tpl.name + ' (Default)',
        description: tpl.description,
        policies: [tpl],
        rateLimit: null, failOpen: true, cacheTtlSeconds: 3600,
      };
      const r = await fetch('/api/profiles', { method: 'POST', headers: this.headers(), body: JSON.stringify(body) });
      if (r.ok) {
        this.notify('Profile created from template "' + tpl.name + '"');
        this.showAddFromTemplate = false;
        await this.loadProfiles();
      } else {
        this.notify('Create failed: ' + (await r.text()), true);
      }
    },

    async confirmDeleteProfile(id) {
      if (!confirm('Delete this profile? API keys bound to it will stop working.')) return;
      const r = await fetch('/api/profiles/' + id, { method: 'DELETE', headers: this.headers() });
      if (r.ok) { this.notify('Profile deleted'); await this.loadProfiles(); }
      else this.notify('Delete failed', true);
    },

    async createKey() {
      if (!this.keyForm.name || !this.keyForm.profileId) return this.notify('Name and profile are required', true);
      const r = await fetch('/api/keys', { method: 'POST', headers: this.headers(), body: JSON.stringify(this.keyForm) });
      if (r.ok) {
        const data = await r.json();
        this.newRawKey = data.rawKey;
        this.showKeyForm = false;
        this.notify('API key created — save it now');
        await this.loadKeys();
      } else this.notify('Create failed: ' + (await r.text()), true);
    },

    async revokeKey(id) {
      if (!confirm('Revoke this key?')) return;
      const r = await fetch('/api/keys/' + id + '/revoke', { method: 'POST', headers: this.headers() });
      if (r.ok) { this.notify('Key revoked'); await this.loadKeys(); }
      else this.notify('Revoke failed', true);
    },

    async rotateKey(id) {
      if (!confirm('Rotate this key? The old key will stop working immediately.')) return;
      const r = await fetch('/api/keys/' + id + '/rotate', { method: 'POST', headers: this.headers() });
      if (r.ok) {
        const data = await r.json();
        this.newRawKey = data.rawKey;
        this.notify('Key rotated — save the new key now');
        await this.loadKeys();
      } else this.notify('Rotate failed', true);
    },

    async deleteKey(id) {
      if (!confirm('Permanently delete this key?')) return;
      const r = await fetch('/api/keys/' + id, { method: 'DELETE', headers: this.headers() });
      if (r.ok) { this.notify('Key deleted'); await this.loadKeys(); }
      else this.notify('Delete failed', true);
    },

    async addSignature() {
      if (!this.sigForm.text) return this.notify('Text is required', true);
      const r = await fetch('/api/signatures', { method: 'POST', headers: this.headers(), body: JSON.stringify(this.sigForm) });
      if (r.ok) {
        this.notify('Signature added');
        this.showSigForm = false;
        await this.loadSigs();
      } else {
        const err = await r.json().catch(() => ({ error: r.statusText }));
        this.notify(err.error ?? 'Failed', true);
      }
    },

    async deleteSig(id) {
      if (!confirm('Delete this signature from Vectorize?')) return;
      const r = await fetch('/api/signatures/' + id, { method: 'DELETE', headers: this.headers() });
      if (r.ok) { this.notify('Signature deleted'); await this.loadSigs(); }
      else this.notify('Delete failed', true);
    },
  };
}
</script>
</body>
</html>`;

export default html;
