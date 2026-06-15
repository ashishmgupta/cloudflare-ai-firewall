const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cloudflare AI Firewall - Policy Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
  <style>
    [x-cloak] { display: none !important; }
    .tab-active { border-bottom-color: #3b82f6; color: #fff; }
    details > summary { cursor: pointer; list-style: none; }
    details > summary::before { content: '▶ '; font-size: 0.65rem; color: #6b7280; }
    details[open] > summary::before { content: '▼ '; }
    input, select, textarea { color-scheme: dark; }
  </style>
</head>
<body class="bg-gray-950 text-gray-200 min-h-screen" x-data="app()" x-init="init()">

<!-- ── Login overlay ────────────────────────────────────────────────────────── -->
<div x-show="!loggedIn" style="position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:#03040a;z-index:50">
  <div style="background:#0d1117;border:1px solid #1f2937;border-radius:12px" class="p-9 w-full max-w-sm text-center">
    <div class="text-2xl font-bold text-white mb-8">Cloudflare AI Firewall<br><span class="text-lg font-semibold text-gray-400">Policy Manager</span></div>
    <div x-show="loginError" x-cloak class="mb-4 text-red-400 text-sm bg-red-950 border border-red-800 rounded px-3 py-2 text-left" x-text="loginError"></div>
    <div class="space-y-3 text-left">
      <div>
        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Username</label>
        <input type="text" x-model="loginUsername" @keydown.enter="login()"
          class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder-gray-600" placeholder="admin" autocomplete="username" />
      </div>
      <div>
        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Password</label>
        <input type="password" x-model="loginPassword" @keydown.enter="login()"
          class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" autocomplete="current-password" />
      </div>
      <button @click="login()" :disabled="loginBusy"
        class="w-full bg-blue-600 text-white py-2 rounded text-sm font-medium hover:bg-blue-700 disabled:opacity-50 mt-1"
        x-text="loginBusy ? 'Signing in…' : 'Sign In'"></button>
    </div>
  </div>
</div>

<!-- ── App (hidden until logged in) ────────────────────────────────────────── -->
<div x-show="loggedIn" x-cloak>

<nav class="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
  <div class="flex items-center gap-3">
    <span class="text-xl font-bold text-white">Cloudflare AI Firewall</span>
    <span class="text-gray-700 select-none">·</span>
    <span class="text-sm font-semibold text-gray-400">Policy Manager</span>
  </div>
  <div class="flex items-center gap-3">
    <span class="text-xs bg-blue-900 text-blue-300 border border-blue-700 rounded px-2 py-0.5 font-semibold">ADMIN</span>
    <span class="text-sm text-white font-medium" x-text="user && user.username"></span>
    <button @click="logout()" class="text-sm text-gray-400 hover:text-gray-200 border border-gray-700 rounded px-3 py-1">Sign Out</button>
  </div>
</nav>

<div class="bg-gray-900 border-b border-gray-800 px-6">
  <nav class="flex gap-6 text-sm font-medium">
    <template x-for="t in ['profiles','keys','signatures','audit']">
      <button @click="tab=t" :class="tab===t ? 'tab-active' : 'text-gray-400 hover:text-gray-200'"
        class="py-3 border-b-2 border-transparent capitalize" x-text="t === 'keys' ? 'API Keys' : t === 'audit' ? 'Audit Log' : t"></button>
    </template>
  </nav>
</div>

<main class="max-w-6xl mx-auto px-6 py-8">

  <div x-show="message" x-cloak :class="msgErr ? 'bg-red-950 border-red-800 text-red-400' : 'bg-green-950 border-green-800 text-green-400'"
    class="mb-4 border rounded px-4 py-3 text-sm flex justify-between">
    <span x-text="message"></span>
    <button @click="message=''" class="font-bold ml-4">×</button>
  </div>

  <!-- Raw key banner -->
  <div x-show="newRawKey" x-cloak class="mb-4 bg-amber-950 border border-amber-700 rounded-lg p-4">
    <p class="text-sm font-semibold text-amber-300 mb-1">Save this API key — it will not be shown again</p>
    <code class="block text-sm font-mono break-all text-amber-200 mt-1 mb-2" x-text="newRawKey"></code>
    <p class="text-xs text-amber-400 mb-2">Use this key as the <code class="bg-amber-900 px-1 rounded">X-API-Key</code> header when calling <code class="bg-amber-900 px-1 rounded">POST /v1/inspect</code> on the firewall-api.</p>
    <button @click="newRawKey=''" class="text-xs text-amber-400 hover:underline">Dismiss</button>
  </div>

  <!-- ── Profiles ── -->
  <div x-show="tab==='profiles'">
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold text-white">Security Profiles</h2>
      <div class="flex gap-2">
        <button @click="showAddFromTemplate=!showAddFromTemplate" class="text-sm border border-blue-600 text-blue-400 px-3 py-1 rounded hover:bg-blue-950">+ From Template</button>
        <button @click="openCreateProfile()" class="text-sm bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700">+ New Profile</button>
      </div>
    </div>

    <div x-show="showAddFromTemplate" x-cloak class="mb-6 bg-blue-950 border border-blue-800 rounded-lg p-4">
      <p class="text-sm font-medium text-blue-200 mb-3">Create a profile with built-in template policies</p>
      <div class="flex gap-3 flex-wrap">
        <template x-for="tpl in templates" :key="tpl">
          <button @click="createFromTemplate(tpl)"
            class="text-sm bg-gray-800 border border-blue-700 text-white px-3 py-2 rounded hover:bg-blue-900 capitalize"
            x-text="tpl.replace(/-/g,' ')"></button>
        </template>
      </div>
    </div>

    <div x-show="showProfileForm" x-cloak class="mb-6 bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 class="font-semibold mb-3 text-white" x-text="editingProfile ? 'Edit Profile' : 'New Profile'"></h3>
      <div class="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label class="block text-xs text-gray-500 mb-1">Name *</label>
          <input x-model="profileForm.name" type="text" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600" placeholder="e.g. Production Strict" />
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">Rate Limit (req/min, blank = 60)</label>
          <input x-model.number="profileForm.rateLimit" type="number" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600" placeholder="60" />
        </div>
      </div>
      <div class="mb-3">
        <label class="block text-xs text-gray-500 mb-1">Description</label>
        <input x-model="profileForm.description" type="text" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200" />
      </div>
      <div class="flex items-center gap-4 mb-3 text-sm text-gray-300">
        <label class="flex items-center gap-2">
          <input x-model="profileForm.failOpen" type="checkbox" class="rounded" />
          Fail-open on AI errors
        </label>
        <div class="flex items-center gap-2">
          <span class="text-gray-500">Cache TTL (s):</span>
          <input x-model.number="profileForm.cacheTtlSeconds" type="number" class="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-200 w-24" />
        </div>
      </div>
      <div class="flex gap-2">
        <button @click="saveProfile()" class="text-sm bg-blue-600 text-white px-4 py-1.5 rounded hover:bg-blue-700">Save</button>
        <button @click="showProfileForm=false;editingProfile=null" class="text-sm text-gray-400 px-4 py-1.5">Cancel</button>
      </div>
    </div>

    <div x-show="profiles.length === 0" x-cloak class="text-sm text-gray-500 py-8 text-center">
      No profiles yet. Create one above.
    </div>

    <div class="space-y-2">
      <template x-for="profile in profiles" :key="profile.id">
        <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden" x-data="{ open: false }">

          <!-- ── Collapsed header (always visible) ── -->
          <div @click="open = !open"
            class="flex items-center gap-3 px-5 py-3 bg-gray-800 cursor-pointer select-none hover:bg-gray-750 transition-colors"
            :class="open ? 'border-b border-gray-700' : ''">
            <!-- Chevron -->
            <span class="text-gray-500 text-[10px] shrink-0 w-3" x-text="open ? '▼' : '▶'"></span>
            <!-- Name + ID -->
            <span class="font-semibold text-white shrink-0" x-text="profile.name"></span>
            <span class="text-xs text-gray-600 font-mono shrink-0 hidden sm:block" x-text="profile.id.slice(0,8) + '…'"></span>
            <!-- Collapsed: policy chips + key count -->
            <div x-show="!open" class="flex items-center gap-2 flex-1 min-w-0 overflow-hidden">
              <template x-for="pol in (profile.policies ?? []).filter(p => p.id !== 'policy-custom-rules')" :key="pol.id">
                <span class="text-xs bg-gray-700 text-gray-300 rounded px-2 py-0.5 shrink-0" x-text="pol.name"></span>
              </template>
              <span x-show="getCustomDets(profile).length > 0"
                class="text-xs bg-blue-950 text-blue-400 border border-blue-800 rounded px-2 py-0.5 shrink-0"
                x-text="getCustomDets(profile).length + ' custom rule' + (getCustomDets(profile).length > 1 ? 's' : '')"></span>
            </div>
            <!-- Expanded: spacer -->
            <div x-show="open" class="flex-1"></div>
            <!-- Always-visible: key count + actions -->
            <span class="text-xs text-gray-600 shrink-0"
              x-text="apiKeys.filter(k => k.profileId === profile.id).length + ' key' + (apiKeys.filter(k => k.profileId === profile.id).length !== 1 ? 's' : '')"></span>
            <button @click.stop="openEditProfile(profile)" class="text-xs text-blue-400 hover:underline shrink-0">Edit</button>
            <button @click.stop="confirmDeleteProfile(profile.id)" class="text-xs text-red-400 hover:underline shrink-0">Delete</button>
          </div>

          <!-- ── Expanded content ── -->
          <div x-show="open">
            <div class="px-5 py-4">

              <!-- Policies -->
              <div class="mb-1">
                <template x-for="policy in (profile.policies ?? []).filter(p => p.id !== 'policy-custom-rules')" :key="policy.id">
                  <details class="mb-2">
                    <summary class="text-sm font-medium py-1 flex items-center text-gray-200">
                      <span x-text="policy.name"></span>
                      <span class="text-xs text-gray-500 ml-2" x-text="'(' + (policy.categories?.length ?? 0) + ' categories)'"></span>
                      <button @click.stop="removePolicyFromProfile(profile, policy.id)" class="ml-auto text-xs text-red-400 hover:text-red-300 font-normal">Remove</button>
                    </summary>
                    <div class="ml-4 mt-1 space-y-1">
                      <template x-for="cat in (policy.categories ?? [])" :key="cat.id">
                        <details class="bg-gray-800 rounded p-2">
                          <summary class="text-xs font-medium text-gray-300">
                            <span x-text="cat.name"></span>
                            <span class="text-gray-500 ml-1" x-text="'(' + (cat.detections?.length ?? 0) + ')'"></span>
                          </summary>
                          <div class="ml-3 mt-1 space-y-1">
                            <template x-for="det in (cat.detections ?? [])" :key="det.id">
                              <div class="flex items-start gap-2 text-xs py-1">
                                <span :class="det.mode==='block' ? 'bg-red-950 text-red-400' : 'bg-yellow-950 text-yellow-400'"
                                  class="px-1.5 py-0.5 rounded font-mono text-[10px] shrink-0" x-text="det.mode"></span>
                                <div>
                                  <span class="font-medium text-gray-200" x-text="det.name"></span>
                                  <div class="text-gray-500 mt-0.5" x-text="(det.settings ?? []).filter(s=>s.enabled).map(s=>s.name).join(', ')"></div>
                                </div>
                              </div>
                            </template>
                          </div>
                        </details>
                      </template>
                    </div>
                  </details>
                </template>
                <div x-show="(profile.policies ?? []).filter(p => p.id !== 'policy-custom-rules').length === 0"
                  class="text-xs text-gray-500 py-2">No policies embedded yet.</div>
              </div>

              <!-- Add policy -->
              <div class="pt-3 border-t border-gray-800 flex items-center gap-2 flex-wrap">
                <span class="text-xs text-gray-500">Add policy:</span>
                <template x-for="tpl in templates" :key="tpl">
                  <button @click="addPolicyToProfile(profile, tpl)"
                    class="text-xs border border-blue-700 text-blue-400 px-2 py-0.5 rounded hover:bg-blue-950"
                    x-text="tpl.replace(/-/g,' ')"></button>
                </template>
              </div>

              <!-- ── Custom Rules ── -->
              <div class="mt-4 pt-3 border-t border-gray-800">
                <div class="flex items-center justify-between mb-2">
                  <span class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Custom Rules</span>
                  <button @click="openAddCustomRule(profile)" class="text-xs text-blue-400 hover:underline">+ Add Rule</button>
                </div>
                <template x-for="det in getCustomDets(profile)" :key="det.id">
                  <div class="flex items-start gap-2 py-1 text-xs">
                    <span :class="det.mode==='block' ? 'bg-red-950 text-red-400' : 'bg-yellow-950 text-yellow-400'"
                      class="px-1.5 py-0.5 rounded font-mono text-[10px] shrink-0" x-text="det.mode"></span>
                    <div class="flex-1 min-w-0">
                      <span class="font-medium text-gray-200" x-text="det.name"></span>
                      <span class="text-gray-500 ml-1" x-text="'(' + (det.customPatterns||[]).length + ' patterns)'"></span>
                      <div class="text-gray-500 mt-0.5 flex flex-wrap gap-1">
                        <template x-for="(p, i) in (det.customPatterns||[]).slice(0,4)" :key="i">
                          <span class="inline-block bg-gray-700 text-gray-300 rounded px-1 font-mono truncate max-w-[120px]"
                            x-text="p.isRegex ? '/' + p.value + '/i' : p.value"></span>
                        </template>
                        <span x-show="(det.customPatterns||[]).length > 4" class="text-gray-600"
                          x-text="'+' + (det.customPatterns.length - 4) + ' more'"></span>
                      </div>
                    </div>
                    <button @click="removeCustomDet(profile, det.id)" class="text-red-400 hover:text-red-300 shrink-0 text-sm leading-none">×</button>
                  </div>
                </template>
                <div x-show="getCustomDets(profile).length === 0 && showCustomDetForm !== profile.id"
                  class="text-xs text-gray-500 py-1">No custom rules yet.</div>

                <!-- Add form -->
                <div x-show="showCustomDetForm === profile.id" x-cloak
                  class="mt-2 bg-gray-800 border border-gray-700 rounded p-3 space-y-2">
                  <div class="flex gap-2">
                    <input x-model="customDetForm.name" type="text" placeholder="Rule name *"
                      class="flex-1 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 placeholder-gray-500" />
                    <select x-model="customDetForm.mode" class="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200">
                      <option value="block">Block</option>
                      <option value="monitor">Monitor</option>
                    </select>
                  </div>
                  <div class="space-y-1">
                    <template x-for="(p, i) in customDetForm.patterns" :key="i">
                      <div class="flex items-center gap-1 text-xs">
                        <span class="bg-gray-700 border border-gray-600 rounded px-2 py-0.5 font-mono flex-1 truncate text-gray-300"
                          x-text="p.isRegex ? '/' + p.value + '/i' : p.value"></span>
                        <button @click="removePatternFromDet(i)" class="text-red-400 hover:text-red-300 shrink-0">×</button>
                      </div>
                    </template>
                  </div>
                  <div class="flex gap-1 items-center">
                    <input x-model="customPatternInput" @keydown.enter="addPatternToDet()" type="text"
                      placeholder="Word, phrase or regex…" class="flex-1 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 placeholder-gray-500" />
                    <label class="flex items-center gap-1 text-xs shrink-0 cursor-pointer text-gray-400">
                      <input type="checkbox" x-model="customPatternIsRegex" class="rounded" />
                      Regex
                    </label>
                    <button @click="addPatternToDet()"
                      class="text-xs bg-gray-600 hover:bg-gray-500 text-gray-200 rounded px-2 py-1 shrink-0">+</button>
                  </div>
                  <div class="flex gap-2">
                    <button @click="saveCustomDetection(profile)"
                      class="text-xs bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700">Save Rule</button>
                    <button @click="showCustomDetForm=''" class="text-xs text-gray-400 px-3 py-1">Cancel</button>
                  </div>
                </div>
              </div>
            </div>

            <!-- ── API Keys footer ── -->
            <div class="px-5 py-4 border-t border-gray-800 bg-gray-800">
              <div class="flex items-center justify-between mb-3">
                <span class="text-xs font-semibold text-gray-400 uppercase tracking-wider">API Keys</span>
                <button @click="quickCreateKey(profile)" class="text-xs text-blue-400 hover:underline">+ New Key</button>
              </div>
              <template x-for="key in apiKeys.filter(k => k.profileId === profile.id)" :key="key.id">
                <div class="flex items-center gap-3 py-1.5 border-b border-gray-700 last:border-0 text-sm">
                  <span class="font-medium text-white" x-text="key.name"></span>
                  <span :class="key.active ? 'bg-green-950 text-green-400' : 'bg-gray-700 text-gray-400'"
                    class="px-1.5 py-0.5 rounded text-[10px] font-semibold shrink-0" x-text="key.active ? 'active' : 'revoked'"></span>
                  <span class="text-xs text-gray-500 shrink-0" x-text="key.createdAt?.slice(0,10)"></span>
                  <div class="ml-auto flex gap-3 shrink-0">
                    <button x-show="key.active" @click="rotateKey(key.id)" class="text-xs text-blue-400 hover:underline">Rotate</button>
                    <button x-show="key.active" @click="revokeKey(key.id)" class="text-xs text-red-400 hover:underline">Revoke</button>
                    <button @click="deleteKey(key.id)" class="text-xs text-gray-500 hover:underline">Delete</button>
                  </div>
                </div>
              </template>
              <div x-show="!apiKeys.filter(k => k.profileId === profile.id).length"
                class="text-xs text-gray-500 py-1">No API keys yet.</div>
            </div>
          </div>

        </div>
      </template>
    </div>
  </div>

  <!-- ── API Keys ── -->
  <div x-show="tab==='keys'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold text-white">API Keys</h2>
      <button @click="showKeyForm=!showKeyForm" class="text-sm bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700">+ New Key</button>
    </div>

    <div x-show="showKeyForm" x-cloak class="mb-6 bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 class="font-semibold mb-3 text-white">Create API Key</h3>
      <div class="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label class="block text-xs text-gray-500 mb-1">Name *</label>
          <input x-model="keyForm.name" type="text" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600" placeholder="e.g. prod-backend" />
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">Bind to Profile *</label>
          <select x-model="keyForm.profileId" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200">
            <option value="">Select profile…</option>
            <template x-for="p in profiles" :key="p.id">
              <option :value="p.id" x-text="p.name"></option>
            </template>
          </select>
        </div>
      </div>
      <div class="flex gap-2">
        <button @click="createKey()" class="text-sm bg-blue-600 text-white px-4 py-1.5 rounded hover:bg-blue-700">Generate</button>
        <button @click="showKeyForm=false" class="text-sm text-gray-400 px-4 py-1.5">Cancel</button>
      </div>
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-xs text-gray-400 uppercase">
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
            <tr class="border-t border-gray-800 hover:bg-gray-800">
              <td class="px-4 py-2 font-medium text-white" x-text="key.name"></td>
              <td class="px-4 py-2 text-gray-400 text-xs font-mono" x-text="key.profileId?.slice(0,8)+'…'"></td>
              <td class="px-4 py-2">
                <span :class="key.active ? 'bg-green-950 text-green-400' : 'bg-gray-700 text-gray-400'"
                  class="px-2 py-0.5 rounded text-xs" x-text="key.active ? 'active' : 'revoked'"></span>
              </td>
              <td class="px-4 py-2 text-gray-500 text-xs" x-text="key.createdAt?.slice(0,10)"></td>
              <td class="px-4 py-2 flex gap-2">
                <button x-show="key.active" @click="rotateKey(key.id)" class="text-xs text-blue-400 hover:underline">Rotate</button>
                <button x-show="key.active" @click="revokeKey(key.id)" class="text-xs text-red-400 hover:underline">Revoke</button>
                <button @click="deleteKey(key.id)" class="text-xs text-gray-500 hover:underline">Delete</button>
              </td>
            </tr>
          </template>
          <tr x-show="apiKeys.length===0" class="border-t border-gray-800">
            <td colspan="5" class="px-4 py-6 text-center text-gray-500 text-sm">No keys yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Signatures ── -->
  <div x-show="tab==='signatures'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold text-white">Attack Signatures <span class="text-xs text-gray-500">(Vectorize)</span></h2>
      <button @click="showSigForm=!showSigForm" class="text-sm bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700">+ Add Signature</button>
    </div>
    <div x-show="showSigForm" x-cloak class="mb-4 bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div class="space-y-2 mb-3">
        <input x-model="sigForm.text" type="text" placeholder="Attack text *" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500" />
        <input x-model="sigForm.category" type="text" placeholder="Category (e.g. injection)" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500" />
        <input x-model="sigForm.description" type="text" placeholder="Description" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500" />
      </div>
      <div class="flex gap-2">
        <button @click="addSignature()" class="text-sm bg-blue-600 text-white px-4 py-1.5 rounded hover:bg-blue-700">Add</button>
        <button @click="showSigForm=false" class="text-sm text-gray-400 px-4 py-1.5">Cancel</button>
      </div>
    </div>
    <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-xs text-gray-400 uppercase">
          <tr>
            <th class="px-4 py-2 text-left">Text</th>
            <th class="px-4 py-2 text-left">Category</th>
            <th class="px-4 py-2 text-left">Created</th>
            <th class="px-4 py-2 text-left"></th>
          </tr>
        </thead>
        <tbody>
          <template x-for="sig in signatures" :key="sig.id">
            <tr class="border-t border-gray-800 hover:bg-gray-800">
              <td class="px-4 py-2 text-gray-300 max-w-xs truncate" x-text="sig.text"></td>
              <td class="px-4 py-2 text-gray-500 text-xs" x-text="sig.category"></td>
              <td class="px-4 py-2 text-gray-500 text-xs" x-text="sig.createdAt?.slice(0,10)"></td>
              <td class="px-4 py-2"><button @click="deleteSig(sig.id)" class="text-xs text-red-400 hover:underline">Delete</button></td>
            </tr>
          </template>
          <tr x-show="signatures.length===0" class="border-t border-gray-800">
            <td colspan="4" class="px-4 py-6 text-center text-gray-500 text-sm">No signatures yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Audit ── -->
  <div x-show="tab==='audit'" x-cloak>
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold text-white">Audit Log</h2>
      <button @click="loadAudit()" class="text-sm text-blue-400 hover:underline">Refresh</button>
    </div>
    <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-xs text-gray-400 uppercase">
          <tr>
            <th class="px-4 py-2 text-left">Time</th>
            <th class="px-4 py-2 text-left">Action</th>
            <th class="px-4 py-2 text-left">Type</th>
            <th class="px-4 py-2 text-left">Resource ID</th>
          </tr>
        </thead>
        <tbody>
          <template x-for="(evt, i) in auditEvents" :key="i">
            <tr class="border-t border-gray-800 hover:bg-gray-800">
              <td class="px-4 py-2 text-gray-500 text-xs" x-text="evt.timestamp?.slice(0,19)?.replace('T',' ')"></td>
              <td class="px-4 py-2 font-medium text-gray-200" x-text="evt.action"></td>
              <td class="px-4 py-2 text-gray-400" x-text="evt.resourceType"></td>
              <td class="px-4 py-2 font-mono text-xs text-gray-500" x-text="evt.resourceId"></td>
            </tr>
          </template>
          <tr x-show="auditEvents.length===0" class="border-t border-gray-800">
            <td colspan="4" class="px-4 py-6 text-center text-gray-500 text-sm">No events yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

</main>
</div><!-- end x-show="loggedIn" -->

<script>
function app() {
  return {
    // ── Auth state ─────────────────────────────────────────────────────────────
    loggedIn: false,
    user: null,
    loginUsername: '',
    loginPassword: '',
    loginError: '',
    loginBusy: false,

    // ── App state ──────────────────────────────────────────────────────────────
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
    showCustomDetForm: '',
    customDetForm: { name: '', mode: 'block', patterns: [] },
    customPatternInput: '',
    customPatternIsRegex: false,

    // ── Init ──────────────────────────────────────────────────────────────────
    async init() {
      // Load templates regardless of auth (public endpoint)
      const tr = await fetch('/api/templates');
      if (tr.ok) this.templates = await tr.json();
      // Then check existing session
      await this.checkSession();
    },

    // ── Auth methods ──────────────────────────────────────────────────────────
    async checkSession() {
      const r = await fetch('/api/auth/me');
      if (r.ok) {
        this.user = await r.json();
        this.loggedIn = true;
        await this.loadAll();
      }
    },

    async login() {
      this.loginError = '';
      this.loginBusy = true;
      try {
        const r = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: this.loginUsername, password: this.loginPassword }),
        });
        const data = await r.json();
        if (!r.ok) {
          this.loginError = data.error || 'Login failed';
          return;
        }
        this.loginPassword = '';
        this.loginError = '';
        this.user = data;
        this.loggedIn = true;
        await this.loadAll();
      } catch (e) {
        this.loginError = String(e);
      } finally {
        this.loginBusy = false;
      }
    },

    async logout() {
      await fetch('/api/auth/logout', { method: 'POST' });
      this.loggedIn = false;
      this.user = null;
      this.profiles = [];
      this.apiKeys = [];
      this.signatures = [];
      this.auditEvents = [];
    },

    // ── Fetch helper: intercepts 401/403 ──────────────────────────────────────
    async req(url, opts = {}) {
      const r = await fetch(url, opts);
      if (r.status === 401 || r.status === 403) {
        this.loggedIn = false;
        this.user = null;
        return null;
      }
      return r;
    },

    headers() {
      return { 'Content-Type': 'application/json' };
    },

    notify(msg, err = false) { this.message = msg; this.msgErr = err; },

    // ── Data loaders ──────────────────────────────────────────────────────────
    async loadAll() {
      await Promise.all([this.loadProfiles(), this.loadKeys(), this.loadSigs(), this.loadAudit()]);
    },

    async loadProfiles() {
      const r = await this.req('/api/profiles');
      if (r && r.ok) this.profiles = await r.json();
      else if (r) this.notify('Failed to load profiles', true);
    },

    async loadKeys() {
      const r = await this.req('/api/keys');
      if (r && r.ok) this.apiKeys = await r.json();
    },

    async loadSigs() {
      const r = await this.req('/api/signatures');
      if (r && r.ok) this.signatures = await r.json();
    },

    async loadAudit() {
      const r = await this.req('/api/audit');
      if (r && r.ok) this.auditEvents = await r.json();
    },

    // ── Profile actions ───────────────────────────────────────────────────────
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

      const isNew = !this.editingProfile;
      let r;
      if (this.editingProfile) {
        r = await this.req('/api/profiles/' + this.editingProfile.id, { method: 'PUT', headers: this.headers(), body: JSON.stringify(body) });
      } else {
        r = await this.req('/api/profiles', { method: 'POST', headers: this.headers(), body: JSON.stringify(body) });
      }
      if (r && r.ok) {
        const profile = await r.json();
        this.showProfileForm = false;
        this.editingProfile = null;
        if (isNew) {
          const keyRes = await this.req('/api/keys', {
            method: 'POST', headers: this.headers(),
            body: JSON.stringify({ name: profile.name + ' Default', profileId: profile.id }),
          });
          if (keyRes && keyRes.ok) {
            const keyData = await keyRes.json();
            this.newRawKey = keyData.rawKey;
            this.notify('Profile created — API key generated. Save it now!');
          } else {
            this.notify('Profile created (key generation failed)', true);
          }
        } else {
          this.notify('Profile updated');
        }
        await Promise.all([this.loadProfiles(), this.loadKeys()]);
      } else if (r) {
        this.notify('Save failed: ' + (await r.text()), true);
      }
    },

    async createFromTemplate(slug) {
      const tplRes = await fetch('/api/templates/' + slug);
      if (!tplRes.ok) return this.notify('Template not found', true);
      const tpl = await tplRes.json();
      const body = {
        name: tpl.name + ' (Default)',
        description: tpl.description,
        policies: [tpl],
        rateLimit: null, failOpen: true, cacheTtlSeconds: 3600,
      };
      const r = await this.req('/api/profiles', { method: 'POST', headers: this.headers(), body: JSON.stringify(body) });
      if (r && r.ok) {
        const profile = await r.json();
        this.showAddFromTemplate = false;
        const keyRes = await this.req('/api/keys', {
          method: 'POST', headers: this.headers(),
          body: JSON.stringify({ name: profile.name + ' Default', profileId: profile.id }),
        });
        if (keyRes && keyRes.ok) {
          const keyData = await keyRes.json();
          this.newRawKey = keyData.rawKey;
          this.notify('Profile created from template — API key generated. Save it now!');
        } else {
          this.notify('Profile created from template "' + tpl.name + '"');
        }
        await Promise.all([this.loadProfiles(), this.loadKeys()]);
      } else if (r) {
        this.notify('Create failed: ' + (await r.text()), true);
      }
    },

    async confirmDeleteProfile(id) {
      if (!confirm('Delete this profile? API keys bound to it will stop working.')) return;
      const r = await this.req('/api/profiles/' + id, { method: 'DELETE', headers: this.headers() });
      if (r && r.ok) { this.notify('Profile deleted'); await this.loadProfiles(); }
      else if (r) this.notify('Delete failed', true);
    },

    // ── Key actions ───────────────────────────────────────────────────────────
    async createKey() {
      if (!this.keyForm.name || !this.keyForm.profileId) return this.notify('Name and profile are required', true);
      const r = await this.req('/api/keys', { method: 'POST', headers: this.headers(), body: JSON.stringify(this.keyForm) });
      if (r && r.ok) {
        const data = await r.json();
        this.newRawKey = data.rawKey;
        this.showKeyForm = false;
        this.notify('API key created — save it now');
        await this.loadKeys();
      } else if (r) this.notify('Create failed: ' + (await r.text()), true);
    },

    async revokeKey(id) {
      if (!confirm('Revoke this key?')) return;
      const r = await this.req('/api/keys/' + id + '/revoke', { method: 'POST', headers: this.headers() });
      if (r && r.ok) { this.notify('Key revoked'); await this.loadKeys(); }
      else if (r) this.notify('Revoke failed', true);
    },

    async rotateKey(id) {
      if (!confirm('Rotate this key? The old key will stop working immediately.')) return;
      const r = await this.req('/api/keys/' + id + '/rotate', { method: 'POST', headers: this.headers() });
      if (r && r.ok) {
        const data = await r.json();
        this.newRawKey = data.rawKey;
        this.notify('Key rotated — save the new key now');
        await this.loadKeys();
      } else if (r) this.notify('Rotate failed', true);
    },

    async deleteKey(id) {
      if (!confirm('Permanently delete this key?')) return;
      const r = await this.req('/api/keys/' + id, { method: 'DELETE', headers: this.headers() });
      if (r && r.ok) { this.notify('Key deleted'); await this.loadKeys(); }
      else if (r) this.notify('Delete failed', true);
    },

    // ── Signature actions ─────────────────────────────────────────────────────
    async addSignature() {
      if (!this.sigForm.text) return this.notify('Text is required', true);
      const r = await this.req('/api/signatures', { method: 'POST', headers: this.headers(), body: JSON.stringify(this.sigForm) });
      if (r && r.ok) {
        this.notify('Signature added');
        this.showSigForm = false;
        await this.loadSigs();
      } else if (r) {
        const err = await r.json().catch(() => ({ error: r.statusText }));
        this.notify(err.error ?? 'Failed', true);
      }
    },

    async deleteSig(id) {
      if (!confirm('Delete this signature from Vectorize?')) return;
      const r = await this.req('/api/signatures/' + id, { method: 'DELETE', headers: this.headers() });
      if (r && r.ok) { this.notify('Signature deleted'); await this.loadSigs(); }
      else if (r) this.notify('Delete failed', true);
    },

    // ── Inline helpers ────────────────────────────────────────────────────────
    async quickCreateKey(profile) {
      const name = prompt('Key name:', profile.name + ' Key');
      if (!name) return;
      const r = await this.req('/api/keys', {
        method: 'POST', headers: this.headers(),
        body: JSON.stringify({ name, profileId: profile.id }),
      });
      if (r && r.ok) {
        const data = await r.json();
        this.newRawKey = data.rawKey;
        this.notify('API key created — save it now!');
        await this.loadKeys();
      } else if (r) {
        this.notify('Create failed: ' + (await r.text()), true);
      }
    },

    async addPolicyToProfile(profile, templateSlug) {
      const tplRes = await fetch('/api/templates/' + templateSlug);
      if (!tplRes.ok) return this.notify('Template not found', true);
      const tpl = await tplRes.json();
      const existing = profile.policies ?? [];
      if (existing.some(p => p.id === tpl.id)) {
        return this.notify('"' + tpl.name + '" is already in this profile', true);
      }
      const r = await this.req('/api/profiles/' + profile.id, {
        method: 'PUT',
        headers: this.headers(),
        body: JSON.stringify({ policies: [...existing, tpl] }),
      });
      if (r && r.ok) {
        this.notify('"' + tpl.name + '" added to ' + profile.name);
        await this.loadProfiles();
      } else if (r) {
        this.notify('Failed: ' + (await r.text()), true);
      }
    },

    async removePolicyFromProfile(profile, policyId) {
      if (!confirm('Remove this policy from the profile?')) return;
      const r = await this.req('/api/profiles/' + profile.id, {
        method: 'PUT',
        headers: this.headers(),
        body: JSON.stringify({ policies: (profile.policies ?? []).filter(p => p.id !== policyId) }),
      });
      if (r && r.ok) {
        this.notify('Policy removed');
        await this.loadProfiles();
      } else if (r) {
        this.notify('Failed: ' + (await r.text()), true);
      }
    },

    // ── Custom detection rules ────────────────────────────────────────────────
    getCustomDets(profile) {
      const pol = (profile.policies ?? []).find(p => p.id === 'policy-custom-rules');
      if (!pol) return [];
      const cat = (pol.categories ?? []).find(c => c.id === 'cat-custom-rules');
      return cat ? (cat.detections ?? []) : [];
    },

    openAddCustomRule(profile) {
      this.showCustomDetForm = this.showCustomDetForm === profile.id ? '' : profile.id;
      this.customDetForm = { name: '', mode: 'block', patterns: [] };
      this.customPatternInput = '';
      this.customPatternIsRegex = false;
    },

    addPatternToDet() {
      const v = this.customPatternInput.trim();
      if (!v) return;
      this.customDetForm.patterns.push({ value: v, isRegex: this.customPatternIsRegex, description: '' });
      this.customPatternInput = '';
      this.customPatternIsRegex = false;
    },

    removePatternFromDet(i) {
      this.customDetForm.patterns.splice(i, 1);
    },

    async saveCustomDetection(profile) {
      if (!this.customDetForm.name.trim()) return this.notify('Rule name is required', true);
      if (!this.customDetForm.patterns.length) return this.notify('Add at least one pattern', true);

      const updated = JSON.parse(JSON.stringify(profile));
      let pol = updated.policies.find(p => p.id === 'policy-custom-rules');
      if (!pol) {
        pol = { id: 'policy-custom-rules', name: 'Custom Rules', description: 'User-defined word list and regex rules', categories: [] };
        updated.policies.push(pol);
      }
      let cat = pol.categories.find(c => c.id === 'cat-custom-rules');
      if (!cat) {
        cat = { id: 'cat-custom-rules', name: 'Custom Rules', description: '', detections: [] };
        pol.categories.push(cat);
      }
      cat.detections.push({
        id: 'det-custom-' + Date.now(),
        name: this.customDetForm.name.trim(),
        description: '',
        mode: this.customDetForm.mode,
        settings: [],
        detectionExample: '',
        safeExample: '',
        type: 'custom',
        customPatterns: this.customDetForm.patterns,
      });

      const r = await this.req('/api/profiles/' + profile.id, {
        method: 'PUT',
        headers: this.headers(),
        body: JSON.stringify({ policies: updated.policies }),
      });
      if (r && r.ok) {
        this.showCustomDetForm = '';
        this.notify('Custom rule added');
        await this.loadProfiles();
      } else if (r) {
        this.notify('Save failed: ' + (await r.text()), true);
      }
    },

    async removeCustomDet(profile, detId) {
      if (!confirm('Remove this custom rule?')) return;
      const updated = JSON.parse(JSON.stringify(profile));
      const pol = updated.policies.find(p => p.id === 'policy-custom-rules');
      if (!pol) return;
      const cat = pol.categories.find(c => c.id === 'cat-custom-rules');
      if (!cat) return;
      cat.detections = cat.detections.filter(d => d.id !== detId);

      const r = await this.req('/api/profiles/' + profile.id, {
        method: 'PUT',
        headers: this.headers(),
        body: JSON.stringify({ policies: updated.policies }),
      });
      if (r && r.ok) {
        this.notify('Custom rule removed');
        await this.loadProfiles();
      } else if (r) {
        this.notify('Failed: ' + (await r.text()), true);
      }
    },
  };
}
</script>
</body>
</html>`;

export default html;
