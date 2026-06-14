/* eslint-disable */
// HTML is a single string; inner JS uses concatenation to avoid nested template-literal conflicts.

const PAGE_JS = `
var currentUser = null;
var chartVerdict = null;
var chartSets    = null;

// ── Auth flow ──────────────────────────────────────────────────────────────────
function showLogin() {
  document.getElementById('login-overlay').style.display = '';
  document.getElementById('app').classList.add('hidden');
}

function showApp(user) {
  currentUser = user;
  document.getElementById('login-overlay').style.display = 'none';
  document.getElementById('app').classList.remove('hidden');
  document.getElementById('header-user').textContent = user.username;
  var roleEl = document.getElementById('header-role');
  roleEl.textContent = user.role.toUpperCase();
  roleEl.className = user.role === 'admin'
    ? 'text-xs font-semibold px-2 py-0.5 rounded' +
      ' bg-blue-900 text-blue-300 border border-blue-700'
    : 'text-xs font-semibold px-2 py-0.5 rounded' +
      ' bg-gray-800 text-gray-400 border border-gray-700';
  if (user.role === 'admin') {
    document.getElementById('tab-users').classList.remove('hidden');
  }
  loadPromptSets();
}

function login() {
  var username = document.getElementById('login-username').value.trim();
  var password = document.getElementById('login-password').value;
  var errEl    = document.getElementById('login-error');
  var btn      = document.getElementById('login-btn');
  errEl.classList.add('hidden');
  if (!username || !password) {
    errEl.textContent = 'Username and password are required.';
    errEl.classList.remove('hidden');
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, password: password }),
  })
    .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
    .then(function(res) {
      if (!res.ok) {
        errEl.textContent = res.data.error || 'Login failed';
        errEl.classList.remove('hidden');
        return;
      }
      document.getElementById('login-password').value = '';
      showApp(res.data);
    })
    .catch(function(err) { errEl.textContent = String(err); errEl.classList.remove('hidden'); })
    .finally(function() { btn.disabled = false; btn.textContent = 'Sign In'; });
}

function logout() {
  fetch('/api/auth/logout', { method: 'POST' })
    .finally(function() { currentUser = null; showLogin(); });
}

function api(path, opts) {
  opts = opts || {};
  return fetch(path, Object.assign({}, opts, {
    headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {}),
  })).then(function(r) {
    if (r.status === 401) {
      currentUser = null;
      showLogin();
      throw new Error('Session expired — please sign in again.');
    }
    if (!r.ok) return r.text().then(function(t) { throw new Error(t); });
    return r.json();
  });
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function badge(v) {
  var cls = { block:'badge-block', monitor:'badge-monitor', pass:'badge-pass' }[v] || 'badge-error';
  return '<span class="badge ' + cls + '">' + esc((v || 'error').toUpperCase()) + '</span>';
}

function checkIcon(verdict, expected) {
  if (!expected) return '<span class="text-gray-600">—</span>';
  return verdict === expected
    ? '<span class="pass-icon text-green-400">✓</span>'
    : '<span class="pass-icon text-red-400">✗</span>';
}

function relTime(ts) {
  var d = Date.now() - new Date(ts).getTime();
  if (d < 60000)    return Math.floor(d / 1000)    + 's ago';
  if (d < 3600000)  return Math.floor(d / 60000)   + 'm ago';
  if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
  return new Date(ts).toLocaleDateString();
}

var SET_NAMES = {
  'sensitive-data':    'Sensitive Data',
  'security-controls': 'Security Controls',
  'content-moderation':'Content Mod',
  'model-judgment':    'Model Judgment',
};
var SET_IDS    = ['sensitive-data','security-controls','content-moderation','model-judgment'];
var SET_LABELS = ['Sensitive Data','Security Controls','Content Mod','Model Judgment'];

function latencyFmt(ms) {
  return ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : ms + 'ms';
}

function fmtJson(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch(e) { return s || ''; }
}

// ── Tabs ───────────────────────────────────────────────────────────────────────
function showTab(name) {
  ['runner','events','stats','inspect','users'].forEach(function(t) {
    var pane = document.getElementById('pane-' + t);
    var btn  = document.getElementById('tab-' + t);
    if (pane) pane.classList.toggle('hidden', t !== name);
    if (btn)  btn.classList.toggle('active', t === name);
  });
  if (name === 'events')  loadEvents();
  if (name === 'stats')   loadStats();
  if (name === 'users')   { loadUsers(); loadAdminInspectKeys(); }
  if (name === 'inspect') loadInspectProfiles();
}

// ── Runner ─────────────────────────────────────────────────────────────────────
function loadPromptSets() {
  fetch('/api/prompt-sets').then(function(r) { return r.json(); }).then(function(sets) {
    var html = '';
    sets.forEach(function(s) {
      html +=
        '<div class="card flex flex-col" data-set-id="' + esc(s.id) + '" data-set-name="' + esc(s.name) + '">' +
          '<div class="text-base font-semibold text-white mb-1">' + esc(s.name) + '</div>' +
          '<div class="text-gray-400 text-xs mb-3 leading-relaxed">' + esc(s.description) + '</div>' +
          '<div class="mt-auto flex items-center justify-between">' +
            '<span class="text-gray-600 text-xs">' + s.items.length + ' prompts</span>' +
            '<button class="btn-primary run-set-btn">Run Set</button>' +
          '</div>' +
        '</div>';
    });
    document.getElementById('sets-grid').innerHTML = html;
    document.querySelectorAll('.run-set-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var card = btn.closest('[data-set-id]');
        if (card) runSet(card.getAttribute('data-set-id'), card.getAttribute('data-set-name'));
      });
    });
  });
}

function runSet(setId, setName) {
  document.querySelectorAll('.run-set-btn').forEach(function(b) { b.disabled = true; });

  var sumEl  = document.getElementById('run-summary');
  var resEl  = document.getElementById('run-results');
  var bodyEl = document.getElementById('results-body');
  sumEl.classList.remove('hidden');
  resEl.classList.remove('hidden');
  document.getElementById('sum-name').textContent    = setName;
  document.getElementById('sum-pass-n').textContent  = '…';
  document.getElementById('sum-fail-n').textContent  = '…';
  document.getElementById('sum-latency').textContent = '';
  document.getElementById('sum-spinner').classList.remove('hidden');
  bodyEl.innerHTML = '<tr><td colspan="6" class="py-8 text-center text-gray-600">' +
    '<div class="spinner" style="margin:auto"></div></td></tr>';

  api('/api/run-set', { method: 'POST', body: JSON.stringify({ setId: setId }) })
    .then(function(data) {
      var passed = data.results.filter(function(r) { return r.pass; }).length;
      var failed = data.results.length - passed;
      var avgMs  = Math.round(
        data.results.reduce(function(s, r) { return s + (r.latencyMs || 0); }, 0) / data.results.length
      );

      document.getElementById('sum-pass-n').textContent  = passed;
      document.getElementById('sum-fail-n').textContent  = failed;
      document.getElementById('sum-latency').textContent = 'avg ' + latencyFmt(avgMs);
      document.getElementById('sum-spinner').classList.add('hidden');

      var rows = '';
      data.results.forEach(function(r) {
        var viols = r.error
          ? '<span class="text-red-400 text-xs mono">' + esc(r.error) + '</span>'
          : (r.violations || []).map(function(v) {
              return '<span class="inline-block bg-gray-800 text-gray-400 rounded px-1 mr-1 text-xs mono">' +
                esc(v.detectionName || v.setting || '') + '</span>';
            }).join('') || '<span class="text-gray-700">—</span>';

        rows +=
          '<tr>' +
          '<td><div class="text-sm text-gray-200 font-medium">' + esc(r.label) + '</div>' +
          '<div class="prompt-text" title="' + esc(r.prompt) + '">' + esc(r.prompt) + '</div></td>' +
          '<td>' + badge(r.expected) + '</td>' +
          '<td>' + badge(r.verdict) + '</td>' +
          '<td class="text-center">' + checkIcon(r.verdict, r.expected) + '</td>' +
          '<td>' + viols + '</td>' +
          '<td class="text-right text-gray-400 text-xs">' + latencyFmt(r.latencyMs || 0) + '</td>' +
          '</tr>';
      });
      bodyEl.innerHTML = rows;
    })
    .catch(function(err) {
      document.getElementById('sum-name').textContent = 'Error';
      document.getElementById('sum-spinner').classList.add('hidden');
      bodyEl.innerHTML = '<tr><td colspan="6" class="py-4 text-red-400 text-sm">' + esc(String(err)) + '</td></tr>';
    })
    .finally(function() {
      document.querySelectorAll('.run-set-btn').forEach(function(b) { b.disabled = false; });
    });
}

// ── Events ─────────────────────────────────────────────────────────────────────
function loadEvents() {
  var set     = document.getElementById('f-set').value;
  var verdict = document.getElementById('f-verdict').value;

  document.getElementById('evt-loading').classList.remove('hidden');
  document.getElementById('evt-body').innerHTML = '';
  document.getElementById('evt-count').textContent = '';

  var qs = new URLSearchParams({ limit: '100', offset: '0' });
  if (set)     qs.set('set', set);
  if (verdict) qs.set('verdict', verdict);

  api('/api/events?' + qs.toString())
    .then(function(rows) {
      document.getElementById('evt-loading').classList.add('hidden');
      document.getElementById('evt-count').textContent = rows.length + ' events';

      if (rows.length === 0) {
        document.getElementById('evt-body').innerHTML =
          '<tr><td colspan="8" class="py-8 text-center text-gray-600">No events match this filter.</td></tr>';
        return;
      }

      var html = '';
      rows.forEach(function(e, idx) {
        var viols = [];
        try { viols = JSON.parse(e.violations || '[]'); } catch(x) {}
        var violLbl = viols.length === 0
          ? '<span class="text-gray-700">—</span>'
          : '<span class="text-xs text-gray-400">' + viols.length + ' detection' + (viols.length > 1 ? 's' : '') + '</span>';
        var detailId = 'detail-' + idx;
        html +=
          '<tr class="evt-main-row">' +
          '<td class="text-gray-500 text-xs">' + relTime(e.ts) + '</td>' +
          '<td class="text-xs text-gray-400">' + esc(SET_NAMES[e.prompt_set] || e.prompt_set) + '</td>' +
          '<td class="text-sm">' + esc(e.prompt_label) + '</td>' +
          '<td><span class="prompt-text" title="' + esc(e.prompt) + '">' + esc(e.prompt) + '</span></td>' +
          '<td>' + (e.expected ? badge(e.expected) : '<span class="text-gray-700">—</span>') + '</td>' +
          '<td>' + badge(e.verdict) + '</td>' +
          '<td>' + violLbl + '</td>' +
          '<td class="text-right">' +
            '<span class="text-gray-400 text-xs mr-2">' + latencyFmt(e.latency_ms) + '</span>' +
            '<button class="raw-toggle text-xs text-blue-400 hover:text-blue-300" data-target="' + detailId + '">Raw</button>' +
          '</td>' +
          '</tr>' +
          '<tr id="' + detailId + '" class="hidden">' +
          '<td colspan="8" class="pb-4 pt-1">' +
            '<div class="grid grid-cols-2 gap-3">' +
              '<div>' +
                '<div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Request</div>' +
                '<pre class="bg-gray-900 border border-gray-800 rounded p-3 text-xs text-green-300 overflow-auto max-h-48">' + esc(fmtJson(e.raw_request)) + '</pre>' +
              '</div>' +
              '<div>' +
                '<div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Response</div>' +
                '<pre class="bg-gray-900 border border-gray-800 rounded p-3 text-xs text-blue-300 overflow-auto max-h-48">' + esc(fmtJson(e.raw_response)) + '</pre>' +
              '</div>' +
            '</div>' +
          '</td>' +
          '</tr>';
      });
      document.getElementById('evt-body').innerHTML = html;

      document.querySelectorAll('.raw-toggle').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var target = document.getElementById(btn.getAttribute('data-target'));
          if (target) {
            target.classList.toggle('hidden');
            btn.textContent = target.classList.contains('hidden') ? 'Raw' : 'Hide';
          }
        });
      });
    })
    .catch(function(err) {
      document.getElementById('evt-loading').classList.add('hidden');
      document.getElementById('evt-body').innerHTML =
        '<tr><td colspan="8" class="py-4 text-red-400 text-sm text-center">' + esc(String(err)) + '</td></tr>';
    });
}

function confirmClear() {
  if (!confirm('Delete all events? This cannot be undone.')) return;
  api('/api/events', { method: 'DELETE' }).then(function() { loadEvents(); });
}

// ── Stats ──────────────────────────────────────────────────────────────────────
function countFor(setCounts, set, verdict) {
  var row = setCounts.find(function(r) { return r.prompt_set === set && r.verdict === verdict; });
  return row ? row.count : 0;
}

function loadStats() {
  api('/api/stats').then(function(s) {
    var total = s.verdictCounts.reduce(function(sum, r) { return sum + r.count; }, 0);
    document.getElementById('s-total').textContent    = total;
    document.getElementById('s-accuracy').textContent = (s.accuracy || 0).toFixed(1) + '%';
    document.getElementById('s-latency').textContent  = latencyFmt(Math.round(s.avgLatencyMs || 0));

    var vmap = {};
    s.verdictCounts.forEach(function(r) { vmap[r.verdict] = r.count; });

    if (chartVerdict) chartVerdict.destroy();
    chartVerdict = new Chart(document.getElementById('c-verdict'), {
      type: 'doughnut',
      data: {
        labels: ['Block','Monitor','Pass'],
        datasets: [{
          data: [vmap.block || 0, vmap.monitor || 0, vmap.pass || 0],
          backgroundColor: ['#7f1d1d','#78350f','#14532d'],
          borderColor:     ['#991b1b','#92400e','#166534'],
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '62%',
        plugins: { legend: { labels: { color: '#9ca3af', font: { size: 12 }, padding: 16 } } },
      },
    });

    if (chartSets) chartSets.destroy();
    chartSets = new Chart(document.getElementById('c-sets'), {
      type: 'bar',
      data: {
        labels: SET_LABELS,
        datasets: [
          { label:'Block',   data: SET_IDS.map(function(id){ return countFor(s.setCounts,id,'block');   }), backgroundColor:'#7f1d1d', borderColor:'#991b1b', borderWidth:1 },
          { label:'Monitor', data: SET_IDS.map(function(id){ return countFor(s.setCounts,id,'monitor'); }), backgroundColor:'#78350f', borderColor:'#92400e', borderWidth:1 },
          { label:'Pass',    data: SET_IDS.map(function(id){ return countFor(s.setCounts,id,'pass');    }), backgroundColor:'#14532d', borderColor:'#166534', borderWidth:1 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { stacked:true, ticks:{color:'#6b7280'}, grid:{color:'#111827'} },
          y: { stacked:true, ticks:{color:'#6b7280'}, grid:{color:'#1f2937'} },
        },
        plugins: { legend: { labels: { color:'#9ca3af', font:{size:11}, padding:12 } } },
      },
    });

    var rows = '';
    SET_IDS.forEach(function(id, i) {
      var block   = countFor(s.setCounts, id, 'block');
      var monitor = countFor(s.setCounts, id, 'monitor');
      var pass    = countFor(s.setCounts, id, 'pass');
      var error   = countFor(s.setCounts, id, 'error');
      var tot     = block + monitor + pass + error;
      var avgMs   = Math.round((s.setLatency.find(function(r) { return r.prompt_set === id; }) || { avg_ms:0 }).avg_ms);
      rows +=
        '<tr>' +
        '<td class="text-gray-200 font-medium">' + SET_LABELS[i] + '</td>' +
        '<td class="text-right ' + (block   ? 'text-red-400'    : 'text-gray-600') + '">' + block   + '</td>' +
        '<td class="text-right ' + (monitor ? 'text-yellow-400' : 'text-gray-600') + '">' + monitor + '</td>' +
        '<td class="text-right ' + (pass    ? 'text-green-400'  : 'text-gray-600') + '">' + pass    + '</td>' +
        '<td class="text-right ' + (error   ? 'text-gray-400'   : 'text-gray-700') + '">' + error   + '</td>' +
        '<td class="text-right text-gray-400">' + tot + '</td>' +
        '<td class="text-right text-gray-400">' + (avgMs ? latencyFmt(avgMs) : '—') + '</td>' +
        '</tr>';
    });
    document.getElementById('s-breakdown').innerHTML = rows;
  }).catch(function(err) { console.error('Stats error:', err); });
}

// ── Ad-hoc inspector ───────────────────────────────────────────────────────────
var adhocBusy = false;

function loadInspectProfiles() {
  var sel = document.getElementById('adhoc-profile');
  sel.innerHTML = '<option value="">Loading…</option>';
  api('/api/inspect-profiles')
    .then(function(profiles) {
      if (!profiles.length) {
        sel.innerHTML = '<option value="">No profiles configured</option>';
        return;
      }
      var opts = '<option value="">Select a security profile…</option>';
      profiles.forEach(function(p) {
        opts += '<option value="' + esc(p.profile_id) + '">' + esc(p.profile_name) + '</option>';
      });
      sel.innerHTML = opts;
    })
    .catch(function() { sel.innerHTML = '<option value="">Error loading profiles</option>'; });
}

function sendAdhoc() {
  if (adhocBusy) return;
  var prompt    = document.getElementById('adhoc-prompt').value.trim();
  var profileId = document.getElementById('adhoc-profile').value;
  if (!prompt)    { alert('Enter a prompt to inspect.'); return; }
  if (!profileId) { alert('Select a security profile.'); return; }

  adhocBusy = true;
  document.getElementById('adhoc-send').disabled = true;
  document.getElementById('adhoc-spinner').classList.remove('hidden');
  document.getElementById('adhoc-result').classList.add('hidden');
  document.getElementById('adhoc-error').classList.add('hidden');

  api('/api/adhoc', {
    method: 'POST',
    body: JSON.stringify({ prompt: prompt, profileId: profileId }),
  })
    .then(function(data) {
      renderAdhocResult(data);
      document.getElementById('adhoc-result').classList.remove('hidden');
    })
    .catch(function(err) {
      var errEl = document.getElementById('adhoc-error');
      errEl.textContent = String(err);
      errEl.classList.remove('hidden');
    })
    .finally(function() {
      adhocBusy = false;
      document.getElementById('adhoc-send').disabled = false;
      document.getElementById('adhoc-spinner').classList.add('hidden');
    });
}

function renderAdhocResult(data) {
  document.getElementById('adhoc-error').classList.add('hidden');

  var isFirewallError = data.status && data.status !== 200 && data.status !== 403;
  var verdictEl = document.getElementById('adhoc-verdict');
  if (isFirewallError) {
    var code = data.code || data.error || ('HTTP ' + data.status);
    verdictEl.innerHTML = '<span class="badge badge-error">' + esc(String(code)) + '</span>';
  } else {
    verdictEl.innerHTML = badge(data.verdict || 'error');
  }

  document.getElementById('adhoc-reqid').textContent =
    (data.profileName ? data.profileName + ' · ' : '') + (data.requestId || '');

  var cachedEl = document.getElementById('adhoc-cached');
  if (data.cached === true) {
    cachedEl.innerHTML = '<span style="font-size:11px;background:#422006;color:#fcd34d;border:1px solid #92400e;border-radius:4px;padding:1px 8px">cached</span>';
  } else if (data.cached === false) {
    cachedEl.innerHTML = '<span class="text-xs text-gray-600">live</span>';
  } else {
    cachedEl.innerHTML = '';
  }

  document.getElementById('adhoc-wall').textContent = latencyFmt(data.wallMs || 0) + ' wall';

  var viols = data.violations || [];
  var violEl = document.getElementById('adhoc-violations');
  if (viols.length === 0) {
    violEl.innerHTML = '<span class="text-gray-600 text-sm">None</span>';
  } else {
    var rows = '<table class="tbl w-full"><thead><tr>' +
      '<th class="text-left">Detection</th>' +
      '<th class="text-left">Setting</th>' +
      '<th class="text-left" style="width:80px">Mode</th>' +
      '<th class="text-left">MITRE ATLAS</th>' +
      '</tr></thead><tbody>';
    viols.forEach(function(v) {
      var mitre = v.mitreAtlas ? (v.mitreAtlas.techniqueId + ' — ' + v.mitreAtlas.techniqueName) : '—';
      rows += '<tr>' +
        '<td class="font-medium text-white">' + esc(v.detectionName || '') + '</td>' +
        '<td class="text-gray-400">' + esc(v.setting || '') + '</td>' +
        '<td>' + badge(v.mode || '') + '</td>' +
        '<td class="text-xs text-blue-400 mono">' + esc(mitre) + '</td>' +
        '</tr>';
    });
    rows += '</tbody></table>';
    violEl.innerHTML = rows;
  }

  var lat = data.latencyMs;
  var latEl = document.getElementById('adhoc-latency');
  if (lat && typeof lat === 'object') {
    var pills = [];
    if (typeof lat.total === 'number') {
      pills.push('<span class="inline-flex items-center gap-1.5 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs">' +
        '<span class="text-gray-500 uppercase" style="font-size:10px;letter-spacing:.08em">total</span>' +
        '<span class="text-white font-semibold">' + latencyFmt(lat.total) + '</span></span>');
    }
    var perLayer = lat.perLayer || {};
    var layerColors = { layer0:'text-green-400', layer1:'text-blue-400', layer2:'text-yellow-400', layer3:'text-red-400' };
    Object.keys(perLayer).sort().forEach(function(k) {
      var col = layerColors[k] || 'text-gray-400';
      pills.push('<span class="inline-flex items-center gap-1.5 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs">' +
        '<span class="text-gray-500 uppercase" style="font-size:10px;letter-spacing:.08em">' + esc(k) + '</span>' +
        '<span class="' + col + ' font-semibold">' + latencyFmt(perLayer[k] || 0) + '</span></span>');
    });
    latEl.innerHTML = pills.length ? '<div class="flex flex-wrap gap-2">' + pills.join('') + '</div>' : '<span class="text-gray-600">—</span>';
  } else {
    latEl.innerHTML = '<span class="text-gray-600">—</span>';
  }

  var reqLines = [(data.requestMethod || 'POST') + ' /v1/inspect HTTP/1.1'];
  var reqHdrs = data.requestHeaders || {};
  Object.keys(reqHdrs).forEach(function(k) { reqLines.push(k + ': ' + reqHdrs[k]); });
  reqLines.push('');
  try { reqLines.push(JSON.stringify(JSON.parse(data.requestBody || '{}'), null, 2)); }
  catch(e) { reqLines.push(data.requestBody || ''); }
  document.getElementById('adhoc-raw-req').textContent = reqLines.join('\\n');

  var resLines = ['HTTP/1.1 ' + (data.status || '?') + (data.statusText ? ' ' + data.statusText : '')];
  var resHdrs = data.responseHeaders || {};
  Object.keys(resHdrs).forEach(function(k) { resLines.push(k + ': ' + resHdrs[k]); });
  resLines.push('');
  try { resLines.push(JSON.stringify(JSON.parse(data.responseBody || '{}'), null, 2)); }
  catch(e) { resLines.push(data.responseBody || ''); }
  document.getElementById('adhoc-raw-res').textContent = resLines.join('\\n');

  document.getElementById('adhoc-raw-req-panel').classList.remove('hidden');
  document.getElementById('adhoc-raw-res-panel').classList.remove('hidden');
  document.getElementById('adhoc-raw-req-btn').textContent = 'Hide';
  document.getElementById('adhoc-raw-res-btn').textContent = 'Hide';
}

function toggleAdhocRaw(panel) {
  var panelEl = document.getElementById('adhoc-raw-' + panel + '-panel');
  var btnEl   = document.getElementById('adhoc-raw-' + panel + '-btn');
  panelEl.classList.toggle('hidden');
  btnEl.textContent = panelEl.classList.contains('hidden') ? 'Show' : 'Hide';
}

// ── User management ────────────────────────────────────────────────────────────
function loadUsers() {
  document.getElementById('users-body').innerHTML =
    '<tr><td colspan="4" class="py-8 text-center text-gray-600"><div class="spinner" style="margin:auto"></div></td></tr>';
  api('/api/users').then(function(users) {
    if (!users.length) {
      document.getElementById('users-body').innerHTML =
        '<tr><td colspan="4" class="py-8 text-center text-gray-600">No users yet.</td></tr>';
      return;
    }
    var rows = '';
    users.forEach(function(u) {
      var isAdmin = u.role === 'admin';
      var isSelf  = currentUser && currentUser.username === u.username;
      var roleBadge = isAdmin
        ? '<span class="badge" style="background:#1e3a5f;color:#93c5fd;border:1px solid #1d4ed8">ADMIN</span>'
        : '<span class="badge badge-error">TESTER</span>';
      rows +=
        '<tr>' +
        '<td class="text-white font-medium">' + esc(u.username) +
          (isSelf ? ' <span class="text-xs text-gray-600 font-normal">(you)</span>' : '') +
        '</td>' +
        '<td>' + roleBadge + '</td>' +
        '<td class="text-gray-500 text-xs">' + (u.created_at || '').slice(0, 10) + '</td>' +
        '<td class="text-right">' +
          '<button class="user-role-btn text-xs text-blue-400 hover:text-blue-300 mr-4"' +
            ' data-uid="' + esc(u.id) + '" data-new-role="' + (isAdmin ? 'tester' : 'admin') + '">' +
            'Make ' + (isAdmin ? 'Tester' : 'Admin') +
          '</button>' +
          '<button class="user-pw-btn text-xs text-yellow-400 hover:text-yellow-300 mr-4"' +
            ' data-uid="' + esc(u.id) + '" data-uname="' + esc(u.username) + '">' +
            'Reset PW' +
          '</button>' +
          (isSelf
            ? '<span class="text-xs text-gray-700">Delete</span>'
            : '<button class="user-del-btn text-xs text-red-400 hover:text-red-300"' +
              ' data-uid="' + esc(u.id) + '" data-uname="' + esc(u.username) + '">Delete</button>'
          ) +
        '</td>' +
        '</tr>';
    });
    document.getElementById('users-body').innerHTML = rows;

    document.querySelectorAll('.user-role-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var newRole = btn.getAttribute('data-new-role');
        if (!confirm('Change role to ' + newRole + '?')) return;
        api('/api/users/' + btn.getAttribute('data-uid') + '/role', {
          method: 'PUT',
          body: JSON.stringify({ role: newRole }),
        }).then(function() { loadUsers(); });
      });
    });

    document.querySelectorAll('.user-pw-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var pw = prompt('New password for ' + btn.getAttribute('data-uname') + ':');
        if (!pw) return;
        api('/api/users/' + btn.getAttribute('data-uid') + '/password', {
          method: 'PUT',
          body: JSON.stringify({ password: pw }),
        }).then(function() {
          alert('Password reset. Active sessions for this user have been revoked.');
        });
      });
    });

    document.querySelectorAll('.user-del-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        if (!confirm('Delete "' + btn.getAttribute('data-uname') + '"? This cannot be undone.')) return;
        api('/api/users/' + btn.getAttribute('data-uid'), { method: 'DELETE' })
          .then(function() { loadUsers(); });
      });
    });
  }).catch(function(err) {
    document.getElementById('users-body').innerHTML =
      '<tr><td colspan="4" class="py-4 text-red-400 text-sm text-center">' + esc(String(err)) + '</td></tr>';
  });
}

function showCreateUser() {
  document.getElementById('create-user-form').classList.remove('hidden');
  document.getElementById('new-username').focus();
}
function hideCreateUser() {
  document.getElementById('create-user-form').classList.add('hidden');
  document.getElementById('new-username').value = '';
  document.getElementById('new-password').value = '';
  document.getElementById('new-role').value = 'tester';
  document.getElementById('cu-error').classList.add('hidden');
}
function submitCreateUser() {
  var username = document.getElementById('new-username').value.trim();
  var password = document.getElementById('new-password').value;
  var role     = document.getElementById('new-role').value;
  var errEl    = document.getElementById('cu-error');
  errEl.classList.add('hidden');
  if (!username || !password) {
    errEl.textContent = 'Username and password are required.';
    errEl.classList.remove('hidden');
    return;
  }
  api('/api/users', { method: 'POST', body: JSON.stringify({ username: username, password: password, role: role }) })
    .then(function() { hideCreateUser(); loadUsers(); })
    .catch(function(err) { errEl.textContent = String(err); errEl.classList.remove('hidden'); });
}

// ── Admin: Inspection profile management ──────────────────────────────────────
function loadAdminInspectKeys() {
  if (!currentUser || currentUser.role !== 'admin') return;
  var tbody = document.getElementById('ikeys-body');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="3" class="py-6 text-center text-gray-600"><div class="spinner" style="margin:auto"></div></td></tr>';
  api('/api/inspect-keys')
    .then(function(keys) {
      if (!keys.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="py-6 text-center text-gray-600">No profiles registered yet.</td></tr>';
        return;
      }
      var rows = '';
      keys.forEach(function(k) {
        rows +=
          '<tr>' +
          '<td class="text-white font-medium">' + esc(k.profile_name) + '</td>' +
          '<td class="text-xs text-gray-500 mono">' + esc(k.profile_id) + '</td>' +
          '<td class="text-right">' +
            '<button class="ikey-del-btn text-xs text-red-400 hover:text-red-300"' +
              ' data-pid="' + esc(k.profile_id) + '" data-pname="' + esc(k.profile_name) + '">Remove</button>' +
          '</td>' +
          '</tr>';
      });
      tbody.innerHTML = rows;
      document.querySelectorAll('.ikey-del-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          if (!confirm('Remove "' + btn.getAttribute('data-pname') + '" from inspection profiles?')) return;
          api('/api/inspect-keys/' + encodeURIComponent(btn.getAttribute('data-pid')), { method: 'DELETE' })
            .then(function() { loadAdminInspectKeys(); });
        });
      });
    })
    .catch(function(err) {
      tbody.innerHTML = '<tr><td colspan="3" class="py-4 text-red-400 text-sm text-center">' + esc(String(err)) + '</td></tr>';
    });
}

function showAddInspectKey() {
  document.getElementById('add-ikey-form').classList.remove('hidden');
  document.getElementById('ikey-name').focus();
}
function hideAddInspectKey() {
  document.getElementById('add-ikey-form').classList.add('hidden');
  document.getElementById('ikey-pid').value  = '';
  document.getElementById('ikey-name').value = '';
  document.getElementById('ikey-key').value  = '';
  document.getElementById('ikey-error').classList.add('hidden');
}
function submitAddInspectKey() {
  var pid   = document.getElementById('ikey-pid').value.trim();
  var name  = document.getElementById('ikey-name').value.trim();
  var key   = document.getElementById('ikey-key').value.trim();
  var errEl = document.getElementById('ikey-error');
  errEl.classList.add('hidden');
  if (!pid || !name || !key) {
    errEl.textContent = 'All three fields are required.';
    errEl.classList.remove('hidden');
    return;
  }
  api('/api/inspect-keys', {
    method: 'POST',
    body: JSON.stringify({ profile_id: pid, profile_name: name, api_key: key }),
  })
    .then(function() { hideAddInspectKey(); loadAdminInspectKeys(); })
    .catch(function(err) { errEl.textContent = String(err); errEl.classList.remove('hidden'); });
}

// ── Init: check session ────────────────────────────────────────────────────────
fetch('/api/auth/me')
  .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
  .then(function(res) {
    if (res.ok) showApp(res.data);
    else showLogin();
  })
  .catch(function() { showLogin(); });
`;

export function getHtml(): string {
  return '<!DOCTYPE html>\n' +
'<html lang="en">\n' +
'<head>\n' +
'<meta charset="UTF-8">\n' +
'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
'<title>Firewall Tester</title>\n' +
'<script src="https://cdn.tailwindcss.com"><\/script>\n' +
'<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"><\/script>\n' +
'<style>\n' +
'body { font-family: system-ui, -apple-system, sans-serif; }\n' +
'code, .mono { font-family: ui-monospace, "Cascadia Code", monospace; }\n' +
'.tab-btn { color: #6b7280; border-bottom: 2px solid transparent; padding: 8px 16px; font-size: 14px; font-weight: 500; cursor: pointer; }\n' +
'.tab-btn:hover { color: #d1d5db; }\n' +
'.tab-btn.active { color: #fff; border-bottom-color: #3b82f6; }\n' +
'.badge { display: inline-block; padding: 1px 8px; border-radius: 9999px; font-size: 11px; font-weight: 700; letter-spacing: .03em; }\n' +
'.badge-block   { background: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }\n' +
'.badge-monitor { background: #78350f; color: #fcd34d; border: 1px solid #92400e; }\n' +
'.badge-pass    { background: #14532d; color: #86efac; border: 1px solid #166534; }\n' +
'.badge-error   { background: #1f2937; color: #9ca3af; border: 1px solid #374151; }\n' +
'.tbl th { font-size:11px; font-weight:600; letter-spacing:.06em; text-transform:uppercase; color:#6b7280; padding:8px 12px 8px 0; border-bottom:1px solid #1f2937; }\n' +
'.tbl td { font-size:13px; padding:10px 12px 10px 0; border-bottom:1px solid #111827; color:#d1d5db; vertical-align:middle; }\n' +
'.tbl tr:last-child td { border-bottom:none; }\n' +
'.tbl tr:hover td { background:rgba(255,255,255,.02); }\n' +
'.card { background:#111827; border:1px solid #1f2937; border-radius:8px; padding:20px; }\n' +
'.btn-primary { background:#2563eb; color:#fff; padding:6px 14px; border-radius:6px; font-size:13px; font-weight:500; cursor:pointer; }\n' +
'.btn-primary:hover   { background:#1d4ed8; }\n' +
'.btn-primary:disabled{ opacity:.5; cursor:not-allowed; }\n' +
'.btn-danger { background:#1f2937; color:#f87171; padding:6px 14px; border-radius:6px; font-size:13px; font-weight:500; cursor:pointer; }\n' +
'.btn-danger:hover { background:#7f1d1d; color:#fca5a5; }\n' +
'select, input[type=password], input[type=text], textarea { background:#1f2937; border:1px solid #374151; border-radius:6px; color:#d1d5db; padding:6px 10px; font-size:13px; }\n' +
'select:focus, input:focus, textarea:focus { outline:none; border-color:#3b82f6; }\n' +
'textarea { resize:vertical; width:100%; font-family:ui-monospace,"Cascadia Code",monospace; }\n' +
'.spinner { display:inline-block; width:14px; height:14px; border:2px solid #374151; border-top-color:#3b82f6; border-radius:50%; animation:spin .7s linear infinite; }\n' +
'@keyframes spin { to { transform:rotate(360deg); } }\n' +
'.prompt-text { font-family:ui-monospace,monospace; font-size:11px; color:#6b7280; max-width:320px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; display:block; }\n' +
'.pass-icon { font-size:16px; }\n' +
'.kpi-value { font-size:28px; font-weight:700; line-height:1.1; }\n' +
'#login-overlay { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:#03040a; z-index:50; }\n' +
'.login-card { background:#0d1117; border:1px solid #1f2937; border-radius:12px; padding:36px; width:100%; max-width:360px; }\n' +
'.login-card input[type=text], .login-card input[type=password] { width:100%; box-sizing:border-box; }\n' +
'<\/style>\n' +
'<\/head>\n' +
'<body class="bg-gray-950 text-gray-200 min-h-screen">\n' +

'<!-- Login overlay -->\n' +
'<div id="login-overlay">\n' +
'  <div class="login-card">\n' +
'    <div class="text-xl font-bold text-white mb-1">Firewall Tester</div>\n' +
'    <div class="text-gray-500 text-sm mb-6">Sign in to continue</div>\n' +
'    <div id="login-error" class="hidden text-red-400 text-sm mb-4 bg-red-950 border border-red-800 rounded px-3 py-2"></div>\n' +
'    <div class="flex flex-col gap-3">\n' +
'      <div>\n' +
'        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Username</label>\n' +
'        <input type="text" id="login-username" placeholder="admin" autocomplete="username"\n' +
'               onkeydown="if(event.key===\'Enter\')login()">\n' +
'      </div>\n' +
'      <div>\n' +
'        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Password</label>\n' +
'        <input type="password" id="login-password" placeholder="••••••••" autocomplete="current-password"\n' +
'               onkeydown="if(event.key===\'Enter\')login()">\n' +
'      </div>\n' +
'      <button id="login-btn" class="btn-primary mt-2" style="width:100%;padding:9px 14px" onclick="login()">Sign In</button>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +

'<!-- Main app -->\n' +
'<div id="app" class="hidden min-h-screen">\n' +

'<div class="border-b border-gray-800 bg-gray-900">\n' +
'  <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">\n' +
'    <div class="flex items-center gap-6">\n' +
'      <div>\n' +
'        <span class="text-lg font-bold text-white">Firewall Tester</span>\n' +
'        <span class="text-gray-500 text-sm ml-2">prompt evaluation &amp; event log</span>\n' +
'      </div>\n' +
'      <div class="flex gap-0">\n' +
'        <button class="tab-btn active" onclick="showTab(\'runner\')" id="tab-runner">Runner</button>\n' +
'        <button class="tab-btn" onclick="showTab(\'events\')" id="tab-events">Events</button>\n' +
'        <button class="tab-btn" onclick="showTab(\'stats\')" id="tab-stats">Stats</button>\n' +
'        <button class="tab-btn" onclick="showTab(\'inspect\')" id="tab-inspect">Inspect</button>\n' +
'        <button class="tab-btn hidden" onclick="showTab(\'users\')" id="tab-users">Users</button>\n' +
'      </div>\n' +
'    </div>\n' +
'    <div class="flex items-center gap-3">\n' +
'      <span id="header-role" class="text-xs font-semibold px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700"></span>\n' +
'      <span id="header-user" class="text-sm text-white font-medium"></span>\n' +
'      <button class="btn-danger" onclick="logout()" style="padding:5px 12px;font-size:12px">Sign Out</button>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +

'<div class="max-w-7xl mx-auto px-6 py-6">\n' +

'  <!-- RUNNER -->\n' +
'  <div id="pane-runner">\n' +
'    <div class="grid grid-cols-3 gap-4 mb-8" id="sets-grid"></div>\n' +
'    <div id="run-summary" class="hidden mb-4 card flex items-center gap-6">\n' +
'      <div class="text-sm font-semibold text-white" id="sum-name"></div>\n' +
'      <div class="flex items-center gap-1 text-sm">\n' +
'        <span class="text-green-400 font-semibold" id="sum-pass-n"></span>\n' +
'        <span class="text-gray-500">passed</span>\n' +
'      </div>\n' +
'      <div class="flex items-center gap-1 text-sm">\n' +
'        <span class="text-red-400 font-semibold" id="sum-fail-n"></span>\n' +
'        <span class="text-gray-500">failed</span>\n' +
'      </div>\n' +
'      <div class="text-gray-500 text-sm" id="sum-latency"></div>\n' +
'      <div id="sum-spinner" class="hidden"><div class="spinner"></div></div>\n' +
'    </div>\n' +
'    <div id="run-results" class="hidden card">\n' +
'      <table class="tbl w-full">\n' +
'        <thead><tr>\n' +
'          <th class="text-left" style="width:35%">Prompt</th>\n' +
'          <th class="text-left" style="width:80px">Expected</th>\n' +
'          <th class="text-left" style="width:80px">Actual</th>\n' +
'          <th class="text-center" style="width:48px">✓/✗</th>\n' +
'          <th class="text-left">Violations</th>\n' +
'          <th class="text-right" style="width:72px">Latency</th>\n' +
'        </tr></thead>\n' +
'        <tbody id="results-body"></tbody>\n' +
'      </table>\n' +
'    </div>\n' +
'  </div>\n' +

'  <!-- EVENTS -->\n' +
'  <div id="pane-events" class="hidden">\n' +
'    <div class="flex items-center gap-3 mb-5">\n' +
'      <select id="f-set" style="width:180px">\n' +
'        <option value="">All Sets</option>\n' +
'        <option value="sensitive-data">Sensitive Data</option>\n' +
'        <option value="security-controls">Security Controls</option>\n' +
'        <option value="content-moderation">Content Moderation</option>\n' +
'        <option value="model-judgment">Model Judgment</option>\n' +
'      </select>\n' +
'      <select id="f-verdict" style="width:140px">\n' +
'        <option value="">All Verdicts</option>\n' +
'        <option value="block">Block</option>\n' +
'        <option value="monitor">Monitor</option>\n' +
'        <option value="pass">Pass</option>\n' +
'      </select>\n' +
'      <button class="btn-primary" onclick="loadEvents()">Load Events</button>\n' +
'      <button class="btn-danger" onclick="confirmClear()">Clear All</button>\n' +
'      <span id="evt-count" class="text-gray-500 text-sm ml-auto"></span>\n' +
'    </div>\n' +
'    <div id="evt-loading" class="hidden text-gray-500 text-sm py-6 flex items-center gap-2"><div class="spinner"></div> Loading…</div>\n' +
'    <div class="card">\n' +
'      <table class="tbl w-full">\n' +
'        <thead><tr>\n' +
'          <th class="text-left" style="width:90px">Time</th>\n' +
'          <th class="text-left" style="width:120px">Set</th>\n' +
'          <th class="text-left" style="width:170px">Label</th>\n' +
'          <th class="text-left">Prompt</th>\n' +
'          <th class="text-left" style="width:76px">Expected</th>\n' +
'          <th class="text-left" style="width:76px">Verdict</th>\n' +
'          <th class="text-left" style="width:80px">Violations</th>\n' +
'          <th class="text-right" style="width:100px">Latency / Raw</th>\n' +
'        </tr></thead>\n' +
'        <tbody id="evt-body">\n' +
'          <tr><td colspan="8" class="py-8 text-center text-gray-600">No events yet — run a prompt set to get started.</td></tr>\n' +
'        </tbody>\n' +
'      </table>\n' +
'    </div>\n' +
'  </div>\n' +

'  <!-- STATS -->\n' +
'  <div id="pane-stats" class="hidden">\n' +
'    <div class="grid grid-cols-3 gap-4 mb-6">\n' +
'      <div class="card"><div class="text-xs text-gray-500 uppercase tracking-wider mb-2">Total Runs</div><div class="kpi-value text-white" id="s-total">—</div></div>\n' +
'      <div class="card"><div class="text-xs text-gray-500 uppercase tracking-wider mb-2">Detection Accuracy</div><div class="kpi-value text-green-400" id="s-accuracy">—</div><div class="text-xs text-gray-500 mt-1">actual matches expected</div></div>\n' +
'      <div class="card"><div class="text-xs text-gray-500 uppercase tracking-wider mb-2">Avg Latency</div><div class="kpi-value text-blue-400" id="s-latency">—</div></div>\n' +
'    </div>\n' +
'    <div class="grid grid-cols-2 gap-4 mb-6">\n' +
'      <div class="card"><div class="text-sm font-semibold text-gray-300 mb-4">Verdict Distribution</div><div style="height:220px"><canvas id="c-verdict"></canvas></div></div>\n' +
'      <div class="card"><div class="text-sm font-semibold text-gray-300 mb-4">Runs by Set &amp; Verdict</div><div style="height:220px"><canvas id="c-sets"></canvas></div></div>\n' +
'    </div>\n' +
'    <div class="card">\n' +
'      <div class="text-sm font-semibold text-gray-300 mb-4">Set Breakdown</div>\n' +
'      <table class="tbl w-full">\n' +
'        <thead><tr>\n' +
'          <th class="text-left">Set</th>\n' +
'          <th class="text-right">Block</th>\n' +
'          <th class="text-right">Monitor</th>\n' +
'          <th class="text-right">Pass</th>\n' +
'          <th class="text-right">Error</th>\n' +
'          <th class="text-right">Total</th>\n' +
'          <th class="text-right">Avg Latency</th>\n' +
'        </tr></thead>\n' +
'        <tbody id="s-breakdown"></tbody>\n' +
'      </table>\n' +
'    </div>\n' +
'  </div>\n' +

'  <!-- INSPECT -->\n' +
'  <div id="pane-inspect" class="hidden">\n' +
'    <div class="grid grid-cols-2 gap-6 mb-6">\n' +
'      <div class="card">\n' +
'        <div class="text-sm font-semibold text-gray-300 mb-3">Prompt</div>\n' +
'        <textarea id="adhoc-prompt" rows="10" placeholder="Type any prompt to test the firewall..."></textarea>\n' +
'      </div>\n' +
'      <div class="card flex flex-col gap-4">\n' +
'        <div>\n' +
'          <div class="text-xs text-gray-500 uppercase tracking-wider mb-2">Security Profile</div>\n' +
'          <select id="adhoc-profile" style="width:100%;box-sizing:border-box">\n' +
'            <option value="">Select a security profile…</option>\n' +
'          </select>\n' +
'          <div class="text-xs text-gray-600 mt-2">Determines which policies are applied. Admins register profiles in the Users tab.</div>\n' +
'        </div>\n' +
'        <div class="mt-auto flex items-center gap-3">\n' +
'          <button id="adhoc-send" class="btn-primary" onclick="sendAdhoc()">Inspect Prompt</button>\n' +
'          <div id="adhoc-spinner" class="hidden flex items-center gap-2">\n' +
'            <div class="spinner"></div>\n' +
'            <span class="text-gray-500 text-sm">Running…</span>\n' +
'          </div>\n' +
'        </div>\n' +
'      </div>\n' +
'    </div>\n' +
'    <div id="adhoc-error" class="hidden card mb-4 text-red-400 text-sm"></div>\n' +
'    <div id="adhoc-result" class="hidden">\n' +
'      <div class="card mb-4 flex items-center gap-4">\n' +
'        <div id="adhoc-verdict"></div>\n' +
'        <div class="text-xs text-gray-600 mono flex-1 truncate" id="adhoc-reqid"></div>\n' +
'        <div id="adhoc-cached"></div>\n' +
'        <div class="text-gray-400 text-sm font-semibold" id="adhoc-wall"></div>\n' +
'      </div>\n' +
'      <div class="card mb-4">\n' +
'        <div class="text-sm font-semibold text-gray-300 mb-3">Violations</div>\n' +
'        <div id="adhoc-violations"></div>\n' +
'      </div>\n' +
'      <div class="card mb-4">\n' +
'        <div class="text-sm font-semibold text-gray-300 mb-3">Layer Latency</div>\n' +
'        <div id="adhoc-latency"></div>\n' +
'      </div>\n' +
'      <div class="grid grid-cols-2 gap-4">\n' +
'        <div class="card">\n' +
'          <div class="flex items-center justify-between mb-2">\n' +
'            <div class="text-xs text-gray-500 uppercase tracking-wider">Raw Request</div>\n' +
'            <button id="adhoc-raw-req-btn" class="text-xs text-blue-400 hover:text-blue-300" onclick="toggleAdhocRaw(\'req\')">Hide</button>\n' +
'          </div>\n' +
'          <div id="adhoc-raw-req-panel">\n' +
'            <pre id="adhoc-raw-req" class="bg-gray-900 border border-gray-800 rounded p-3 text-xs text-green-300 overflow-auto max-h-64"></pre>\n' +
'          </div>\n' +
'        </div>\n' +
'        <div class="card">\n' +
'          <div class="flex items-center justify-between mb-2">\n' +
'            <div class="text-xs text-gray-500 uppercase tracking-wider">Raw Response</div>\n' +
'            <button id="adhoc-raw-res-btn" class="text-xs text-blue-400 hover:text-blue-300" onclick="toggleAdhocRaw(\'res\')">Hide</button>\n' +
'          </div>\n' +
'          <div id="adhoc-raw-res-panel">\n' +
'            <pre id="adhoc-raw-res" class="bg-gray-900 border border-gray-800 rounded p-3 text-xs text-blue-300 overflow-auto max-h-64"></pre>\n' +
'          </div>\n' +
'        </div>\n' +
'      </div>\n' +
'    </div>\n' +
'  </div>\n' +

'  <!-- USERS + INSPECT PROFILES (admin only) -->\n' +
'  <div id="pane-users" class="hidden">\n' +
'    <div class="flex items-center justify-between mb-5">\n' +
'      <div class="text-sm font-semibold text-gray-300">User Management</div>\n' +
'      <button class="btn-primary" onclick="showCreateUser()">+ New User</button>\n' +
'    </div>\n' +
'    <div id="create-user-form" class="hidden card mb-5">\n' +
'      <div class="text-sm font-semibold text-gray-200 mb-4">Create User</div>\n' +
'      <div class="grid grid-cols-3 gap-4">\n' +
'        <div>\n' +
'          <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Username</label>\n' +
'          <input type="text" id="new-username" placeholder="username" style="width:100%;box-sizing:border-box"\n' +
'                 onkeydown="if(event.key===\'Enter\')submitCreateUser()">\n' +
'        </div>\n' +
'        <div>\n' +
'          <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Password</label>\n' +
'          <input type="password" id="new-password" placeholder="••••••••" style="width:100%;box-sizing:border-box"\n' +
'                 onkeydown="if(event.key===\'Enter\')submitCreateUser()">\n' +
'        </div>\n' +
'        <div>\n' +
'          <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Role</label>\n' +
'          <select id="new-role" style="width:100%;box-sizing:border-box">\n' +
'            <option value="tester">Tester</option>\n' +
'            <option value="admin">Admin</option>\n' +
'          </select>\n' +
'        </div>\n' +
'      </div>\n' +
'      <div class="mt-4 flex items-center gap-3">\n' +
'        <button class="btn-primary" onclick="submitCreateUser()">Create</button>\n' +
'        <button class="btn-danger" onclick="hideCreateUser()">Cancel</button>\n' +
'        <span id="cu-error" class="hidden text-red-400 text-sm"></span>\n' +
'      </div>\n' +
'    </div>\n' +
'    <div class="card">\n' +
'      <table class="tbl w-full">\n' +
'        <thead><tr>\n' +
'          <th class="text-left">Username</th>\n' +
'          <th class="text-left" style="width:90px">Role</th>\n' +
'          <th class="text-left" style="width:110px">Created</th>\n' +
'          <th class="text-right" style="width:220px">Actions</th>\n' +
'        </tr></thead>\n' +
'        <tbody id="users-body">\n' +
'          <tr><td colspan="4" class="py-8 text-center text-gray-600">Loading…</td></tr>\n' +
'        </tbody>\n' +
'      </table>\n' +
'    </div>\n' +

'    <!-- Inspection profiles -->\n' +
'    <div class="flex items-center justify-between mt-10 mb-5">\n' +
'      <div>\n' +
'        <div class="text-sm font-semibold text-gray-300">Inspection Profiles</div>\n' +
'        <div class="text-xs text-gray-600 mt-0.5">Link a Security Profile to its API key so testers can use it in the Inspect tab.</div>\n' +
'      </div>\n' +
'      <button class="btn-primary" onclick="showAddInspectKey()">+ Add Profile</button>\n' +
'    </div>\n' +
'    <div id="add-ikey-form" class="hidden card mb-5">\n' +
'      <div class="text-sm font-semibold text-gray-200 mb-4">Register Inspection Profile</div>\n' +
'      <div class="grid grid-cols-3 gap-4">\n' +
'        <div>\n' +
'          <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Profile Name</label>\n' +
'          <input type="text" id="ikey-name" placeholder="Default Profile" style="width:100%;box-sizing:border-box">\n' +
'        </div>\n' +
'        <div>\n' +
'          <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Profile ID</label>\n' +
'          <input type="text" id="ikey-pid" placeholder="UUID from policy-manager" style="width:100%;box-sizing:border-box">\n' +
'        </div>\n' +
'        <div>\n' +
'          <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">API Key</label>\n' +
'          <input type="password" id="ikey-key" placeholder="fw_…" style="width:100%;box-sizing:border-box">\n' +
'        </div>\n' +
'      </div>\n' +
'      <div class="mt-4 flex items-center gap-3">\n' +
'        <button class="btn-primary" onclick="submitAddInspectKey()">Save</button>\n' +
'        <button class="btn-danger" onclick="hideAddInspectKey()">Cancel</button>\n' +
'        <span id="ikey-error" class="hidden text-red-400 text-sm"></span>\n' +
'      </div>\n' +
'    </div>\n' +
'    <div class="card">\n' +
'      <table class="tbl w-full">\n' +
'        <thead><tr>\n' +
'          <th class="text-left">Profile Name</th>\n' +
'          <th class="text-left">Profile ID</th>\n' +
'          <th class="text-right" style="width:80px">Actions</th>\n' +
'        </tr></thead>\n' +
'        <tbody id="ikeys-body">\n' +
'          <tr><td colspan="3" class="py-6 text-center text-gray-600">Loading…</td></tr>\n' +
'        </tbody>\n' +
'      </table>\n' +
'    </div>\n' +
'  </div>\n' +

'</div>\n' +
'</div>\n' +

'<script>\n' + PAGE_JS + '\n<\/script>\n' +
'</body>\n</html>';
}
