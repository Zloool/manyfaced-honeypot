"""Static CSS + JS for the dashboard (issue #234 redesign).

Plain strings, no build step, no third-party framework — consistent with
``dashboard.py``'s "stdlib http.server only" design constraint. Kept in their
own module purely to keep ``dashboard_render.py`` readable; they are inlined
into the single served page (no separate static-asset route), preserving the
existing "every other path 404s" security posture.
"""

from __future__ import annotations

CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:#050805;color:#83f5ae;font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
  -webkit-font-smoothing:antialiased;overflow-x:hidden;
  background-image:radial-gradient(circle at 50% -10%, rgba(30,90,52,.28), transparent 60%)}
a{color:#83f5ae;text-decoration:none}
a:hover{color:#d3ffe4}
::selection{background:#1f5c38;color:#eafff2}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:#060c07}
::-webkit-scrollbar-thumb{background:#183a24;border-radius:2px}
input{font-family:inherit}
button{font-family:inherit;cursor:pointer}
[hidden]{display:none!important}

@keyframes blink{0%,49%{opacity:1}50%,100%{opacity:.12}}
@keyframes flick{0%,100%{opacity:1}92%{opacity:1}93%{opacity:.86}94%{opacity:1}97%{opacity:.93}98%{opacity:1}}

.crt-scan{position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg, rgba(0,0,0,.14) 0px, rgba(0,0,0,.14) 1px, transparent 1px, transparent 3px);
  mix-blend-mode:multiply}
.crt-vignette{position:fixed;inset:0;pointer-events:none;z-index:9998;
  background:radial-gradient(ellipse at center, transparent 52%, rgba(0,0,0,.6) 100%);
  animation:flick 7s infinite linear}

.title-font{font-family:'VT323',ui-monospace,monospace}

nav.top{position:sticky;top:0;z-index:60;display:flex;align-items:center;gap:22px;padding:11px 22px;flex-wrap:wrap;
  background:rgba(6,11,7,.86);backdrop-filter:blur(7px);border-bottom:1px solid rgba(120,255,170,.16)}
.brand{font-family:'VT323',monospace;font-size:23px;color:#d3ffe4;letter-spacing:1px;line-height:1}
.brand-dim{color:#3f7a55}
.nav-links{display:flex;gap:16px;font-size:12px;letter-spacing:.5px;flex-wrap:wrap}
.nav-links a{color:#4e8768;white-space:nowrap}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:16px;font-size:12px}
.live-pill{display:inline-flex;align-items:center;gap:7px;color:#83f5ae}
.dot{width:8px;height:8px;border-radius:50%;background:#3dff88;box-shadow:0 0 9px #3dff88;animation:blink 1.4s infinite;display:inline-block}
.clock{color:#d3ffe4;font-variant-numeric:tabular-nums;min-width:74px;text-align:right;display:inline-block}
.btn{font-size:11px;letter-spacing:.5px;padding:5px 11px;border-radius:4px;background:#0c160d;color:#83f5ae;border:1px solid rgba(120,255,170,.25)}

main{max-width:1180px;margin:0 auto;padding:0 22px 90px}

.hero{padding:38px 0 10px}
.hero-head{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:16px}
.hero-title{font-family:'VT323',monospace;font-size:52px;line-height:.9;color:#d3ffe4;
  text-shadow:0 0 16px rgba(70,255,140,.45);letter-spacing:1px}
.blink-cursor{animation:blink 1s step-end infinite;color:#3dff88}
.hero-sub{margin-top:8px;color:#4e8768;font-size:13px;letter-spacing:.5px}
.hero-sub b{color:#83f5ae;font-weight:400}
.hero-mult{text-align:right;font-size:11px;color:#3f7a55;letter-spacing:.5px}
.hero-mult .dim{color:#2f5c40}

.hero-canvas-wrap{position:relative;height:452px;border:1px solid rgba(120,255,170,.2);border-radius:9px;
  overflow:hidden;background:radial-gradient(ellipse at 50% 40%, #0a160d, #050905)}
.hero-canvas-wrap canvas{width:100%;height:100%;display:block}
.hero-flag{position:absolute;top:12px;left:14px;font-size:11px;letter-spacing:1px;color:#3dff88;display:flex;align-items:center;gap:7px}
.hero-legend{position:absolute;bottom:12px;left:14px;display:flex;gap:16px;font-size:11px;color:#4e8768}
.hero-legend span{display:inline-flex;align-items:center;gap:6px}
.sw{width:9px;height:9px;border-radius:2px;display:inline-block}
.sw.probe{background:#3dff88;box-shadow:0 0 6px #3dff88}
.sw.scan{background:#ffcf5c;box-shadow:0 0 6px #ffcf5c}
.sw.exploit{background:#ff6b74;box-shadow:0 0 6px #ff6b74}
.hero-hint{position:absolute;bottom:12px;right:14px;font-size:11px;color:#3f7a55}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:14px}
.stat-card{background:#080f09;border:1px solid rgba(120,255,170,.16);border-radius:7px;padding:14px 15px}
.stat-label{font-size:11px;letter-spacing:1px;color:#3f7a55;text-transform:uppercase}
.stat-value{font-family:'VT323',monospace;font-size:38px;line-height:1;margin-top:4px;font-variant-numeric:tabular-nums;
  text-shadow:0 0 12px rgba(70,255,140,.35)}
.stat-sub{font-size:11px;color:#4e8768;margin-top:4px}

.section{padding:40px 0 6px}
.section-head{display:flex;align-items:center;gap:12px;margin-bottom:4px;flex-wrap:wrap}
.section-title{font-family:'VT323',monospace;font-size:30px;color:#d3ffe4;letter-spacing:1px}
.rule{flex:1;min-width:24px;height:1px;background:linear-gradient(90deg,rgba(120,255,170,.3),transparent)}
.section-hint{font-size:12px;color:#3f7a55;margin-bottom:14px}

.seg-row{display:flex;gap:6px;flex-wrap:wrap}
.seg-btn{font-size:12px;letter-spacing:.5px;padding:6px 13px;border-radius:5px;
  background:#0c160d;color:#4e8768;border:1px solid rgba(120,255,170,.2)}
.seg-btn.active{background:#12241a;color:#d3ffe4;border-color:rgba(120,255,170,.55)}
.seg-btn.sm{font-size:11px;padding:4px 9px}

.chip-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.chip{font-size:11px;letter-spacing:.3px;padding:4px 9px;border-radius:4px;
  background:#0c160d;color:#4e8768;border:1px solid rgba(120,255,170,.2);display:inline-flex;gap:7px;align-items:center}
.chip.active{background:#12241a;color:#d3ffe4;border-color:rgba(120,255,170,.55)}
.chip.filter{background:#12241a;color:#83f5ae;border-color:rgba(120,255,170,.3)}
.chip-x{color:#4e8768}
.chip-clear{color:#ff6b74;border-color:rgba(255,107,116,.35);background:transparent}
.chip-label{font-size:11px;color:#3f7a55}

.vol-box{background:#080f09;border:1px solid rgba(120,255,170,.16);border-radius:8px;padding:16px 18px;overflow-x:auto}
.vol-chart{display:flex;align-items:flex-end;gap:6px;height:200px;padding-top:6px}
.vol-col{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;flex:1 1 0;min-width:14px;cursor:pointer;height:100%}
.vol-col.focus .vol-bar{background:linear-gradient(180deg,#1f7a49,#d3ffe4)}
.vol-bars{flex:1 1 auto;width:100%;display:flex;align-items:flex-end;justify-content:center;min-height:0}
.vol-bar{width:100%;max-width:46px;min-height:2px;background:linear-gradient(180deg,#1f7a49,#3dff88);box-shadow:0 0 10px rgba(61,255,136,.4);border-radius:3px 3px 0 0;transition:height .3s ease}
.vol-xlabel{font-size:10px;color:#4e8768;text-align:center;font-variant-numeric:tabular-nums;margin-top:6px;white-space:nowrap}
.vol-xcount{font-size:11px;color:#83f5ae;text-align:center;font-variant-numeric:tabular-nums}

.intel-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.intel-card{background:#080f09;border:1px solid rgba(120,255,170,.16);border-radius:8px;padding:15px 16px}
.intel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.intel-title{font-size:12px;letter-spacing:1px;color:#d3ffe4;text-transform:uppercase}
.intel-row{display:grid;grid-template-columns:20px 1fr 70px;align-items:center;gap:10px;padding:5px 6px;border-radius:4px;cursor:pointer}
.intel-row.active{background:rgba(120,255,170,.09)}
.intel-rank{font-size:11px;color:#2f5c40;text-align:right}
.intel-label-row{display:flex;align-items:baseline;gap:8px}
.intel-label{font-size:13px;color:#a9f7c6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.intel-row.active .intel-label{color:#d3ffe4}
.intel-label.repeat-offender{color:#ff6b74}
.intel-sub{font-size:10px;color:#3f7a55;white-space:nowrap}
.intel-track{height:5px;margin-top:5px;background:rgba(120,255,170,.07);border-radius:3px;overflow:hidden}
.intel-fill{height:100%;background:#3dff88;box-shadow:0 0 7px rgba(61,255,136,.4)}
.intel-fill.hot{background:#ffcf5c}
.intel-fill.danger{background:#ff6b74}
.intel-count{font-size:12px;color:#83f5ae;text-align:right;font-variant-numeric:tabular-nums}

.log-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.search-wrap{position:relative;flex:1;min-width:220px}
.search-prompt{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:#2f5c40;font-size:12px}
.search-input{width:100%;background:#080f09;border:1px solid rgba(120,255,170,.2);border-radius:5px;
  color:#d3ffe4;font-size:12px;padding:8px 11px 8px 26px;outline:none}

.log-box{background:#080f09;border:1px solid rgba(120,255,170,.16);border-radius:8px;overflow:hidden}
.log-head-row{display:grid;grid-template-columns:82px 92px 1fr 132px 92px 26px;gap:10px;padding:9px 14px;
  border-bottom:1px solid rgba(120,255,170,.14);font-size:10px;letter-spacing:1px;color:#2f5c40;text-transform:uppercase}
.log-empty{padding:34px;text-align:center;color:#3f7a55;font-size:13px}

.log-pager{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:14px;justify-content:center}
.log-pager .seg-btn[disabled]{opacity:.4;cursor:default}
.log-pager .seg-btn{min-width:34px}
.pager-ellipsis{color:#3f7a55;padding:0 4px}
.pager-info{font-size:11px;color:#4e8768;margin-left:8px;font-variant-numeric:tabular-nums}

.log-entry{border-bottom:1px solid rgba(120,255,170,.07)}
.log-row-main{display:grid;grid-template-columns:82px 92px 1fr 132px 92px 26px;gap:10px;padding:9px 14px;
  cursor:pointer;align-items:center;border-left:2px solid #3dff88}
.log-time{font-size:11px;color:#4e8768;font-variant-numeric:tabular-nums}
.log-port{font-size:12px;color:#d3ffe4;font-variant-numeric:tabular-nums}
.log-svc{font-size:10px;color:#3f7a55}
.log-req{min-width:0;display:flex;align-items:center;gap:9px}
.badge-method{font-size:10px;padding:1px 6px;border-radius:3px;white-space:nowrap}
.badge-method.get{background:rgba(120,255,170,.12);color:#83f5ae}
.badge-method.post{background:rgba(255,207,92,.16);color:#ffcf5c}
.badge-method.other{background:rgba(102,230,255,.12);color:#66e6ff}
.log-target{font-size:12px;color:#a9f7c6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge-face{font-size:10px;padding:1px 6px;border-radius:3px;background:rgba(120,255,170,.09);color:#4e8768;white-space:nowrap}
.log-source{font-size:11px;color:#83f5ae;min-width:0}
.log-cc{color:#ffcf5c}
.log-ip{color:#4e8768}
.log-sensor{font-size:11px;color:#3f7a55;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-caret{font-size:12px;color:#2f5c40;text-align:center}

.log-raw-wrap{padding:2px 14px 14px 18px}
.log-raw-meta{display:flex;gap:20px;flex-wrap:wrap;font-size:10px;color:#3f7a55;margin:6px 0 8px}
.log-raw-meta b{color:#83f5ae;font-weight:400}
.log-raw{margin:0;white-space:pre-wrap;word-break:break-all;font-size:11.5px;line-height:1.55;color:#8fe6ac;
  background:#040704;border:1px solid rgba(120,255,170,.14);border-left:2px solid #3dff88;border-radius:5px;padding:11px 13px}

.log-group-main{background:rgba(120,255,170,.035)}
.badge-group{font-size:10px;padding:2px 7px;border-radius:3px;letter-spacing:.5px}
.badge-group.scan{background:rgba(255,107,116,.16);color:#ff6b74}
.badge-group.repeat{background:rgba(255,207,92,.16);color:#ffcf5c}
.badge-group.burst{background:rgba(102,230,255,.14);color:#66e6ff}
.log-group-count{font-size:10px;padding:1px 7px;border-radius:3px;white-space:nowrap;font-variant-numeric:tabular-nums}
.log-children{background:#050a06}
.log-child-row{display:grid;grid-template-columns:82px 92px 1fr 132px 92px 26px;gap:10px;padding:7px 14px 7px 26px;
  cursor:pointer;align-items:center;border-top:1px solid rgba(120,255,170,.05)}

.footer{text-align:center;color:#254a33;font-size:11px;margin-top:46px}

@media (max-width:720px){
  nav.top{gap:10px 14px;padding:10px 14px}
  .brand{font-size:20px}
  .nav-links{gap:12px;order:3;width:100%;justify-content:flex-start}
  .nav-right{margin-left:auto;gap:10px;flex-wrap:wrap;justify-content:flex-end}
  .log-head-row,.log-row-main,.log-child-row{grid-template-columns:64px 70px 1fr 26px}
  .log-source,.log-sensor{display:none}
}
"""

# Bootstrap object (token/range) is injected before this script as
# `window.__MFD__ = {...}` — see dashboard_render.render_page(). All other
# dynamic content in this script is inserted via textContent or via HTML
# already escaped server-side, never raw string concatenation into innerHTML.
JS = r"""
(function(){
  'use strict';
  var CFG = window.__MFD__ || {};
  var state = { range: CFG.range || '24h', port: null, country: null, service: null, ip: null,
                window: null, method: 'ALL', sort: 'newest', search: '', paused: false, page: 1 };

  function $(sel, root){ return (root||document).querySelector(sel); }
  function $all(sel, root){ return Array.prototype.slice.call((root||document).querySelectorAll(sel)); }
  function pad(n){ return n<10?'0'+n:''+n; }

  // ---------------- clock ----------------
  function tickClock(){
    var d = new Date();
    var el = $('#clock');
    if (el) el.textContent = pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());
  }
  setInterval(tickClock, 1000); tickClock();

  // ---------------- pause ----------------
  var pauseBtn = $('#pause-btn');
  if (pauseBtn) pauseBtn.addEventListener('click', function(){
    state.paused = !state.paused;
    pauseBtn.textContent = state.paused ? '▶ RESUME' : '❘❘ PAUSE';
  });

  // ---------------- fetch helper ----------------
  // Wire format: first line is a fresh random boundary chosen by the server
  // for THIS response only; the rest is "<boundary>:<name>\n<content>\n"
  // chunks. The boundary can't be predicted ahead of time by anything that
  // ends up embedded in <content> (e.g. attacker-controlled capture text),
  // so it can't be used to forge a fake section split.
  function fetchFragment(range, port, page){
    var url = '?token='+encodeURIComponent(CFG.token)+'&format=fragment&range='+encodeURIComponent(range);
    if (port != null) url += '&port='+encodeURIComponent(port);
    if (page != null) url += '&page='+encodeURIComponent(page);
    return fetch(url, {credentials:'same-origin'}).then(function(r){ return r.text(); }).then(function(text){
      var nl = text.indexOf('\n');
      if (nl < 0) return {};
      var boundary = text.slice(0, nl);
      var chunks = text.slice(nl+1).split(boundary+':');
      var out = {};
      chunks.forEach(function(chunk){
        if (!chunk) return;
        var i = chunk.indexOf('\n');
        if (i < 0) return;
        var name = chunk.slice(0, i);
        var content = chunk.slice(i+1);
        if (content.slice(-1) === '\n') content = content.slice(0, -1);
        out[name] = content;
      });
      return out;
    });
  }

  function applyFragment(frag, sections){
    sections.forEach(function(name){
      if (frag[name] == null) return;
      var target = $('#'+name);
      if (target) target.innerHTML = frag[name];
    });
    if (frag.meta){
      try { applyMeta(JSON.parse(frag.meta)); } catch(e){ /* ignore malformed meta */ }
    }
    wireLogRows();
    wireIntelRows();
    wireVolumeRows();
    wireLogPager();
    applyFilters();
  }

  function applyMeta(meta){
    if (!meta) return;
    var map = {'stat-total':meta.total,'stat-day':meta.day,'stat-uniq':meta.uniq,
               'stat-ports':meta.activePorts,'stat-rate':meta.rate};
    Object.keys(map).forEach(function(id){
      var el = document.getElementById(id);
      if (el && map[id] != null) el.textContent = map[id];
    });
    var summary = $('#log-summary');
    if (summary && meta.summary){
      summary.setAttribute('data-full', meta.summary);
      summary.textContent = meta.summary;
    }
    // Keep the pager state in sync with the rendered page (issue #316).
    if (meta.logPage != null) state.page = meta.logPage;
  }

  // ---------------- range / port controls ----------------
  function setActive(row, attr, value){
    $all('.seg-btn', row).forEach(function(b){
      b.classList.toggle('active', b.getAttribute(attr) === String(value));
    });
  }

  var rangeRow = $('#range-row');
  if (rangeRow) rangeRow.addEventListener('click', function(e){
    var btn = e.target.closest('[data-range]');
    if (!btn) return;
    state.range = btn.getAttribute('data-range');
    state.window = null;
    state.page = 1;
    setActive(rangeRow, 'data-range', state.range);
    fetchFragment(state.range, state.port).then(function(frag){
      applyFragment(frag, ['vol-box','intel-grid','log-rows']);
    });
  });

  function setPortFilter(port){
    state.port = (port === '' || port == null) ? null : Number(port);
    state.page = 1;
    $all('.chip-port').forEach(function(b){
      b.classList.toggle('active', (b.getAttribute('data-port')||'') === String(state.port==null?'':state.port));
    });
    $all('.intel-row[data-filter-type="port"]').forEach(function(r){
      r.classList.toggle('active', Number(r.getAttribute('data-filter-value')) === state.port);
    });
    fetchFragment(state.range, state.port).then(function(frag){ applyFragment(frag, ['vol-box']); });
    applyFilters();
  }

  function wireVolumeRows(){
    var chipRow = $('#port-chip-row');
    if (chipRow && !chipRow.__wired){
      chipRow.__wired = true;
      chipRow.addEventListener('click', function(e){
        var btn = e.target.closest('.chip-port');
        if (!btn) return;
        setPortFilter(btn.getAttribute('data-port'));
      });
    }
    var volBox = $('#vol-box');
    if (volBox && !volBox.__wired){
      volBox.__wired = true;
      volBox.addEventListener('click', function(e){
        var row = e.target.closest('.vol-col');
        if (!row) return;
        var start = row.getAttribute('data-start'), end = row.getAttribute('data-end');
        var label = row.getAttribute('data-label');
        if (state.window && state.window.start === start){
          state.window = null;
        } else {
          state.window = {start:start, end:end, label:label};
        }
        $all('.vol-row', volBox).forEach(function(r){
          r.classList.toggle('focus', !!state.window && r.getAttribute('data-start') === state.window.start);
        });
        applyFilters();
      });
    }
  }

  // ---------------- intel top lists ----------------
  function wireIntelRows(){
    $all('.intel-card').forEach(function(card){
      if (card.__wired) return;
      card.__wired = true;
      var sortBtn = $('.intel-sort-btn', card);
      if (sortBtn) sortBtn.addEventListener('click', function(){
        var mode = sortBtn.getAttribute('data-mode') === 'count' ? 'name' : 'count';
        sortBtn.setAttribute('data-mode', mode);
        sortBtn.textContent = mode === 'count' ? 'BY VOLUME' : 'BY NAME';
        var list = $('.intel-list', card);
        var rows = $all('.intel-row', list);
        rows.sort(function(a,b){
          if (mode === 'count') return Number(b.getAttribute('data-count')) - Number(a.getAttribute('data-count'));
          return a.getAttribute('data-label').localeCompare(b.getAttribute('data-label'));
        });
        rows.forEach(function(r){ list.appendChild(r); });
      });
      card.addEventListener('click', function(e){
        var row = e.target.closest('.intel-row');
        if (!row) return;
        var type = row.getAttribute('data-filter-type'), value = row.getAttribute('data-filter-value');
        if (type === 'port'){
          setPortFilter(state.port === Number(value) ? null : value);
          return;
        }
        var key = type === 'country' ? 'country' : type === 'service' ? 'service' : 'ip';
        state[key] = (state[key] === value) ? null : value;
        $all('.intel-row[data-filter-type="'+type+'"]').forEach(function(r){
          r.classList.toggle('active', r.getAttribute('data-filter-value') === state[key]);
        });
        applyFilters();
      });
    });
  }

  // ---------------- log toolbar ----------------
  var searchInput = $('#log-search');
  if (searchInput) searchInput.addEventListener('input', function(){
    state.search = searchInput.value.trim().toLowerCase();
    applyFilters();
  });

  var methodRow = $('#method-row');
  if (methodRow) methodRow.addEventListener('click', function(e){
    var btn = e.target.closest('[data-method]');
    if (!btn) return;
    state.method = btn.getAttribute('data-method');
    setActive(methodRow, 'data-method', state.method);
    applyFilters();
  });

  var sortRow = $('#sort-row');
  if (sortRow) sortRow.addEventListener('click', function(e){
    var btn = e.target.closest('[data-sort]');
    if (!btn) return;
    state.sort = btn.getAttribute('data-sort');
    setActive(sortRow, 'data-sort', state.sort);
    reorderLog();
  });

  function reorderLog(){
    var container = $('#log-rows');
    if (!container) return;
    var rows = $all(':scope > .log-entry', container);
    rows.sort(function(a,b){
      if (state.sort === 'port') return (Number(a.getAttribute('data-sort-port'))||9999) - (Number(b.getAttribute('data-sort-port'))||9999) || (Number(b.getAttribute('data-ts')) - Number(a.getAttribute('data-ts')));
      if (state.sort === 'volume') return Number(b.getAttribute('data-count')) - Number(a.getAttribute('data-count')) || (Number(b.getAttribute('data-ts')) - Number(a.getAttribute('data-ts')));
      return Number(b.getAttribute('data-ts')) - Number(a.getAttribute('data-ts'));
    });
    rows.forEach(function(r){ container.appendChild(r); });
  }

  // ---------------- filter chips ----------------
  function chipHtml(label){
    var span = document.createElement('button');
    span.className = 'chip filter';
    span.textContent = label + ' ';
    var x = document.createElement('span');
    x.className = 'chip-x'; x.textContent = '✕';
    span.appendChild(x);
    return span;
  }

  function renderChips(){
    var row = $('#filter-chip-row');
    if (!row) return;
    row.innerHTML = '';
    var entries = [];
    if (state.port != null) entries.push(['port', 'port '+state.port]);
    if (state.country) entries.push(['country', 'country '+state.country]);
    if (state.service) entries.push(['service', 'service '+state.service]);
    if (state.ip) entries.push(['ip', 'ip '+state.ip]);
    if (state.window) entries.push(['window', 'window '+state.window.label]);
    if (state.method !== 'ALL') entries.push(['method', 'method '+state.method]);
    if (state.search) entries.push(['search', 'grep "'+state.search+'"']);
    if (!entries.length){ row.hidden = true; return; }
    row.hidden = false;
    var label = document.createElement('span');
    label.className = 'chip-label'; label.textContent = 'FILTERS:';
    row.appendChild(label);
    entries.forEach(function(entry){
      var btn = chipHtml(entry[1]);
      btn.addEventListener('click', function(){ clearFilter(entry[0]); });
      row.appendChild(btn);
    });
    var clearAll = document.createElement('button');
    clearAll.className = 'chip chip-clear'; clearAll.textContent = 'clear all';
    clearAll.addEventListener('click', clearAllFilters);
    row.appendChild(clearAll);
  }

  function clearFilter(kind){
    if (kind === 'port') return setPortFilter(null);
    if (kind === 'country') state.country = null;
    if (kind === 'service') state.service = null;
    if (kind === 'ip') state.ip = null;
    if (kind === 'window') state.window = null;
    if (kind === 'method'){ state.method = 'ALL'; setActive(methodRow, 'data-method', 'ALL'); }
    if (kind === 'search'){ state.search = ''; if (searchInput) searchInput.value = ''; }
    $all('.intel-row.active').forEach(function(r){ r.classList.remove('active'); });
    $all('.vol-row.focus').forEach(function(r){ r.classList.remove('focus'); });
    applyFilters();
  }

  function clearAllFilters(){
    state.port = null; state.country = null; state.service = null; state.ip = null;
    state.window = null; state.method = 'ALL'; state.search = ''; state.page = 1;
    if (searchInput) searchInput.value = '';
    if (methodRow) setActive(methodRow, 'data-method', 'ALL');
    $all('.chip-port').forEach(function(b){ b.classList.toggle('active', b.getAttribute('data-port') === ''); });
    $all('.intel-row.active').forEach(function(r){ r.classList.remove('active'); });
    $all('.vol-row.focus').forEach(function(r){ r.classList.remove('focus'); });
    fetchFragment(state.range, null).then(function(frag){ applyFragment(frag, ['vol-box']); });
  }

  // ---------------- log rows: toggle raw / group, filtering ----------------
  function wireLogPager(){
    var wrap = $('#log-pager-wrap');
    if (!wrap || wrap.__wired) return;
    wrap.__wired = true;
    wrap.addEventListener('click', function(e){
      var btn = e.target.closest('.log-pager [data-page]');
      if (!btn || btn.disabled) return;
      var p = parseInt(btn.getAttribute('data-page'), 10);
      if (!p || p === state.page) return;
      setLogPage(p);
    });
    // Re-apply active state when fragments refresh the pager in place.
    wrap.__wire = true;
  }

  function setLogPage(p){
    state.page = p;
    fetchFragment(state.range, state.port, p).then(function(frag){
      applyFragment(frag, ['vol-box','intel-grid','log-rows','log-pager']);
    });
  }

  function wireLogRows(){
    var container = $('#log-rows');
    if (!container || container.__wired) return;
    container.__wired = true;
    container.addEventListener('click', function(e){
      var mainRow = e.target.closest('.log-row-main, .log-group-main, .log-child-row');
      if (!mainRow) return;
      var wrap = mainRow.nextElementSibling;
      if (!wrap) return;
      var isHidden = wrap.hasAttribute('hidden');
      if (isHidden) wrap.removeAttribute('hidden'); else wrap.setAttribute('hidden','');
      var caret = $('.log-caret', mainRow);
      if (caret) caret.textContent = isHidden ? '▾' : '▸';
    });
  }

  function matchesFilters(entry){
    var ts = Number(entry.getAttribute('data-ts'));
    if (state.window){
      var s = Number(state.window.start), en = Number(state.window.end);
      if (ts < s || ts >= en) return false;
    }
    if (state.port != null){
      var ports = (entry.getAttribute('data-ports')||'').split(',').filter(Boolean).map(Number);
      if (ports.indexOf(state.port) < 0) return false;
    }
    if (state.country && entry.getAttribute('data-cc') !== state.country) return false;
    if (state.service && entry.getAttribute('data-service') !== state.service) return false;
    if (state.ip && entry.getAttribute('data-ip') !== state.ip) return false;
    if (state.method !== 'ALL' && entry.getAttribute('data-method') !== state.method) return false;
    if (state.search){
      var hay = entry.getAttribute('data-search') || '';
      if (hay.indexOf(state.search) < 0) return false;
    }
    return true;
  }

  function hasActiveFilters(){
    return state.port != null || !!state.country || !!state.service || !!state.ip ||
      !!state.window || state.method !== 'ALL' || !!state.search;
  }

  function applyFilters(){
    var container = $('#log-rows');
    var empty = $('#log-empty');
    if (!container) return;
    var entries = $all(':scope > .log-entry', container);
    var visible = 0;
    entries.forEach(function(entry){
      var ok = matchesFilters(entry);
      entry.hidden = !ok;
      if (ok) visible++;
    });
    if (empty) empty.hidden = visible > 0;
    var summary = $('#log-summary');
    if (summary){
      summary.textContent = hasActiveFilters()
        ? (visible + ' of ' + entries.length + ' rows match')
        : (summary.getAttribute('data-full') || summary.textContent);
    }
    renderChips();
  }

  // ---------------- hero canvas: patch-panel with cables + pulses ----------------
  function initHero(){
    var wrap = $('#hero-canvas-wrap');
    var cv = $('#srv-canvas');
    if (!wrap || !cv) return;
    var ctx = cv.getContext('2d');
    var ports;
    try { ports = JSON.parse(wrap.getAttribute('data-ports') || '[]'); } catch(e){ ports = []; }
    var mult = Number(wrap.getAttribute('data-mult')) || 6;
    if (!ports.length) return;

    var state2 = { ports: ports.map(function(p){ return {p:p.p, s:p.s, w:Math.max(1,p.w), glow:0, rings:[], flash:0}; }), pulses:[], W:0, H:0 };
    var chassis = null, spawns = [], rps = 0, acc = 0, last = performance.now();

    function wpick(arr){
      var t = 0, i;
      for (i=0;i<arr.length;i++) t += arr[i].w;
      var r = Math.random()*t;
      for (i=0;i<arr.length;i++){ r -= arr[i].w; if (r<=0) return arr[i]; }
      return arr[arr.length-1];
    }
    function rr(x,y,w,h,rad){ ctx.beginPath(); ctx.moveTo(x+rad,y); ctx.arcTo(x+w,y,x+w,y+h,rad);
      ctx.arcTo(x+w,y+h,x,y+h,rad); ctx.arcTo(x,y+h,x,y,rad); ctx.arcTo(x,y,x+w,y,rad); ctx.closePath(); }
    function bez(a,b,c,d,t){ var u=1-t; return {x:u*u*u*a.x+3*u*u*t*b.x+3*u*t*t*c.x+t*t*t*d.x,
      y:u*u*u*a.y+3*u*u*t*b.y+3*u*t*t*c.y+t*t*t*d.y}; }
    function sevCol(s){ return s==='crit'?'#ff6b74':s==='warn'?'#ffcf5c':'#3dff88'; }

    function layout(){
      var rect = cv.getBoundingClientRect(); var dpr = window.devicePixelRatio || 1;
      cv.width = rect.width*dpr; cv.height = rect.height*dpr; ctx.setTransform(dpr,0,0,dpr,0,0);
      state2.W = rect.width; state2.H = rect.height;
      var cw = Math.min(rect.width-60,720), ch = Math.min(rect.height-120,300);
      var cx = (rect.width-cw)/2, cy = (rect.height-ch)/2+8;
      chassis = {x:cx,y:cy,w:cw,h:ch};
      var cols = 6, rows = Math.ceil(state2.ports.length/cols);
      var padX=26, padTop=54, padBot=20;
      var gw=(cw-padX*2)/cols, gh=(ch-padTop-padBot)/rows;
      var railY = cy+40;
      state2.ports.forEach(function(pt,i){
        var c=i%cols, r=Math.floor(i/cols);
        pt.cx = cx+padX+gw*c+gw/2; pt.cy = cy+padTop+gh*r+gh/2-4;
        pt.lw = Math.min(gw-12,64); pt.lh = 20;
        var dir = (c%2)?1:-1; var bow = dir*Math.min(gw*0.42,52);
        var sx=pt.cx, sy=railY, ex=pt.cx, ey=pt.cy-pt.lh/2-3;
        pt.cab = {sx:sx,sy:sy,ex:ex,ey:ey,c1x:sx+bow,c1y:sy+(ey-sy)*0.32,c2x:ex+bow,c2y:sy+(ey-sy)*0.72};
      });
    }
    layout();
    window.addEventListener('resize', layout);

    function spawn(){
      var pt = wpick(state2.ports);
      var roll = Math.random(); var sev = roll<0.08?'crit':roll<0.30?'warn':'info';
      state2.pulses.push({pt:pt, t:0, dur:520+Math.random()*380, col:sevCol(sev)});
      spawns.push(performance.now());
    }

    function draw(nowp){
      var dt = Math.min(60, nowp-last); last = nowp;
      if (!state.paused){
        acc += dt/1000*(2.0*mult);
        while (acc>1){ spawn(); acc -= 1; }
      }
      var cut = nowp-1000;
      while (spawns.length && spawns[0]<cut) spawns.shift();
      rps = spawns.length;
      ctx.clearRect(0,0,state2.W,state2.H);
      ctx.strokeStyle = 'rgba(60,140,90,0.06)'; ctx.lineWidth = 1;
      for (var x=0;x<state2.W;x+=34){ ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,state2.H); ctx.stroke(); }
      for (var y=0;y<state2.H;y+=34){ ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(state2.W,y); ctx.stroke(); }
      if (!chassis) { requestAnimationFrame(draw); return; }
      var ch = chassis;
      ctx.save(); ctx.shadowColor='rgba(61,255,136,0.25)'; ctx.shadowBlur=24;
      rr(ch.x,ch.y,ch.w,ch.h,10); ctx.fillStyle='#0a140c'; ctx.fill();
      ctx.shadowBlur=0; ctx.lineWidth=1.5; ctx.strokeStyle='rgba(120,255,170,0.35)'; rr(ch.x,ch.y,ch.w,ch.h,10); ctx.stroke();
      ctx.restore();
      ctx.fillStyle='rgba(120,255,170,0.14)'; rr(ch.x-14,ch.y+10,10,ch.h-20,3); ctx.fill();
      rr(ch.x+ch.w+4,ch.y+10,10,ch.h-20,3); ctx.fill();
      for (var i=0;i<3;i++){
        ctx.fillStyle='rgba(200,255,220,0.35)';
        ctx.beginPath(); ctx.arc(ch.x-9,ch.y+22+i*((ch.h-44)/2),1.8,0,7); ctx.fill();
        ctx.beginPath(); ctx.arc(ch.x+ch.w+9,ch.y+22+i*((ch.h-44)/2),1.8,0,7); ctx.fill();
      }
      ctx.font="14px 'VT323', monospace"; ctx.textBaseline='middle'; ctx.fillStyle='#8fe6ac'; ctx.textAlign='left';
      ctx.fillText('MANYFACED // HIVE-NODE', ch.x+18, ch.y+22);
      ctx.textAlign='right'; ctx.fillStyle='#3dff88'; ctx.fillText('● '+rps+' pkt/s', ch.x+ch.w-18, ch.y+22);
      ctx.textAlign='left';
      ctx.strokeStyle='rgba(120,255,170,0.15)'; ctx.beginPath(); ctx.moveTo(ch.x+14,ch.y+38); ctx.lineTo(ch.x+ch.w-14,ch.y+38); ctx.stroke();

      state2.ports.forEach(function(pt){
        var cb = pt.cab; if (!cb) return;
        pt.flash *= Math.pow(0.015, dt/1000);
        ctx.beginPath(); ctx.moveTo(cb.sx,cb.sy); ctx.bezierCurveTo(cb.c1x,cb.c1y,cb.c2x,cb.c2y,cb.ex,cb.ey);
        ctx.strokeStyle = 'rgba(52,132,88,'+(0.20+pt.flash*0.55)+')'; ctx.lineWidth=3.4; ctx.stroke();
        if (pt.flash>0.02){
          ctx.save(); ctx.shadowColor=pt.fcol||'#3dff88'; ctx.shadowBlur=9*pt.flash; ctx.globalAlpha=Math.min(1,pt.flash);
          ctx.strokeStyle=pt.fcol||'#3dff88'; ctx.lineWidth=2;
          ctx.beginPath(); ctx.moveTo(cb.sx,cb.sy); ctx.bezierCurveTo(cb.c1x,cb.c1y,cb.c2x,cb.c2y,cb.ex,cb.ey); ctx.stroke();
          ctx.restore();
        }
        ctx.beginPath(); ctx.arc(cb.sx,cb.sy,2.3,0,7); ctx.fillStyle='rgba(140,240,180,0.55)'; ctx.fill();
      });

      state2.pulses = state2.pulses.filter(function(pl){
        pl.t += dt/pl.dur; var cb = pl.pt.cab; if (!cb) return false;
        if (pl.t>=1){
          pl.pt.glow = Math.min(1.5, pl.pt.glow+(pl.col==='#ff6b74'?1.1:0.85));
          pl.pt.rings.push({rad:6,a:0.7}); pl.pt.flash=1; pl.pt.fcol=pl.col;
          return false;
        }
        var P = function(t){ return bez({x:cb.sx,y:cb.sy},{x:cb.c1x,y:cb.c1y},{x:cb.c2x,y:cb.c2y},{x:cb.ex,y:cb.ey},t); };
        var a = P(pl.t), b = P(Math.max(0,pl.t-0.09));
        ctx.save(); ctx.shadowColor=pl.col; ctx.shadowBlur=10; ctx.strokeStyle=pl.col; ctx.lineWidth=3;
        ctx.beginPath(); ctx.moveTo(b.x,b.y); ctx.lineTo(a.x,a.y); ctx.stroke();
        ctx.beginPath(); ctx.arc(a.x,a.y,2.6,0,7); ctx.fillStyle=pl.col; ctx.fill();
        ctx.restore();
        return true;
      });

      state2.ports.forEach(function(pt){
        pt.glow *= Math.pow(0.001, dt/1000);
        var g = pt.glow; var x = pt.cx-pt.lw/2, y = pt.cy-pt.lh/2;
        ctx.save(); ctx.shadowColor='#3dff88'; ctx.shadowBlur=6+g*20;
        var base = 18+g*90;
        rr(x,y,pt.lw,pt.lh,3); ctx.fillStyle='rgb('+Math.round(10+g*40)+','+Math.round(base+40)+','+Math.round(24+g*30)+')'; ctx.fill();
        ctx.restore();
        rr(x,y,pt.lw,pt.lh,3); ctx.lineWidth=1; ctx.strokeStyle='rgba(120,255,170,'+(0.3+g*0.6)+')'; ctx.stroke();
        ctx.beginPath(); ctx.arc(x+6,pt.cy,2,0,7); ctx.fillStyle = g>0.15?'#d3ffe4':'#2fae62'; ctx.fill();
        ctx.font="bold 13px 'JetBrains Mono', monospace"; ctx.textAlign='center'; ctx.textBaseline='middle';
        ctx.fillStyle = g>0.3?'#f2fff7':'#c4f5d6'; ctx.fillText(pt.p, pt.cx+4, pt.cy);
        ctx.fillStyle='rgba(150,240,185,0.55)'; ctx.font="9px 'JetBrains Mono', monospace"; ctx.textBaseline='top';
        ctx.fillText(pt.s, pt.cx, pt.cy+pt.lh/2+3);
        pt.rings = pt.rings.filter(function(r){
          r.rad += dt*0.08; r.a -= dt*0.0016; if (r.a<=0) return false;
          ctx.beginPath(); ctx.arc(pt.cx+4,pt.cy,r.rad,0,7); ctx.strokeStyle='rgba(61,255,136,'+r.a+')'; ctx.lineWidth=1.4; ctx.stroke();
          return true;
        });
      });

      requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
  }

  // ---------------- live polling ----------------
  function refreshLive(){
    if (state.paused) return;
    fetchFragment(state.range, state.port, state.page).then(function(frag){
      applyFragment(frag, ['vol-box','intel-grid','log-rows']);
    }).catch(function(){ /* transient network hiccup — try again next tick */ });
  }
  setInterval(refreshLive, 20000);

  // ---------------- notes-less footer / init ----------------
  document.addEventListener('DOMContentLoaded', function(){
    wireLogRows(); wireIntelRows(); wireVolumeRows(); applyFilters(); initHero();
  });
  if (document.readyState !== 'loading'){ wireLogRows(); wireIntelRows(); wireVolumeRows(); applyFilters(); initHero(); }
})();
"""
