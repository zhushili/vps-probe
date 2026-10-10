const $ = id => document.getElementById(id);
const FIELDS = ['t','cpu','steal','iowait','mem','cache','swap','rx','tx','rd','wr'];
const COL = {cpu:'#3b82f6',steal:'#f43f5e',iowait:'#f59e0b',mem:'#8b5cf6',cache:'#06b6d4',swap:'#f59e0b',
             rx:'#10b981',tx:'#3b82f6',rd:'#f59e0b',wr:'#ec4899',disk:'#14b8a6',warn:'#f59e0b',crit:'#ef4444'};
const FONT = getComputedStyle(document.body).fontFamily;
const RING_C = 2 * Math.PI * 34;
// 基于 location.origin 拼接 API 地址：用 user:pass@host 打开面板时，相对地址会带上账号密码，fetch 会直接拒绝
const BASE = location.origin + location.pathname.replace(/[^/]*$/, '').replace(/\/$/, '');
const api = p => BASE + '/api/' + p;
const ICON = {
  sun:'<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>',
  moon:'<svg class="i" viewBox="0 0 24 24"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>',
  copy:'<svg class="i" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  x:'<svg class="i" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  plus:'<svg class="i" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>'
};
const state = {view:'', node:'', meta:null, manage:false, interval:2, memTotal:0, cores:1, range:'live', sort:'cpu', dayAt:0, last:null, loop:null};
let store = {live:blank(), day:blank()};
let PAL = {};

function blank(){ const o = {}; FIELDS.forEach(k => o[k] = []); return o; }

/* ---------- 格式化 ---------- */
const UNITS = ['B','KB','MB','GB','TB','PB'];
function fmtB(b){
  if (b == null || !isFinite(b)) return '—';
  let i = 0; b = Number(b);
  while (Math.abs(b) >= 1024 && i < UNITS.length - 1) { b /= 1024; i++; }
  return (i === 0 ? Math.round(b) : b.toFixed(b >= 100 ? 0 : 1)) + ' ' + UNITS[i];
}
const fmtR = b => fmtB(b) + '/s';
const fmtP = p => (p == null || !isFinite(p) ? '—' : Number(p).toFixed(1) + '%');
const fmtAxis = v => fmtB(v).replace('.0 ', ' ');
const pad = n => String(n).padStart(2, '0');
function fmtTime(t, mode){
  const d = new Date(t * 1000), hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
  if (mode === 's') return hm + ':' + pad(d.getSeconds());
  if (mode === 'd') return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + hm;
  return hm;
}
function fmtDate(t){ const d = new Date(t * 1000); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
function fmtDur(s){
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d) return d + ' 天 ' + h + ' 小时';
  if (h) return h + ' 小时 ' + m + ' 分';
  return m + ' 分 ' + (s % 60) + ' 秒';
}
function fmtAgo(t){
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return '刚刚';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}
const lvl = p => p >= 90 ? 'crit' : p >= 70 ? 'warn' : 'ok';
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function rgba(h, a){ const n = parseInt(h.slice(1), 16); return 'rgba(' + (n >> 16 & 255) + ',' + (n >> 8 & 255) + ',' + (n & 255) + ',' + a + ')'; }
function nice(max, base){
  let u = 1;
  if (base === 1024) while (max / u >= 1024) u *= 1024;
  const raw = max / u / 4, e = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / e;
  const step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e * u;
  return [Math.ceil(max / step - 1e-9) * step, step];
}
function nearest(a, v, lo){
  const base = lo; let hi = a.length - 1;
  if (hi < lo) return -1;
  while (lo < hi) { const m = (lo + hi) >> 1; if (a[m] < v) lo = m + 1; else hi = m; }
  if (lo > base && Math.abs(a[lo - 1] - v) < Math.abs(a[lo] - v)) lo--;
  return lo;
}

/* ---------- 主题 ---------- */
function readPalette(){
  const cs = getComputedStyle(document.documentElement), g = k => cs.getPropertyValue(k).trim();
  PAL = {grid:g('--grid'), faint:g('--faint'), cross:g('--border-strong'), panel:g('--panel'), dark:document.documentElement.dataset.theme !== 'light'};
}
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  $('themeBtn').innerHTML = t === 'dark' ? ICON.sun : ICON.moon;
  readPalette();
  Object.values(charts).forEach(c => c.draw());
}
$('themeBtn').addEventListener('click', () => {
  const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('probe-theme', t); } catch (e) {}
  applyTheme(t);
});
try {
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', e => {
    let saved = null; try { saved = localStorage.getItem('probe-theme'); } catch (_) {}
    if (!saved) applyTheme(e.matches ? 'light' : 'dark');
  });
} catch (e) {}

/* ---------- 网络请求：每个请求都有超时，切换页面时可整体取消 ---------- */
async function getJSON(u, signal){
  const c = new AbortController(), timer = setTimeout(() => c.abort(), 10000);
  const relay = () => c.abort();
  if (signal) { if (signal.aborted) c.abort(); else signal.addEventListener('abort', relay); }
  try {
    const r = await fetch(u, {cache:'no-store', credentials:'same-origin', signal:c.signal});
    if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
    return await r.json();
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', relay);
  }
}
async function send(method, u, body){
  const c = new AbortController(), timer = setTimeout(() => c.abort(), 15000);
  try {
    const r = await fetch(u, {method:method, credentials:'same-origin', headers:{'Content-Type':'application/json'},
                              body:JSON.stringify(body || {}), signal:c.signal});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  } catch (e) {
    throw e.name === 'AbortError' ? new Error('请求超时') : e;
  } finally { clearTimeout(timer); }
}
function setStatus(cls, text){ $('status').className = 'pill ' + cls; $('statusText').textContent = text; }

/* ---------- 轮询：同一时间只有一个有效轮询；页面不可见时暂停，省服务器资源 ---------- */
let loopId = 0, loopCtrl = null;
function stopLoop(){
  loopId++;
  if (loopCtrl) { loopCtrl.abort(); loopCtrl = null; }
}
function start(fn, iv){
  stopLoop();
  state.loop = [fn, iv];
  const id = loopId, ctrl = loopCtrl = new AbortController();
  let first = true;
  (async function run(){
    if (id !== loopId || (document.hidden && !first)) return;
    first = false;
    try { await fn(id, ctrl.signal); } catch (e) { if (e.name !== 'AbortError') console.error(e); }
    if (id === loopId) setTimeout(run, iv() * 1000);
  })();
}
function refresh(){ if (state.loop) start(state.loop[0], state.loop[1]); }
