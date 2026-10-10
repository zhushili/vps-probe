/* ---------- 路由 ---------- */
function showView(detail){
  $('vOverview').hidden = detail; $('vDetail').hidden = !detail;
  document.body.classList.toggle('ov', !detail);
  $('backBtn').hidden = !detail; $('logo').hidden = detail;
  $('addBtn').hidden = detail; $('setBtn').hidden = !detail;
  if (!detail) $('uptimePill').hidden = true;
}
function openOverview(){
  stopLoop();
  state.view = 'overview'; state.node = ''; state.meta = null;
  showView(false);
  $('title').textContent = 'VPS Probe'; document.title = '服务器总览 · VPS Probe';
  start(pollNodes, () => 2);
}
function openDetail(id){
  stopLoop();                       // 立即让旧的轮询和在途请求失效
  if (state.node !== id) {
    store = {live:blank(), day:blank()}; state.dayAt = 0; state.last = null; state.meta = null;
    $('vDetail').classList.add('loading'); $('title').textContent = '加载中…'; $('subtitle').textContent = '';
    $('waitCmd').dataset.node = ''; $('procBody').innerHTML = '';
    scrollTo(0, 0);
  }
  state.view = 'detail'; state.node = id;
  showView(true);
  drawCharts();
  const gen = loopId;
  loadHistory('live').then(() => {
    if (state.node !== id || loopId !== gen) return;
    start(pollDetail, () => state.interval);
    if (state.range === 'day') loadHistory('day');
  });
}
function route(){
  closeDlg();
  const m = location.hash.match(/^#\/s\/([\w-]+)$/);
  if (m) openDetail(m[1]); else openOverview();
}

/* ---------- 其他交互 ---------- */
function segSelect(seg, btn){ seg.querySelectorAll('button').forEach(b => b.classList.toggle('on', b === btn)); }
$('rangeSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  segSelect($('rangeSeg'), b); state.range = b.dataset.range;
  drawCharts();
  if (state.range === 'day' && Date.now() - state.dayAt > 60000) loadHistory('day');
});
$('procSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  segSelect($('procSeg'), b); state.sort = b.dataset.sort;
  if (state.last && state.last.info) renderProcs(state.last);
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  if (state.view === 'detail') { const id = state.node; loadHistory('live').then(() => { if (state.node === id) refresh(); }); }
  else refresh();
});
addEventListener('hashchange', route);
route();
