/* ---------- 单台服务器详情 ---------- */
function renderDetail(s){
  const nd = s.node;
  state.meta = nd; state.manage = !!s.manage;
  $('title').textContent = nd.name; document.title = nd.name + ' · VPS Probe';
  $('vDetail').classList.remove('loading');
  if (!s.info) {
    setStatus('partial', '等待接入');
    $('subtitle').textContent = '还没有收到这台服务器的数据';
    $('uptimePill').hidden = true; $('detailBody').hidden = true; $('offBanner').hidden = true; $('waitCard').hidden = false;
    $('footR').textContent = '添加于本面板，等待首次上报';
    renderWaiting(nd);
    return;
  }
  $('waitCard').hidden = true; $('detailBody').hidden = false; $('uptimePill').hidden = false;
  setStatus(nd.online ? 'online' : 'offline', nd.online ? '在线' : '离线');
  $('offBanner').hidden = nd.online;
  if (!nd.online) $('offBanner').textContent = '这台服务器已离线，最后上报于 ' + fmtDate(nd.last_seen) + '（' + fmtAgo(nd.last_seen) + '），下面显示的是最后一次的数据。';
  renderMetrics(s);
  if (nd.online) appendLive(s);
  if (state.range === 'live') drawCharts();
  else if (Date.now() - state.dayAt > 60000) loadHistory('day');
}

function renderMetrics(s){
  const I = s.info, nd = s.node, cpu = s.cpu, m = s.mem, n = s.net, c = s.conn;
  state.interval = s.probe.interval || 2; state.memTotal = m.total; state.cores = I.cores || 1;
  $('subtitle').textContent = [I.hostname !== nd.name ? I.hostname : '', I.os, I.kernel, I.arch, I.virt].filter(Boolean).join('  ·  ');
  $('uptime').textContent = '已运行 ' + fmtDur(s.uptime);

  setRing(rings.cpu, cpu.pct);
  $('cpuCores').textContent = I.cores + ' 核';
  $('cpuLoad').textContent = cpu.load.length ? cpu.load.map(x => Number(x).toFixed(2)).join(' / ') : '—';
  $('cpuUS').textContent = fmtP(cpu.user) + ' / ' + fmtP(cpu.system);
  $('cpuWS').textContent = fmtP(cpu.iowait) + ' / ' + fmtP(cpu.steal);

  setRing(rings.mem, m.total ? m.used / m.total * 100 : 0);
  $('memTotal').textContent = '共 ' + fmtB(m.total);
  $('memUsed').textContent = fmtB(m.used);
  $('memCache').textContent = fmtB(m.cache);
  $('memSwap').textContent = m.swap_total ? fmtB(m.swap_used) + ' / ' + fmtB(m.swap_total) : '未启用';

  const root = s.disks.find(d => d.mount === '/') || s.disks[0];
  if (root) {
    setRing(rings.disk, root.pct);
    $('diskBadge').textContent = root.mount + ' · 共 ' + fmtB(root.total);
    $('diskUsed').textContent = fmtB(root.used);
    $('diskFree').textContent = fmtB(root.free);
  }
  $('diskIO').textContent = fmtR(s.io.read) + ' / ' + fmtR(s.io.write);

  const main = n.ifaces.slice().sort((a, b) => (b.rx_total + b.tx_total) - (a.rx_total + a.tx_total))[0];
  $('netBadge').textContent = main ? main.name : '—';
  $('netRx').textContent = fmtR(n.rx);
  $('netTx').textContent = fmtR(n.tx);
  $('netCRx').textContent = fmtB(n.cycle_rx);
  $('netCTx').textContent = fmtB(n.cycle_tx);
  $('netConn').textContent = c.established + ' / ' + c.tcp;

  renderInfo(s); renderNet(s); renderDisks(s); renderProcs(s);
  $('footL').textContent = 'VPS Probe v' + I.version + '  ·  单文件 · 零依赖';
  $('footR').textContent = '采样间隔 ' + state.interval + 's  ·  更新于 ' + fmtTime(s.ts, 's');
}

function renderInfo(s){
  const I = s.info, p = s.proc;
  const rows = [
    ['主机名', I.hostname], ['操作系统', I.os], ['内核', I.kernel + ' (' + I.arch + ')'], ['虚拟化', I.virt],
    ['处理器', I.cpu_model], ['核心数', I.cores + ' 核'], ['启动时间', fmtDate(s.ts - s.uptime)],
    ['运行时长', fmtDur(s.uptime)], ['进程 / 线程', p.count + ' / ' + p.threads],
    ['探针', 'v' + I.version + ' · Python ' + I.python + ' · 占用 ' + fmtB(s.probe.rss)]
  ];
  $('sysinfo').innerHTML = rows.map(r => '<div><dt>' + r[0] + '</dt><dd>' + esc(r[1]) + '</dd></div>').join('');
}

function renderNet(s){
  const n = s.net, c = s.conn, pc = n.prev_cycle;
  $('cycleSince').textContent = '统计周期自 ' + n.cycle_start + ' 起' + (pc ? ' · 上周期 ' + fmtB(pc.rx + pc.tx) : '');
  $('tRx').textContent = fmtB(n.cycle_rx);
  $('tTx').textContent = fmtB(n.cycle_tx);
  $('tSum').textContent = fmtB(n.cycle_rx + n.cycle_tx);
  $('cTcp').textContent = c.tcp; $('cEst').textContent = c.established;
  $('cTw').textContent = c.time_wait; $('cUdp').textContent = c.udp;
  $('ifBody').innerHTML = n.ifaces.length ? n.ifaces.map(i =>
    '<tr><td class="mono">' + esc(i.name) + '</td><td class="r">' + fmtR(i.rx) + '</td><td class="r">' + fmtR(i.tx) +
    '</td><td class="r muted">' + fmtB(i.rx_total) + ' / ' + fmtB(i.tx_total) + '</td></tr>').join('')
    : '<tr><td colspan="4" class="empty">没有检测到网卡</td></tr>';
  $('netNote').textContent = '统计口径：' + (n.iface_rule || '统计所有物理网卡') + '。可通过 PROBE_IFACES 指定网卡；数据仅供参考，不等同于服务商计费。';
}

function renderDisks(s){
  $('disks').innerHTML = s.disks.length ? s.disks.map(d => {
    const pct = Number(d.pct) || 0, l = lvl(pct), c = l === 'ok' ? COL.disk : COL[l];
    return '<div class="disk"><div class="disk-top"><span><span class="mp">' + esc(d.mount) + '</span><span class="fs">' + esc(d.fs) + ' · ' + esc(d.device) +
      '</span></span><span class="pct">' + pct.toFixed(1) + '%</span></div><div class="bar lg"><i style="width:' + pct + '%;--c:' + c +
      '"></i></div><div class="disk-bot"><span>已用 ' + fmtB(d.used) + '</span><span>可用 ' + fmtB(d.free) + ' / 共 ' + fmtB(d.total) + '</span></div></div>';
  }).join('') : '<div class="muted">没有检测到磁盘分区</div>';
}

function cellbar(text, pct, color){
  return '<div class="cellbar"><span>' + text + '</span><div class="bar"><i style="width:' + Math.min(100, Math.max(0, pct || 0)).toFixed(1) + '%;--c:' + color + '"></i></div></div>';
}
function renderProcs(s){
  const p = s.proc;
  $('procSummary').textContent = '共 ' + p.count + ' 个进程 · ' + p.threads + ' 个线程' + (p.running != null ? ' · ' + p.running + ' 个运行中' : '');
  const rows = state.sort === 'mem' ? p.top_mem : p.top_cpu, tb = $('procBody');
  if (!rows) {
    tb.innerHTML = '<tr><td colspan="5" class="empty">' + (state.meta && !state.meta.online ? '服务器离线' : '正在采集进程信息…') + '</td></tr>';
    return;
  }
  tb.innerHTML = rows.map(r => {
    const mp = state.memTotal ? r.rss / state.memTotal * 100 : 0, cpu = Number(r.cpu) || 0;
    const cmd = r.cmd ? esc(r.cmd) : '[内核线程]';
    return '<tr><td class="mono muted">' + (Number(r.pid) || 0) + '</td><td class="pn"><div><span class="pname">' + esc(r.name) + '</span><span class="cmd" title="' + cmd + '">' + cmd +
      '</span></div></td><td class="r">' + cellbar(cpu.toFixed(1) + '%', cpu / state.cores, COL.cpu) +
      '</td><td class="r">' + cellbar(fmtB(r.rss), mp, COL.mem) + '</td><td class="r hide-sm muted">' + (Number(r.threads) || 0) + '</td></tr>';
  }).join('');
}

async function renderWaiting(nd){
  const box = $('waitCmd');
  if (!state.manage) { box.innerHTML = '<p class="muted" style="text-align:center">面板未设置访问密码，无法显示安装命令。</p>'; box.dataset.node = ''; return; }
  if (box.dataset.node === nd.id) return;
  box.dataset.node = nd.id; box.innerHTML = '';
  try {
    const info = await getJSON(api('nodes/' + encodeURIComponent(nd.id) + '/secret'));
    if (state.node === nd.id) box.innerHTML = installBlock(info);
  } catch (e) { box.dataset.node = ''; box.innerHTML = '<p class="muted">获取安装命令失败：' + esc(e.message) + '</p>'; }
}

let histCtrl = null;
async function loadHistory(r){
  const node = state.node;
  if (histCtrl) histCtrl.abort();
  const ctrl = histCtrl = new AbortController();
  try {
    const j = await getJSON(api('history?node=' + encodeURIComponent(node) + '&range=' + r), ctrl.signal), o = {};
    if (node !== state.node) return;
    FIELDS.forEach(k => o[k] = j[k] || []);
    store[r] = o;
    if (r === 'day') state.dayAt = Date.now();
  } catch (e) { if (e.name !== 'AbortError') console.warn('history', e); }
  if (r === state.range && node === state.node) drawCharts();
}
function appendLive(s){
  const d = store.live, t = Math.floor(s.ts);
  if (d.t.length && t <= d.t[d.t.length - 1]) return;
  const p = {t:t, cpu:s.cpu.pct, steal:s.cpu.steal, iowait:s.cpu.iowait, mem:s.mem.used, cache:s.mem.cache, swap:s.mem.swap_used,
             rx:s.net.rx, tx:s.net.tx, rd:s.io.read, wr:s.io.write};
  FIELDS.forEach(k => d[k].push(p[k]));
  while (d.t.length && d.t[0] < t - 600) FIELDS.forEach(k => d[k].shift());
}
async function pollDetail(id, signal){
  const node = state.node;
  let s;
  try { s = await getJSON(api('stats?node=' + encodeURIComponent(node)), signal); }
  catch (e) {
    if (id !== loopId || e.name === 'AbortError') return;
    if (e.status === 404) { location.hash = '#/'; return; }
    setStatus('offline', '连接中断'); return;
  }
  // 只渲染“当前轮询 + 当前选中的服务器”的响应，切换服务器后旧响应一律丢弃
  if (id !== loopId || node !== state.node || !s.node || s.node.id !== node) return;
  state.last = s;
  renderDetail(s);
}
