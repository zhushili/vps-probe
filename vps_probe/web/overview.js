/* ---------- 总览 ---------- */
function meter(label, pct, value, title, color){
  const p = Math.max(0, Math.min(100, +pct || 0)), l = lvl(p);
  return '<div class="meter" title="' + esc(title) + '"><span class="ml">' + label + '</span><div class="bar"><i style="width:' + p.toFixed(1) + '%;--c:' +
    (l === 'ok' ? color : COL[l]) + '"></i></div><span class="mv">' + value + '</span></div>';
}
function nodeCard(n){
  const st = n.online ? 'on' : n.reported ? 'off' : 'wait', I = n.info || {};
  const sub = n.reported ? [I.os, I.virt].filter(Boolean).join(' · ') : '等待接入';
  let h = '<a class="card node ' + st + '" href="#/s/' + encodeURIComponent(n.id) + '"><div class="node-head"><span class="sdot ' + st + '"></span><div class="node-name"><b>' +
    esc(n.name) + '</b><span>' + esc(sub) + '</span></div>' + (n.local ? '<span class="badge">本机</span>' : '') + '</div>';
  if (!n.reported) return h + '<div class="node-empty">还没有收到这台服务器的数据<span>点击查看安装命令 →</span></div></a>';
  const on = n.online, mem = n.mem || [0, 0], memP = mem[1] ? mem[0] / mem[1] * 100 : 0, d = n.disk, cy = n.cycle || [0, 0];
  h += '<div class="meters">' +
    meter('CPU', on ? n.cpu : 0, on ? fmtP(n.cpu) : '—', '', COL.cpu) +
    meter('内存', memP, fmtP(memP), fmtB(mem[0]) + ' / ' + fmtB(mem[1]), COL.mem) +
    (d ? meter('磁盘', d[2], fmtP(d[2]), fmtB(d[0]) + ' / ' + fmtB(d[1]), COL.disk) : '') + '</div>';
  h += '<div class="node-stats"><div><small>↓ 下行</small><b>' + (on ? fmtR(n.rx) : '—') + '</b></div><div><small>↑ 上行</small><b>' + (on ? fmtR(n.tx) : '—') +
    '</b></div><div><small>本周期流量</small><b>' + fmtB(cy[0] + cy[1]) + '</b></div></div>';
  h += '<div class="node-foot"><span>' + (on ? '已运行 ' + fmtDur(n.uptime) : '离线 · ' + fmtAgo(n.last_seen)) + '</span><span>' +
    (I.cores ? Number(I.cores) + ' 核 · ' : '') + '负载 ' + Number(n.load || 0).toFixed(2) + '</span></div></a>';
  return h;
}
function renderOverview(r){
  state.manage = !!r.manage;
  const ns = r.nodes || [], on = ns.filter(n => n.online), warn = r.warnings || [];
  setStatus(on.length === ns.length ? 'online' : on.length ? 'partial' : 'offline', on.length + ' / ' + ns.length + ' 在线');
  $('subtitle').textContent = '服务器总览 · 共 ' + ns.length + ' 台';
  $('ovBanner').hidden = !warn.length;
  $('ovBanner').textContent = warn.join('；');
  $('sOnline').textContent = on.length + ' / ' + ns.length;
  $('sRx').textContent = fmtR(on.reduce((a, n) => a + (n.rx || 0), 0));
  $('sTx').textContent = fmtR(on.reduce((a, n) => a + (n.tx || 0), 0));
  $('sTraffic').textContent = fmtB(ns.reduce((a, n) => a + (n.cycle ? n.cycle[0] + n.cycle[1] : 0), 0));
  $('ovHint').textContent = state.manage ? '点击卡片查看详情' : '未设置访问密码，仅可查看';
  $('nodeGrid').innerHTML = ns.map(nodeCard).join('') +
    '<button type="button" class="card node add" data-act="add"><span class="plus">' + ICON.plus + '</span>添加服务器</button>';
  $('footL').textContent = 'VPS Probe v' + r.version + '  ·  单文件 · 零依赖';
  $('footR').textContent = '更新于 ' + fmtTime(Date.now() / 1000, 's');
}
async function pollNodes(id, signal){
  let r;
  try { r = await getJSON(api('nodes'), signal); }
  catch (e) { if (id === loopId) setStatus('offline', '连接中断'); return; }
  if (id === loopId && state.view === 'overview') renderOverview(r);
}
