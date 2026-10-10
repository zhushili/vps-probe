/* ---------- 安装命令 ---------- */
const PLAIN_HTTP = location.protocol === 'http:' && !/^(localhost|127\.|\[::1\])/.test(location.hostname);
function installCmd(info, plainHttp){
  // 从面板下载与面板相同版本的源码包，校验 SHA-256 后安装；HTTP 面板需要先确认是可信网络
  return 'd=$(mktemp -d) && curl -fsSL ' + BASE + '/vps-probe.tar.gz -o $d/p.tgz && echo "' + info.sha256 +
    '  $d/p.tgz" | sha256sum -c --quiet - && tar -xzf $d/p.tgz -C $d && (cd $d && python3 -m vps_probe install --agent=' +
    BASE + ' --token=' + info.token + (plainHttp ? ' --allow-http' : '') + '); rm -rf $d';
}
const uninstallCmd = () => 'vps-probe uninstall';
function cmdBlock(cmd){
  return '<div class="code">' + esc(cmd) + '</div><div class="row-end"><button type="button" class="btn" data-act="copy" data-text="' + esc(cmd) + '">' + ICON.copy + '<span>复制命令</span></button></div>';
}
function installBlock(info){
  const hints = '<ul class="hints"><li>以 root 身份执行（普通用户先运行 <code>sudo -i</code>）；需要 Python 3.8+ 和 systemd</li>' +
    '<li>下载的文件会先做 SHA-256 校验，不一致不会执行</li><li>子服务器不需要开放端口，执行完几秒后就会出现在面板上</li></ul>';
  if (!PLAIN_HTTP) return cmdBlock(installCmd(info, false)) + hints;
  return '<div class="warnbox"><b>面板正在使用 HTTP</b><p>安装文件、token 和监控数据都会以明文传输。公网环境请先在面板服务器上运行 <code>vps-probe</code>，选择「配置域名和 HTTPS」，再从 HTTPS 地址打开面板添加服务器。</p>' +
    '<label class="check"><input type="checkbox" data-trust> 面板与这台服务器之间是可信网络（内网 / 专线 / VPN），允许使用 HTTP</label></div>' +
    '<div class="trusted" hidden>' + cmdBlock(installCmd(info, true)) + hints + '</div>';
}
document.addEventListener('change', e => {
  if (!e.target.matches('[data-trust]')) return;
  const box = e.target.closest('.warnbox').nextElementSibling;
  if (box) box.hidden = !e.target.checked;
});

/* ---------- 对话框：添加 / 设置 / 更换 token / 删除。打开时绑定服务器，操作只作用于这台 ---------- */
const dlg = $('dlg');
let dlgNode = null;                 // 对话框打开时绑定的服务器 {id, name, local, reset_day}
function dlgHead(title, sub){
  return '<div class="dlg-head"><div><h3 id="dlgTitle">' + title + '</h3>' + (sub ? '<p>' + sub + '</p>' : '') +
    '</div><button type="button" class="icon-btn" data-act="close" aria-label="关闭">' + ICON.x + '</button></div>';
}
function openDlg(html){
  dlg.innerHTML = html;
  if (!dlg.open) dlg.showModal();
  const f = dlg.querySelector('input:not([type=checkbox])'); if (f) f.focus();
}
function closeDlg(){ if (dlg.open) dlg.close(); }
function showErr(msg){ const e = dlg.querySelector('.err'); if (e) { e.textContent = msg; e.hidden = false; } }
const fval = (f, n) => f.querySelector('[name="' + n + '"]').value;
const nodeUrl = (id, sub) => api('nodes/' + encodeURIComponent(id) + (sub || ''));

function dlgNoManage(){
  openDlg(dlgHead('需要先设置访问密码') + '<div class="dlg-body"><p class="muted">为了安全，面板没有设置访问密码时，不能在网页上添加或修改服务器。</p>' +
    '<p class="muted">在面板服务器上运行 <code>vps-probe</code>，选择「安装面板 / 修改面板配置」设置密码即可。</p></div>' +
    '<div class="dlg-foot"><button type="button" class="btn primary" data-act="close">知道了</button></div>');
}
function dlgAdd(){
  if (!state.manage) return dlgNoManage();
  openDlg(dlgHead('添加服务器', '添加后会生成一条安装命令，在要监控的服务器上执行即可。') +
    '<form data-act="create"><div class="dlg-body">' +
    '<label class="field"><span>名称</span><input name="name" maxlength="40" required autocomplete="off" placeholder="例如：香港 CN2 · 2C2G"></label>' +
    '<label class="field"><span>月流量重置日</span><input name="reset_day" type="number" min="1" max="28" value="1" required><small>每月几号开始重新统计流量，和服务商的账单日保持一致即可</small></label>' +
    '<div class="err" hidden></div></div><div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="submit" class="btn primary">添加</button></div></form>');
}
function dlgInstall(info, title){
  openDlg(dlgHead(title, '在这台服务器上执行：') + '<div class="dlg-body">' + installBlock(info) + '</div>' +
    '<div class="dlg-foot"><button type="button" class="btn primary" data-act="close">完成</button></div>');
}
function dlgSettings(){
  if (!state.manage) return dlgNoManage();
  if (!state.meta || state.meta.id !== state.node) return;
  const nd = dlgNode = Object.assign({}, state.meta);
  const grace = nd.token_grace_until > Date.now() / 1000 ? '<small>旧 token 在 ' + fmtDate(nd.token_grace_until) + ' 前仍然有效</small>' : '';
  openDlg(dlgHead('服务器设置', nd.local ? '本机（面板所在的服务器）' : '') +
    '<form data-act="save"><div class="dlg-body">' +
    '<label class="field"><span>名称</span><input name="name" maxlength="40" required autocomplete="off" value="' + esc(nd.name) + '"></label>' +
    '<label class="field"><span>月流量重置日</span><input name="reset_day" type="number" min="1" max="28" required value="' + (Number(nd.reset_day) || 1) + '"><small>修改后会从新的统计周期重新开始累计</small></label>' +
    (nd.local ? '' : '<div class="field"><span>子服务器</span><div class="btn-row"><button type="button" class="btn" data-act="showInstall">查看安装命令</button>' +
      '<button type="button" class="btn" data-act="askRotate">更换 token</button><button type="button" class="btn danger" data-act="askDelete">删除服务器</button></div>' + grace + '</div>') +
    '<div class="err" hidden></div></div><div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="submit" class="btn primary">保存</button></div></form>');
}
function dlgRotate(){
  const nd = dlgNode; if (!nd) return;
  openDlg(dlgHead('更换「' + esc(nd.name) + '」的 token', '更换后需要在这台服务器上重新执行安装命令，历史数据会保留。') +
    '<div class="dlg-body"><label class="check"><input type="checkbox" id="graceChk" checked> 旧 token 再保留 1 小时，期间新旧 token 都有效，便于平滑切换</label>' +
    '<p class="muted">如果 token 已经泄露，请取消勾选，旧 token 会立即失效。</p><div class="err" hidden></div></div>' +
    '<div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="button" class="btn primary" data-act="doRotate">更换</button></div>');
}
function dlgDelete(){
  const nd = dlgNode; if (!nd) return;
  openDlg(dlgHead('删除「' + esc(nd.name) + '」？', '面板上这台服务器的历史数据会一起删除，无法恢复。') +
    '<div class="dlg-body"><p class="muted">删除后这台服务器的上报会被拒绝。如需彻底卸载，请在它上面执行：</p>' + cmdBlock(uninstallCmd()) + '<div class="err" hidden></div></div>' +
    '<div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="button" class="btn danger solid" data-act="doDelete">确认删除</button></div>');
}
async function copyText(text, btn){
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {}
  if (!ok) {   // HTTP 页面没有剪贴板 API，用老办法
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    (btn.closest('dialog') || document.body).appendChild(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch (e) {}
    ta.remove();
  }
  const sp = btn.querySelector('span');
  if (sp) { sp.textContent = ok ? '已复制' : '复制失败，请手动选择'; setTimeout(() => { sp.textContent = '复制命令'; }, 1600); }
}

const SUBMIT = {
  async create(f){
    const b = f.querySelector('[type=submit]'); b.disabled = true;
    try {
      const info = await send('POST', api('nodes'), {name:fval(f, 'name').trim(), reset_day:parseInt(fval(f, 'reset_day'), 10)});
      dlgInstall(info, '已添加「' + esc(info.name) + '」'); refresh();
    } catch (e) { showErr(e.message); b.disabled = false; }
  },
  async save(f){
    const b = f.querySelector('[type=submit]'), nd = dlgNode; b.disabled = true;
    try {
      await send('POST', nodeUrl(nd.id), {name:fval(f, 'name').trim(), reset_day:parseInt(fval(f, 'reset_day'), 10)});
      closeDlg(); refresh();
    } catch (e) { showErr(e.message); b.disabled = false; }
  }
};
const ACT = {
  close: closeDlg,
  add: dlgAdd,
  settings: dlgSettings,
  askDelete: dlgDelete,
  askRotate: dlgRotate,
  copy: b => copyText(b.dataset.text, b),
  async showInstall(b){
    const nd = dlgNode; b.disabled = true;
    try { dlgInstall(await getJSON(nodeUrl(nd.id, '/secret')), '「' + esc(nd.name) + '」的安装命令'); }
    catch (e) { showErr('获取失败：' + e.message); b.disabled = false; }
  },
  async doRotate(b){
    const nd = dlgNode; b.disabled = true;
    try {
      const info = await send('POST', nodeUrl(nd.id, '/token'), {grace: $('graceChk').checked ? 3600 : 0});
      dlgInstall(info, '已更换「' + esc(nd.name) + '」的 token');
    } catch (e) { showErr(e.message); b.disabled = false; }
  },
  async doDelete(b){
    const nd = dlgNode; b.disabled = true;
    try {
      await send('DELETE', nodeUrl(nd.id));
      closeDlg();
      if (state.node === nd.id) location.hash = '#/'; else refresh();
    } catch (e) { showErr(e.message); b.disabled = false; }
  }
};
document.addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (!b || b.tagName === 'FORM' || !ACT[b.dataset.act]) return;
  e.preventDefault(); ACT[b.dataset.act](b);
});
dlg.addEventListener('click', e => { if (e.target === dlg) closeDlg(); });
dlg.addEventListener('submit', e => { e.preventDefault(); const fn = SUBMIT[e.target.dataset.act]; if (fn) fn(e.target); });
