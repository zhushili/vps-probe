/* ---------- 折线图（原生 Canvas，无第三方依赖） ---------- */
class Chart {
  constructor(el, legend, o){
    this.el = el; this.lg = legend; this.o = o; this.d = null; this.hx = null; this.w = 0;
    this.cv = document.createElement('canvas'); this.ctx = this.cv.getContext('2d');
    this.tip = document.createElement('div'); this.tip.className = 'tip';
    el.append(this.cv, this.tip);
    const pos = e => { const r = this.cv.getBoundingClientRect(), p = e.touches ? e.touches[0] : e; this.hx = p.clientX - r.left; this.draw(); };
    const out = () => { this.hx = null; this.draw(); };
    this.cv.addEventListener('mousemove', pos);
    this.cv.addEventListener('mouseleave', out);
    this.cv.addEventListener('touchstart', pos, {passive:true});
    this.cv.addEventListener('touchmove', pos, {passive:true});
    this.cv.addEventListener('touchend', out);
    if (window.ResizeObserver) new ResizeObserver(() => this.resize()).observe(el);
    else addEventListener('resize', () => this.resize());
    this.resize();
  }
  resize(){
    const w = this.el.clientWidth, h = this.el.clientHeight, r = window.devicePixelRatio || 1;
    if (!w || !h) return;
    this.w = w; this.h = h;
    this.cv.width = Math.round(w * r); this.cv.height = Math.round(h * r);
    this.cv.style.width = w + 'px'; this.cv.style.height = h + 'px';
    this.ctx.setTransform(r, 0, 0, r, 0, 0);
    this.draw();
  }
  set(d, span, step, mode){
    this.d = d; this.span = span; this.step = step; this.mode = mode;
    const n = d.t.length, o = this.o;
    if (this.lg) this.lg.innerHTML = o.series.map(s => '<span><i style="background:' + COL[s.color] + '"></i>' + s.name + '<b>' + (n ? o.vfmt(d[s.key][n - 1]) : '—') + '</b></span>').join('');
    this.draw();
  }
  draw(){
    const {ctx, w, h, o, d} = this;
    if (!w || !d) return;
    ctx.clearRect(0, 0, w, h);
    const t = d.t, n = t.length;
    const t1 = n ? t[n - 1] : Date.now() / 1000, t0 = t1 - this.span;
    let i0 = 0; while (i0 < n && t[i0] < t0) i0++;

    let vmax = 0;
    for (const s of o.series) { const a = d[s.key]; for (let i = i0; i < n; i++) if (a[i] > vmax) vmax = a[i]; }
    let top, step;
    if (o.max) { top = o.max; step = o.max / 4; }
    else { const fl = typeof o.floor === 'function' ? o.floor() : (o.floor || 1); [top, step] = nice(Math.max(vmax * 1.15, fl), o.base); }
    const ticks = []; for (let k = 0; k * step <= top * 1.0001; k++) ticks.push(k * step);

    ctx.font = '11px ' + FONT;
    const labels = ticks.map(o.fmt);
    const L = Math.ceil(Math.max.apply(null, labels.map(s => ctx.measureText(s).width))) + 12, R = 6, T = 8, B = 24;
    const cw = w - L - R, ch = h - T - B;
    const X = v => L + (v - t0) / this.span * cw, Y = v => T + ch - v / top * ch;

    ctx.lineWidth = 1; ctx.strokeStyle = PAL.grid; ctx.fillStyle = PAL.faint;
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ticks.forEach((v, k) => {
      const y = Math.round(Y(v)) + .5;
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(w - R, y); ctx.stroke();
      ctx.fillText(labels[k], L - 8, y);
    });
    ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
    const xs = this.span <= 900 ? 120 : 14400, tz = new Date().getTimezoneOffset() * 60;
    for (let v = Math.ceil((t0 - tz) / xs) * xs + tz; v <= t1; v += xs) {
      const x = X(v); if (x < L + 18 || x > w - R - 18) continue;
      ctx.fillText(fmtTime(v), x, h - 6);
    }

    if (i0 >= n) {
      ctx.textBaseline = 'middle'; ctx.font = '12px ' + FONT;
      ctx.fillText(this.mode === 'd' ? '数据收集中，探针运行一段时间后显示' : '等待数据…', L + cw / 2, T + ch / 2);
      this.tip.style.opacity = 0; return;
    }

    const gap = this.step * 3.5;
    ctx.save(); ctx.beginPath(); ctx.rect(L, T - 2, cw + 2, ch + 3); ctx.clip();
    for (const s of o.series) {
      const a = d[s.key], c = COL[s.color], segs = []; let seg = [];
      for (let i = i0; i < n; i++) {
        if (seg.length && t[i] - t[i - 1] > gap) { segs.push(seg); seg = []; }
        seg.push([X(t[i]), Y(a[i])]);
      }
      if (seg.length) segs.push(seg);
      for (const sg of segs) {
        if (s.fill && sg.length > 1) {
          const g = ctx.createLinearGradient(0, T, 0, T + ch);
          g.addColorStop(0, rgba(c, PAL.dark ? .30 : .20)); g.addColorStop(1, rgba(c, 0));
          ctx.beginPath(); ctx.moveTo(sg[0][0], T + ch);
          sg.forEach(p => ctx.lineTo(p[0], p[1]));
          ctx.lineTo(sg[sg.length - 1][0], T + ch); ctx.closePath();
          ctx.fillStyle = g; ctx.fill();
        }
        ctx.beginPath(); sg.forEach((p, k) => k ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]));
        ctx.strokeStyle = c; ctx.lineWidth = s.fill ? 1.8 : 1.3; ctx.lineJoin = 'round'; ctx.lineCap = 'round'; ctx.stroke();
      }
    }
    ctx.restore();

    let hi = -1;
    if (this.hx != null && this.hx >= L && this.hx <= w - R) hi = nearest(t, t0 + (this.hx - L) / cw * this.span, i0);
    if (hi < 0) { this.tip.style.opacity = 0; return; }
    const x = Math.round(X(t[hi])) + .5;
    ctx.strokeStyle = PAL.cross; ctx.setLineDash([3, 3]);
    ctx.beginPath(); ctx.moveTo(x, T); ctx.lineTo(x, T + ch); ctx.stroke(); ctx.setLineDash([]);
    for (const s of o.series) {
      ctx.beginPath(); ctx.arc(x, Y(d[s.key][hi]), 3.5, 0, Math.PI * 2);
      ctx.fillStyle = COL[s.color]; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = PAL.panel; ctx.stroke();
    }
    this.tip.innerHTML = '<div class="tt">' + fmtTime(t[hi], this.mode) + '</div>' + o.series.map(s =>
      '<div class="tr"><i style="background:' + COL[s.color] + '"></i><span>' + s.name + '</span><b>' + o.vfmt(d[s.key][hi]) + '</b></div>').join('');
    const tw = this.tip.offsetWidth; let lx = x + 14;
    if (lx + tw > w) lx = x - 14 - tw;
    this.tip.style.left = Math.max(0, lx) + 'px'; this.tip.style.top = T + 'px'; this.tip.style.opacity = 1;
  }
}

/* ---------- 环形仪表 ---------- */
function mkRing(id, color){
  const el = $(id), c = RING_C.toFixed(2);
  el.innerHTML = '<svg viewBox="0 0 80 80"><circle class="bg" cx="40" cy="40" r="34"/><circle class="fg" cx="40" cy="40" r="34" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '" stroke="' + color + '"/></svg><div class="ring-val"><span>0</span><small>%</small></div>';
  return {fg:el.querySelector('.fg'), v:el.querySelector('span'), c:color};
}
function setRing(r, p){
  p = Math.max(0, Math.min(100, +p || 0));
  r.fg.style.strokeDashoffset = (RING_C * (1 - p / 100)).toFixed(2);
  const l = lvl(p); r.fg.style.stroke = l === 'ok' ? r.c : COL[l];
  r.v.textContent = p < 10 ? p.toFixed(1) : Math.round(p);
}
const rings = {cpu:mkRing('ringCpu', COL.cpu), mem:mkRing('ringMem', COL.mem), disk:mkRing('ringDisk', COL.disk)};

readPalette();
$('themeBtn').innerHTML = PAL.dark ? ICON.sun : ICON.moon;
const charts = {
  cpu: new Chart($('chCpu'), $('lgCpu'), {max:100, fmt:v => Math.round(v) + '%', vfmt:fmtP,
    series:[{key:'cpu', name:'使用率', color:'cpu', fill:1}, {key:'iowait', name:'IO 等待', color:'iowait'}, {key:'steal', name:'窃取', color:'steal'}]}),
  mem: new Chart($('chMem'), $('lgMem'), {base:1024, floor:() => state.memTotal || 1048576, fmt:fmtAxis, vfmt:v => fmtB(v),
    series:[{key:'mem', name:'已用', color:'mem', fill:1}, {key:'cache', name:'缓存', color:'cache'}, {key:'swap', name:'Swap', color:'swap'}]}),
  net: new Chart($('chNet'), $('lgNet'), {base:1024, floor:1024, fmt:v => fmtAxis(v) + '/s', vfmt:fmtR,
    series:[{key:'rx', name:'下行', color:'rx', fill:1}, {key:'tx', name:'上行', color:'tx', fill:1}]}),
  io: new Chart($('chIo'), $('lgIo'), {base:1024, floor:1024, fmt:v => fmtAxis(v) + '/s', vfmt:fmtR,
    series:[{key:'rd', name:'读取', color:'rd', fill:1}, {key:'wr', name:'写入', color:'wr', fill:1}]}),
};
function drawCharts(){
  const live = state.range === 'live';
  Object.values(charts).forEach(c => c.set(store[state.range], live ? 600 : 86400, live ? state.interval : 60, live ? 's' : 'd'));
}
