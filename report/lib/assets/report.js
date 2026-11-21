function selectTab(name, push = true) {
  if (!document.getElementById('tab-' + name)) return;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === name);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === 'tab-' + name);
  });
  const sel = document.getElementById('worker-tab-select');
  const wrap = document.getElementById('worker-nav-wrap');
  const dot = document.getElementById('worker-nav-dot');
  if (sel) {
    const opt = Array.from(sel.options).find(o => o.value === name);
    sel.value = opt ? name : '';
    if (wrap) wrap.classList.toggle('has-active', !!opt);
    if (dot) dot.style.background = (opt && opt.dataset.color) ? opt.dataset.color : '#64748b';
  }
  const targetHash = '#' + encodeURIComponent(name);
  if (push && window.location.hash !== targetHash && history.pushState) {
    history.pushState({ tab: name }, '', targetHash);
    window.scrollTo({ top: 0, behavior: 'instant' });
  }
}

function stepWorkerTab(delta) {
  const sel = document.getElementById('worker-tab-select');
  if (!sel) return;
  const vals = Array.from(sel.options).filter(o => o.value).map(o => o.value);
  if (!vals.length) return;
  const idx = vals.indexOf(sel.value);
  let nextIdx;
  if (idx === -1) {
    nextIdx = delta >= 0 ? 0 : vals.length - 1;
  } else {
    nextIdx = (idx + delta + vals.length) % vals.length;
  }
  selectTab(vals[nextIdx]);
}

function copyTopologyJson(btn) {
  const pre = document.getElementById('topology-json-pre');
  if (!pre) return;
  const txt = pre.textContent;
  const markDone = () => {
    if (!btn) return;
    const prev = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = prev; }, 1600);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(markDone).catch(() => {});
  }
}

function downloadTopologyJson(name) {
  const pre = document.getElementById('topology-json-pre');
  if (!pre) return;
  const blob = new Blob([pre.textContent], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = (name || 'topology') + '.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatDuration(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
  if (m > 0) return m + 'm ' + String(s).padStart(2, '0') + 's';
  return s + 's';
}

function escapeHtml(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

document.querySelectorAll('.chart-card[data-series]').forEach(card => {
  const series = JSON.parse(card.dataset.series || '[]');
  const minX = parseFloat(card.dataset.minX);
  const maxX = parseFloat(card.dataset.maxX);
  const padL = parseFloat(card.dataset.padL);
  const plotW = parseFloat(card.dataset.plotW);
  const svg = card.querySelector('.plot-svg');
  const hoverLine = card.querySelector('.hover-line');
  const hoverDot = card.querySelector('.hover-dot');
  const lineBadge = card.querySelector('.line-badge');
  const tooltip = card.querySelector('.chart-tooltip');
  const groups = Array.from(card.querySelectorAll('.series-group'));
  const legendItems = Array.from(card.querySelectorAll('.legend-item'));
  if (!svg || !series.length) return;

  let pinnedSeries = null;

  function highlightSeries(activeName) {
    if (groups.length <= 1) return;
    groups.forEach(g => {
      const match = g.dataset.seriesName === activeName;
      g.classList.toggle('active', !!activeName && match);
      g.classList.toggle('dimmed', !!activeName && !match);
      if (match && activeName && g.parentNode) {
        g.parentNode.appendChild(g);
        if (hoverLine) g.parentNode.appendChild(hoverLine);
        if (hoverDot) g.parentNode.appendChild(hoverDot);
      }
    });
    legendItems.forEach(item => {
      const match = item.dataset.seriesName === activeName;
      item.classList.toggle('active', !!activeName && match);
      item.classList.toggle('dimmed', !!activeName && !match);
    });
  }

  legendItems.forEach(item => {
    const sName = item.dataset.seriesName;
    item.addEventListener('mouseenter', () => highlightSeries(sName));
    item.addEventListener('mouseleave', () => highlightSeries(pinnedSeries));
    item.addEventListener('click', () => {
      pinnedSeries = (pinnedSeries === sName) ? null : sName;
      highlightSeries(pinnedSeries);
    });
  });

  svg.addEventListener('mousemove', e => {
    const rect = svg.getBoundingClientRect();
    const scaleX = 580 / rect.width;
    const scaleY = 270 / rect.height;
    const svgX = (e.clientX - rect.left) * scaleX;
    const svgY = (e.clientY - rect.top) * scaleY;
    if (svgX < padL || svgX > padL + plotW) {
      hoverLine.style.display = 'none';
      hoverDot.style.display = 'none';
      lineBadge.style.display = 'none';
      tooltip.style.display = 'none';
      highlightSeries(pinnedSeries);
      return;
    }
    const ratio = (svgX - padL) / plotW;
    const targetT = minX + ratio * (maxX - minX);

    hoverLine.setAttribute('x1', svgX.toFixed(1));
    hoverLine.setAttribute('x2', svgX.toFixed(1));
    hoverLine.style.display = '';

    // Determine closest series at this time slice (or directly hovered path)
    const directHit = e.target.closest('.series-hit');
    let hoveredSeriesName = directHit ? directHit.dataset.seriesName : null;
    let closestPointBySeries = {};
    let minVerticalDist = Infinity;
    let nearestSeries = null;

    series.forEach(s => {
      if (!s.points.length) return;
      let best = s.points[0];
      let bestDist = Math.abs(best[0] - targetT);
      for (let i = 1; i < s.points.length; i++) {
        const d = Math.abs(s.points[i][0] - targetT);
        if (d < bestDist) { bestDist = d; best = s.points[i]; }
      }
      closestPointBySeries[s.name] = { series: s, point: best };
      const vDist = Math.abs(best[3] - svgY);
      if (vDist < minVerticalDist) {
        minVerticalDist = vDist;
        nearestSeries = s.name;
      }
    });

    if (!hoveredSeriesName && minVerticalDist <= 28) {
      hoveredSeriesName = nearestSeries;
    }
    const activeName = pinnedSeries || hoveredSeriesName || (series.length === 1 ? series[0].name : null);
    highlightSeries(activeName);

    if (activeName && closestPointBySeries[activeName]) {
      const activeInfo = closestPointBySeries[activeName];
      const pt = activeInfo.point;
      const ptSvgX = padL + ((pt[0] - minX) / (maxX - minX)) * plotW;
      const ptSvgY = pt[3];
      hoverDot.setAttribute('cx', ptSvgX.toFixed(1));
      hoverDot.setAttribute('cy', ptSvgY.toFixed(1));
      hoverDot.setAttribute('fill', activeInfo.series.color);
      hoverDot.style.display = '';

      const badgeLeft = (ptSvgX / 580) * rect.width;
      const badgeTop = (ptSvgY / 270) * rect.height;
      lineBadge.style.left = Math.min(Math.max(badgeLeft, 50), rect.width - 60) + 'px';
      lineBadge.style.top = Math.max(badgeTop, 28) + 'px';
      lineBadge.innerHTML = '<span class="legend-dot" style="background:' + escapeHtml(activeInfo.series.color) + '"></span>' +
        '<span>' + escapeHtml(activeInfo.series.name) + ': <strong>' + escapeHtml(pt[2]) + '</strong></span>';
      lineBadge.style.display = 'flex';
    } else {
      hoverDot.style.display = 'none';
      lineBadge.style.display = 'none';
    }

    let html = '<div class="tt-time">t = ' + formatDuration(targetT) + '</div>';
    const sortedSeries = series
      .filter(s => closestPointBySeries[s.name])
      .slice()
      .sort((a, b) => {
        const va = closestPointBySeries[a.name].point[1];
        const vb = closestPointBySeries[b.name].point[1];
        return vb - va;
      });
    sortedSeries.forEach(s => {
      const info = closestPointBySeries[s.name];
      const isAct = s.name === activeName;
      html += '<div class="tt-row' + (isAct ? ' active' : '') + '">' +
        '<span><span class="legend-dot" style="background:' + escapeHtml(s.color) + '"></span> ' + escapeHtml(s.name) + '</span>' +
        '<strong>' + escapeHtml(info.point[2]) + '</strong></div>';
    });
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
  });

  svg.addEventListener('mouseleave', () => {
    hoverLine.style.display = 'none';
    hoverDot.style.display = 'none';
    lineBadge.style.display = 'none';
    tooltip.style.display = 'none';
    highlightSeries(pinnedSeries);
  });
});

function applyHashTab() {
  const hash = decodeURIComponent(window.location.hash.replace(/^#/, '')) || 'overview';
  if (document.getElementById('tab-' + hash)) {
    selectTab(hash, false);
  }
}

function toggleHunkDrawer(id) {
  const row = document.getElementById(id);
  if (!row) return;
  const isHidden = row.style.display === 'none' || !row.style.display;
  row.style.display = isHidden ? 'table-row' : 'none';
  if (isHidden) {
    row.querySelectorAll('.origin-hunk-group').forEach(g => { g.style.display = 'block'; });
  }
  const caret = document.getElementById('caret-' + id);
  if (caret) caret.innerHTML = isHidden ? '&#9662;' : '&#9656;';
}

function toggleAllHunks(btn, prefix) {
  const rows = Array.from(document.querySelectorAll('.hunk-drawer-row')).filter(r => r.id && r.id.startsWith(prefix));
  const anyHidden = rows.some(r => r.style.display === 'none' || !r.style.display);
  rows.forEach(row => {
    row.style.display = anyHidden ? 'table-row' : 'none';
    if (anyHidden) {
      row.querySelectorAll('.origin-hunk-group').forEach(g => { g.style.display = 'block'; });
    }
    const caret = document.getElementById('caret-' + row.id);
    if (caret) caret.innerHTML = anyHidden ? '&#9662;' : '&#9656;';
  });
  if (btn) {
    const collapseLabel = (btn.dataset && btn.dataset.collapseLabel) || 'Collapse All';
    const expandLabel = (btn.dataset && btn.dataset.expandLabel) || 'Expand All';
    btn.textContent = anyHidden ? collapseLabel : expandLabel;
  }
}

function toggleExtraTableRows(btn, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const extras = Array.from(tbody.querySelectorAll('tr.extra-toggle-row'));
  const anyHidden = extras.some(r => r.style.display === 'none' || !r.style.display);
  extras.forEach(r => {
    r.style.display = anyHidden ? 'table-row' : 'none';
    if (!anyHidden && r.dataset.drawerId) {
      const drawer = document.getElementById(r.dataset.drawerId);
      if (drawer) drawer.style.display = 'none';
      const caret = document.getElementById('caret-' + r.dataset.drawerId);
      if (caret) caret.innerHTML = '&#9656;';
    }
  });
  if (btn) {
    const hideLabel = (btn.dataset && btn.dataset.hideLabel) || 'Show Top';
    const showLabel = (btn.dataset && btn.dataset.showLabel) || 'Show All';
    btn.textContent = anyHidden ? hideLabel : showLabel;
  }
}

function toggleVisibleHunks(btn, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const visibleRows = Array.from(tbody.querySelectorAll('tr.clickable-row')).filter(r => r.style.display !== 'none');
  const drawers = visibleRows.map(r => r.dataset.drawerId && document.getElementById(r.dataset.drawerId)).filter(Boolean);
  const anyHidden = drawers.some(r => r.style.display === 'none' || !r.style.display);
  drawers.forEach(row => {
    row.style.display = anyHidden ? 'table-row' : 'none';
    if (anyHidden) {
      row.querySelectorAll('.origin-hunk-group').forEach(g => { g.style.display = 'block'; });
    }
    const caret = document.getElementById('caret-' + row.id);
    if (caret) caret.innerHTML = anyHidden ? '&#9662;' : '&#9656;';
  });
  if (btn) {
    const collapseLabel = (btn.dataset && btn.dataset.collapseLabel) || 'Collapse All';
    const expandLabel = (btn.dataset && btn.dataset.expandLabel) || 'Expand All';
    btn.textContent = anyHidden ? collapseLabel : expandLabel;
  }
}

function jumpToCoveragePair(pairDomId) {
  selectTab('coverage');
  if (!pairDomId) return;
  const el = document.getElementById(pairDomId);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function filterLineageRows(prefix, tag, btn) {
  const tbody = document.getElementById(prefix + '-tbody');
  if (!tbody) return;
  if (btn && btn.parentElement) {
    Array.from(btn.parentElement.querySelectorAll('button')).forEach(b => {
      if (b.textContent.includes('Expand') || b.textContent.includes('Collapse')) return;
      b.classList.toggle('cov-btn-secondary', b !== btn);
    });
  }
  const rows = Array.from(tbody.querySelectorAll('tr.lineage-row'));
  rows.forEach((r, idx) => {
    const tags = (r.dataset.lineageTags || '').split(/\s+/);
    const show = (tag === 'all') || tags.includes(tag);
    r.style.display = show ? 'table-row' : 'none';
    const drawer = document.getElementById(prefix + '-drawer-' + idx);
    if (drawer && !show) {
      drawer.style.display = 'none';
      const caret = document.getElementById('caret-' + prefix + '-drawer-' + idx);
      if (caret) caret.innerHTML = '&#9656;';
    }
  });
}

let activeTriageGroup = 'all';
function filterTriageClusters(group, btn) {
  if (group !== null) {
    activeTriageGroup = group;
    const wrap = document.getElementById('triage-group-filters');
    if (wrap) {
      Array.from(wrap.querySelectorAll('button')).forEach(b => {
        b.classList.toggle('cov-btn-secondary', b !== btn);
      });
    }
  }
  const searchEl = document.getElementById('triage-search');
  const q = searchEl ? searchEl.value.trim().toLowerCase() : '';
  const tbody = document.getElementById('triage-clusters-tbody');
  if (!tbody) return;
  Array.from(tbody.querySelectorAll('tr.triage-cluster-row')).forEach(r => {
    const matchesGroup = (activeTriageGroup === 'all') || (r.dataset.group === activeTriageGroup);
    const matchesSearch = !q || (r.dataset.search || '').includes(q);
    const show = matchesGroup && matchesSearch;
    r.style.display = show ? 'table-row' : 'none';
    const drawer = r.dataset.drawerId && document.getElementById(r.dataset.drawerId);
    if (drawer && !show) {
      drawer.style.display = 'none';
      const caret = document.getElementById('caret-' + r.dataset.drawerId);
      if (caret) caret.innerHTML = '&#9656;';
    }
  });
}

window.addEventListener('popstate', applyHashTab);
window.addEventListener('hashchange', applyHashTab);
window.addEventListener('DOMContentLoaded', applyHashTab);
