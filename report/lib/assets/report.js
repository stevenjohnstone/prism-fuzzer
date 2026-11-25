const reportChunkManifest = window.__PRISM_FUZZER_CHUNK_MANIFEST__ || null;
const reportChunkCache = new Map();
const reportChunkPromises = new Map();
const reportChunkPartBuffers = new Map();
const evoStepStore = Object.create(null);
const drawerSpecStore = Object.create(null);
let applyLatestWorkerBannerCoverage = null;

window.__PRISM_FUZZER_ON_CHUNK__ = function(chunkId, payload) {
  reportChunkCache.set(chunkId, payload);
  if (payload && payload.kind === 'steps' && payload.steps) {
    Object.assign(evoStepStore, payload.steps);
  } else if (payload && payload.kind === 'drawers' && payload.drawers) {
    Object.assign(drawerSpecStore, payload.drawers);
  }
};

window.__PRISM_FUZZER_ON_CHUNK_PART__ = function(chunkId, partIdx, totalParts, sliceStr) {
  let entry = reportChunkPartBuffers.get(chunkId);
  if (!entry) {
    entry = { parts: new Array(totalParts), seen: 0, total: totalParts };
    reportChunkPartBuffers.set(chunkId, entry);
  }
  if (entry.parts[partIdx] === undefined) {
    entry.parts[partIdx] = sliceStr;
    entry.seen += 1;
  }
  if (entry.seen >= entry.total) {
    reportChunkPartBuffers.delete(chunkId);
    const parsed = JSON.parse(entry.parts.join(''));
    window.__PRISM_FUZZER_ON_CHUNK__(chunkId, parsed);
  }
};

function loadChunkScriptFile(relUrl) {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.async = true;
    script.src = relUrl;
    script.onload = () => {
      script.remove();
      resolve();
    };
    script.onerror = () => {
      script.remove();
      reject(new Error('Failed to load report chunk: ' + relUrl));
    };
    document.head.appendChild(script);
  });
}

function loadReportChunk(chunkId) {
  if (!chunkId) return Promise.resolve(null);
  if (reportChunkCache.has(chunkId)) return Promise.resolve(reportChunkCache.get(chunkId));
  if (!reportChunkManifest || !Array.isArray(reportChunkManifest[chunkId])) {
    return Promise.resolve(null);
  }
  if (reportChunkPromises.has(chunkId)) return reportChunkPromises.get(chunkId);

  const files = reportChunkManifest[chunkId];
  const p = Promise.all(files.map(loadChunkScriptFile))
    .then(() => reportChunkCache.get(chunkId) || null)
    .finally(() => { reportChunkPromises.delete(chunkId); });
  reportChunkPromises.set(chunkId, p);
  return p;
}

function ensureTabPanelLoaded(panel) {
  if (!panel || panel.dataset.chunkLoaded === '1' || !panel.dataset.tabChunk) {
    return Promise.resolve(true);
  }
  if (panel._chunkLoadingPromise) return panel._chunkLoadingPromise;

  if (!panel.children.length) {
    panel.innerHTML = '<div class="table-card" style="padding:24px;color:var(--muted);">Loading report section&hellip;</div>';
  }
  panel._chunkLoadingPromise = loadReportChunk(panel.dataset.tabChunk)
    .then(payload => {
      if (panel.dataset.chunkLoaded === '1') return true;
      panel.innerHTML = (payload && payload.html) || '';
      panel.dataset.chunkLoaded = '1';
      initCharts(panel);
      if (applyLatestWorkerBannerCoverage) applyLatestWorkerBannerCoverage(panel);
      if (payload && payload.sankeyMeta && typeof mountSankeyView === 'function') {
        mountSankeyView(payload.sankeyMeta, payload.sankeyInitial);
      }
      return true;
    })
    .catch(() => {
      if (panel.dataset.chunkLoaded !== '1') {
        panel.innerHTML = '<div class="table-card" style="padding:24px;color:var(--muted);">Failed to load report chunk (ensure the <code>chunks/</code> directory is alongside <code>index.html</code>).</div>';
      }
      return false;
    })
    .finally(() => {
      panel._chunkLoadingPromise = null;
    });
  return panel._chunkLoadingPromise;
}

function selectTab(name, push = true) {
  const targetPanel = document.getElementById('tab-' + name);
  if (!targetPanel) return Promise.resolve(false);
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === name);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel === targetPanel);
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
  return ensureTabPanelLoaded(targetPanel);
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

function initCharts(root) {
  (root || document).querySelectorAll('.chart-card[data-series]').forEach(card => {
    if (card.dataset.chartBound === '1') return;
    card.dataset.chartBound = '1';
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
}

initCharts(document);

function buildEvoDrawerInnerHtml(spec) {
  const steps = Array.isArray(spec.s) ? spec.s : [];
  const stepsHtml = steps.map((sid, idx) => {
    const isLast = (idx === steps.length - 1);
    const cls = idx === 0
      ? 'evo-step evo-step-root'
      : (isLast && spec.k ? 'evo-step evo-step-crash' : 'evo-step');
    const tail = evoStepStore[String(sid)] || '';
    return '<div class="' + cls + '"><div class="evo-step-head"><span class="evo-step-num">Step ' + idx + '</span>\n' + tail + '\n</div>';
  }).join('<div class="evo-connector">&darr;</div>');
  return '<td colspan="' + (Number(spec.c) || 7) + '" class="hunk-drawer-cell">' +
    '<div class="origin-hunk-title">' + (spec.t || '') + '</div>' +
    '<div class="evo-chain-wrap">' + stepsHtml + '</div></td>';
}

function hydrateDrawerRows(rows) {
  const pending = rows.filter(r => r && r.dataset.drawerShard && r.dataset.drawerHydrated !== '1' && !r.children.length);
  if (!pending.length) return Promise.resolve();

  const drawerShards = Array.from(new Set(pending.map(r => r.dataset.drawerShard).filter(Boolean)));
  return Promise.all(drawerShards.map(loadReportChunk)).then(() => {
    const stepShards = new Set();
    pending.forEach(r => {
      const spec = drawerSpecStore[r.id];
      if (spec && Array.isArray(spec.deps)) {
        spec.deps.forEach(dep => stepShards.add(dep));
      }
    });
    return Promise.all(Array.from(stepShards).map(loadReportChunk));
  }).then(() => {
    pending.forEach(r => {
      if (r.dataset.drawerHydrated === '1' || r.children.length) return;
      const spec = drawerSpecStore[r.id];
      if (!spec) return;
      if (typeof spec.html === 'string') {
        r.innerHTML = spec.html;
      } else if (Array.isArray(spec.s)) {
        r.innerHTML = buildEvoDrawerInnerHtml(spec);
      }
      r.dataset.drawerHydrated = '1';
    });
  });
}

function ensureExtraRowsLoaded(tbody) {
  if (!tbody || tbody.dataset.extraRowsHydrated === '1') return Promise.resolve();
  const raw = tbody.dataset.extraRowShards || '';
  const shardIds = raw.split(',').map(s => s.trim()).filter(Boolean);
  if (!shardIds.length) {
    tbody.dataset.extraRowsHydrated = '1';
    return Promise.resolve();
  }
  if (tbody._extraRowsPromise) return tbody._extraRowsPromise;

  tbody._extraRowsPromise = Promise.all(shardIds.map(loadReportChunk))
    .then(chunks => {
      if (tbody.dataset.extraRowsHydrated === '1') return;
      const html = chunks.map(c => (c && c.html) || '').join('\n');
      if (html) {
        const tpl = document.createElement('template');
        tpl.innerHTML = html;
        tbody.appendChild(tpl.content);
      }
      tbody.dataset.extraRowsHydrated = '1';
    })
    .finally(() => {
      tbody._extraRowsPromise = null;
    });
  return tbody._extraRowsPromise;
}

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
  if (!isHidden) {
    row.style.display = 'none';
    const caret = document.getElementById('caret-' + id);
    if (caret) caret.innerHTML = '&#9656;';
    return;
  }
  hydrateDrawerRows([row]).then(() => {
    row.style.display = 'table-row';
    row.querySelectorAll('.origin-hunk-group').forEach(g => { g.style.display = 'block'; });
    const caret = document.getElementById('caret-' + id);
    if (caret) caret.innerHTML = '&#9662;';
  });
}

function toggleAllHunks(btn, prefix) {
  const rows = Array.from(document.querySelectorAll('.hunk-drawer-row')).filter(r => r.id && r.id.startsWith(prefix));
  const anyHidden = rows.some(r => r.style.display === 'none' || !r.style.display);
  const finish = () => {
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
  };
  if (anyHidden) {
    hydrateDrawerRows(rows).then(finish);
  } else {
    finish();
  }
}

function toggleExtraTableRows(btn, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  ensureExtraRowsLoaded(tbody).then(() => {
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
  });
}

function toggleVisibleHunks(btn, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const visibleRows = Array.from(tbody.querySelectorAll('tr.clickable-row')).filter(r => r.style.display !== 'none');
  const drawers = visibleRows.map(r => r.dataset.drawerId && document.getElementById(r.dataset.drawerId)).filter(Boolean);
  const anyHidden = drawers.some(r => r.style.display === 'none' || !r.style.display);
  const finish = () => {
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
  };
  if (anyHidden) {
    hydrateDrawerRows(drawers).then(finish);
  } else {
    finish();
  }
}

function jumpToCoveragePair(pairDomId) {
  Promise.resolve(selectTab('coverage')).then(() => {
    if (!pairDomId) return;
    const el = document.getElementById(pairDomId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
}

function filterLineageRows(prefix, tag, btn) {
  const tbody = document.getElementById(prefix + '-tbody');
  if (!tbody) return;
  if (btn && btn.parentElement) {
    Array.from(btn.parentElement.querySelectorAll('button')).forEach(b => {
      if (b.textContent.includes('Expand') || b.textContent.includes('Collapse') || (b.dataset && b.dataset.showLabel)) return;
      b.classList.toggle('cov-btn-secondary', b !== btn);
    });
  }
  ensureExtraRowsLoaded(tbody).then(() => {
    const rows = Array.from(tbody.querySelectorAll('tr.lineage-row'));
    rows.forEach((r, idx) => {
      const tags = (r.dataset.lineageTags || '').split(/\s+/);
      const show = (tag === 'all') || tags.includes(tag);
      r.style.display = show ? 'table-row' : 'none';
      const drawerId = r.dataset.drawerId || (prefix + '-drawer-' + idx);
      const drawer = document.getElementById(drawerId);
      if (drawer && !show) {
        drawer.style.display = 'none';
        const caret = document.getElementById('caret-' + drawerId);
        if (caret) caret.innerHTML = '&#9656;';
      }
    });
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

(function() {
  const COV_PALETTE = [
    '#60a5fa', '#34d399', '#f472b6', '#fbbf24', '#a78bfa', '#fb7185',
    '#38bdf8', '#fb923c', '#4ade80', '#e879f9', '#2dd4bf', '#facc15'
  ];
  let covPollTimer = null;
  let covPollFinished = false;
  let covPollAttempts = 0;
  let covLoading = false;
  let lastAppliedSeq = 0;
  let lastAppliedStatus = '';

  function fmtInt(v) {
    return Math.round(Number(v) || 0).toLocaleString('en-US');
  }

  function fmtPct(v, digits) {
    return (Number(v) || 0).toFixed(digits) + '%';
  }

  function pairHtmlReady(p) {
    return !!(p && p.html_ready !== false && p.report_rel_path);
  }

  function resolveCovPath(rawRel, covBase) {
    const s = String(rawRel == null ? '' : rawRel);
    if (!s) return '';
    const idx = s.indexOf('pairs/');
    let sub = null;
    if (idx === 0 || (idx > 0 && s[idx - 1] === '/')) {
      sub = s.slice(idx);
    } else if (s.startsWith('coverage/')) {
      sub = s.slice('coverage/'.length);
    } else if (s.startsWith('../coverage/')) {
      sub = s.slice('../coverage/'.length);
    }
    if (!sub) return s;
    return (!covBase || covBase === '.') ? sub : (covBase.replace(/\/+$/, '') + '/' + sub);
  }

  function renderWorkerOverviewCells(wpairs, isPending) {
    const covList = wpairs.filter(p => p && p.has_coverage);
    if (!covList.length) {
      if (isPending) {
        return ['<span class="muted cov-pending-inline">Collecting&hellip;</span>', '<span class="muted">&mdash;</span>'];
      }
      return ['<span class="muted">&mdash;</span>', '<span class="muted">&mdash;</span>'];
    }
    if (covList.length === 1) {
      const p = covList[0];
      const lPct = (p.totals && p.totals.lines && p.totals.lines.percent) || 0;
      const bPct = (p.totals && p.totals.branches && p.totals.branches.percent) || 0;
      const label = escapeHtml(p.label || p.id);
      const pairDom = escapeHtml('cov-pair-' + p.id);
      const covCell = '<div class="cov-pair-stat"><a class="pair-chip" href="javascript:void(0)" onclick="event.stopPropagation(); jumpToCoveragePair(\'' + pairDom + '\')">' + label + '</a> <strong>' + fmtPct(lPct, 2) + '</strong> <span class="muted">(' + fmtPct(bPct, 1) + ' B)</span></div>';
      let repCell = '<span class="muted">&mdash;</span>';
      if (pairHtmlReady(p)) {
        repCell = '<a class="cov-link" href="' + escapeHtml(p.report_rel_path) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>';
      } else if (p.html_ready === false) {
        repCell = '<span class="muted" title="Rendering annotated HTML source views">HTML&hellip;</span>';
      }
      return [covCell, repCell];
    }
    const covLines = covList.map(p => {
      const lPct = (p.totals && p.totals.lines && p.totals.lines.percent) || 0;
      const bPct = (p.totals && p.totals.branches && p.totals.branches.percent) || 0;
      const label = escapeHtml(p.label || p.id);
      const pairDom = escapeHtml('cov-pair-' + p.id);
      return '<div class="cov-pair-stat"><a class="pair-chip" href="javascript:void(0)" onclick="event.stopPropagation(); jumpToCoveragePair(\'' + pairDom + '\')">' + label + '</a> <strong>' + fmtPct(lPct, 2) + '</strong> <span class="muted">(' + fmtPct(bPct, 1) + ' B)</span></div>';
    }).join('\n');
    const repLinks = covList.map(p => {
      const label = escapeHtml(p.label || p.id);
      if (pairHtmlReady(p)) {
        return '<div><a class="cov-link" href="' + escapeHtml(p.report_rel_path) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">' + label + ' &nearr;</a></div>';
      }
      if (p.html_ready === false) {
        return '<div><span class="muted">' + label + ' HTML&hellip;</span></div>';
      }
      return '';
    }).filter(Boolean).join('\n');
    return [covLines, repLinks || '<span class="muted">&mdash;</span>'];
  }

  function renderWorkerBannerBtns(wpairs) {
    return wpairs.filter(p => p && p.has_coverage).map(p => {
      const label = escapeHtml(p.label || p.id);
      if (pairHtmlReady(p)) {
        return '<a class="cov-btn" href="' + escapeHtml(p.report_rel_path) + '" target="_blank" rel="noopener">' + label + ' llvm-cov &nearr;</a>';
      }
      if (p.html_ready === false) {
        return '<span class="sched-pill cov-pending-pill">' + label + ' HTML&hellip;</span>';
      }
      return '';
    }).filter(Boolean).join(' ');
  }

  function renderOverviewKpis(activePairs) {
    return activePairs.map(p => {
      const pairDom = escapeHtml('cov-pair-' + p.id);
      const cl = (p.totals && p.totals.lines) || {};
      const cb = (p.totals && p.totals.branches) || {};
      const srcName = p.source || '';
      const targetLbl = p.target_label || '';
      const lblTxt = srcName ? ('Source Coverage &bull; ' + escapeHtml(srcName)) : 'Source Coverage';
      const targetHtml = targetLbl ? ('<div class="kpi-pair-target">' + escapeHtml(targetLbl) + '</div>') : '';
      return '<div class="kpi-card clickable-row" onclick="jumpToCoveragePair(\'' + pairDom + '\')" title="' + escapeHtml(p.label || '') + ' — click to view detailed coverage">' +
        '<div class="kpi-label">' + lblTxt + '</div>' +
        '<div class="kpi-value">' + fmtPct(cl.percent, 2) + '</div>' +
        targetHtml +
        '<div class="kpi-sub">' + fmtInt(cl.covered) + ' / ' + fmtInt(cl.count) + ' lines &bull; ' + fmtPct(cb.percent, 1) + ' branches</div>' +
        '</div>';
    }).join('\n');
  }

  function renderCoverageTabInner(pairs, activePairs, payloadStatus, generatedAt, stage) {
    if (!activePairs.length) {
      const stageNote = stage === 'rendering_html' ? ' (rendering HTML)' : (stage === 'replaying' ? ' (replaying inputs)' : '');
      const chips = pairs.map(p => '<code>' + escapeHtml(p.label || p.id) + '</code>').join(', ');
      return '<div class="fuzzer-banner"><div>' +
        '<h2><span class="legend-dot" style="background:#34d399"></span> Source Coverage by (Source, Target) Pair</h2>' +
        '<p class="cmd-line"><span class="cov-pulse-dot"></span> Collecting LLVM source coverage' + (chips ? ' for ' + chips : '') + escapeHtml(stageNote) + '&hellip;</p>' +
        '</div></div>' +
        '<div class="table-card" style="padding: 20px; color: var(--muted);">Coverage replay is running. Summary percentages and per-file coverage tables will appear here automatically as each <code>(source, target)</code> pair completes.</div>';
    }

    const isUpdating = (payloadStatus === 'running' || payloadStatus === 'updating');
    let summaryCard = '';
    if (pairs.length > 1) {
      const rows = pairs.map((p, idx) => {
        const pt = p.totals || {};
        const pl = pt.lines || {};
        const pb = pt.branches || {};
        const pr = pt.regions || {};
        const pf = pt.functions || {};
        const color = COV_PALETTE[idx % COV_PALETTE.length];
        const pairDom = escapeHtml('cov-pair-' + p.id);
        const ready = pairHtmlReady(p);
        const links = [];
        if (ready) {
          if (p.report_rel_path) links.push('<a class="cov-link" href="' + escapeHtml(p.report_rel_path) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>');
          if (p.summary_rel_path) links.push('<a class="cov-link muted" href="' + escapeHtml(p.summary_rel_path) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">Txt &nearr;</a>');
          if (p.lcov_rel_path) links.push('<a class="cov-link muted" href="' + escapeHtml(p.lcov_rel_path) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">LCOV &nearr;</a>');
        } else if (p.has_coverage && p.html_ready === false) {
          links.push('<span class="muted">Rendering HTML&hellip;</span>');
        }
        const workersList = Array.isArray(p.workers) && p.workers.length
          ? p.workers.map(w => '<code>' + escapeHtml(w) + '</code>').join(' ')
          : '<span class="muted">&mdash;</span>';
        const linesCell = p.has_coverage
          ? ('<div><strong>' + fmtPct(pl.percent, 2) + '</strong> <span class="muted">(' + fmtInt(pl.covered) + ' / ' + fmtInt(pl.count) + ')</span></div>' +
             '<div class="sync-bar" style="height: 6px; margin-top: 4px;"><div class="sync-seg" style="width:' + (Number(pl.percent) || 0).toFixed(2) + '%;background:' + color + '"></div></div>')
          : '<span class="muted">&mdash;</span>';
        const branchesCell = (p.has_coverage && (Number(pb.count) || 0) > 0)
          ? ('<div><strong>' + fmtPct(pb.percent, 2) + '</strong> <span class="muted">(' + fmtInt(pb.covered) + ' / ' + fmtInt(pb.count) + ')</span></div>' +
             '<div class="sync-bar" style="height: 6px; margin-top: 4px;"><div class="sync-seg" style="width:' + (Number(pb.percent) || 0).toFixed(2) + '%;background:#38bdf8"></div></div>')
          : '<span class="muted">&mdash;</span>';
        return '<tr class="clickable-row" onclick="jumpToCoveragePair(\'' + pairDom + '\')">' +
          '<td><span class="legend-dot" style="background:' + color + '"></span> <strong>' + escapeHtml(p.label || '') + '</strong></td>' +
          '<td><code>' + escapeHtml(p.source || '') + '</code></td>' +
          '<td><code>' + escapeHtml(p.target_label || '') + '</code></td>' +
          '<td>' + workersList + '</td>' +
          '<td class="num">' + fmtInt(p.input_count) + '</td>' +
          '<td class="num" style="min-width: 200px;">' + linesCell + '</td>' +
          '<td class="num" style="min-width: 200px;">' + branchesCell + '</td>' +
          '<td class="num">' + (p.has_coverage ? fmtPct(pr.percent, 2) : '<span class="muted">&mdash;</span>') + '</td>' +
          '<td class="num">' + (p.has_coverage ? fmtPct(pf.percent, 2) : '<span class="muted">&mdash;</span>') + '</td>' +
          '<td class="num">' + (links.length ? links.join(' &bull; ') : '<span class="muted">&mdash;</span>') + '</td>' +
          '</tr>';
      }).join('\n');
      summaryCard = '<div class="table-card" style="margin-bottom: 22px;">' +
        '<div class="table-card-header"><div><h3>Coverage by (Source, Target) Pair</h3>' +
        '<p class="chart-sub">Each <code>(source revision, compilation target)</code> pair builds an independent coverage binary and replays compatible inputs from its associated workers and seeds.</p></div></div>' +
        '<table><thead><tr><th>Pair</th><th>Source</th><th>Target</th><th>Workers</th><th class="num">Inputs</th><th class="num">Lines</th><th class="num">Branches</th><th class="num">Regions %</th><th class="num">Functions %</th><th class="num">llvm-cov Reports</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }

    const pairSections = pairs.map((p, idx) => {
      const pairDom = escapeHtml('cov-pair-' + p.id);
      const color = COV_PALETTE[idx % COV_PALETTE.length];
      const bits = [
        'Source: <code>' + escapeHtml(p.source || '') + '</code>',
        'Target: <code>' + escapeHtml(p.target_label || '') + '</code>'
      ];
      if (p.source_commit) {
        bits.push('Commit: <code>' + escapeHtml(String(p.source_commit).slice(0, 10)) + '</code>');
      } else if (p.source_ref) {
        bits.push('Ref: <code>' + escapeHtml(p.source_ref) + '</code>');
      }
      bits.push(fmtInt(p.input_count) + ' deduplicated inputs');
      if (Array.isArray(p.workers) && p.workers.length) {
        bits.push('Workers: ' + p.workers.map(w => '<code>' + escapeHtml(w) + '</code>').join(', '));
      }
      const ready = pairHtmlReady(p);
      const btns = [];
      if (ready) {
        if (p.report_rel_path) btns.push('<a class="cov-btn" href="' + escapeHtml(p.report_rel_path) + '" target="_blank" rel="noopener">Open llvm-cov HTML Report &nearr;</a>');
        if (p.summary_rel_path) btns.push('<a class="cov-btn cov-btn-secondary" href="' + escapeHtml(p.summary_rel_path) + '" target="_blank" rel="noopener">Text Summary &nearr;</a>');
        if (p.lcov_rel_path) btns.push('<a class="cov-btn cov-btn-secondary" href="' + escapeHtml(p.lcov_rel_path) + '" target="_blank" rel="noopener">LCOV (IDE Gutters) &nearr;</a>');
      } else if (p.has_coverage && p.html_ready === false) {
        btns.push('<span class="sched-pill cov-pending-pill"><span class="cov-pulse-dot"></span> Rendering llvm-cov HTML&hellip;</span>');
      }

      if (!p.has_coverage) {
        return '<div id="' + pairDom + '" style="margin-bottom: 28px;">' +
          '<div class="fuzzer-banner"><div><h2><span class="legend-dot" style="background:' + color + '"></span> ' + escapeHtml(p.label || '') + '</h2>' +
          '<p class="cmd-line">' + bits.join(' &bull; ') + '</p></div></div>' +
          '<div class="table-card" style="padding: 18px; color: var(--muted);">' +
          (isUpdating ? 'Replaying inputs for this pair&hellip;' : 'No coverage profile data collected for this pair yet.') +
          '</div></div>';
      }

      const pt = p.totals || {};
      const pl = pt.lines || {};
      const pb = pt.branches || {};
      const pr = pt.regions || {};
      const pf = pt.functions || {};
      const filePrefix = p.file_report_prefix || '';
      const fileRows = (Array.isArray(p.files) ? p.files : []).map(cf => {
        const fname = cf.filename || '';
        const cs = cf.summary || {};
        const fl = cs.lines || {};
        const fb = cs.branches || {};
        const fr = cs.regions || {};
        const ff = cs.functions || {};
        if (!fl.count && !ff.count) return '';
        const missedL = (Number(fl.count) || 0) - (Number(fl.covered) || 0);
        const missedB = (Number(fb.count) || 0) - (Number(fb.covered) || 0);
        const href = cf.report_rel_path || (filePrefix ? (filePrefix + fname + '.html') : '');
        const linkHtml = (ready && href)
          ? ('<a class="cov-link" href="' + escapeHtml(href) + '" target="_blank" rel="noopener"><code>' + escapeHtml(fname) + '</code> &nearr;</a>')
          : ('<code>' + escapeHtml(fname) + '</code>');
        const branchCell = (Number(fb.count) || 0) > 0
          ? ('<strong>' + fmtPct(fb.percent, 2) + '</strong> <span class="muted">(' + fmtInt(fb.covered) + '/' + fmtInt(fb.count) + ')</span>')
          : '<span class="muted">&mdash;</span>';
        const missedBCell = (Number(fb.count) || 0) > 0
          ? (missedB > 0 ? ('<span class="text-warn">' + fmtInt(missedB) + '</span>') : '<span class="muted">0</span>')
          : '<span class="muted">&mdash;</span>';
        return '<tr>' +
          '<td>' + linkHtml + '</td>' +
          '<td class="num"><strong>' + fmtPct(fl.percent, 2) + '</strong> <span class="muted">(' + fmtInt(fl.covered) + '/' + fmtInt(fl.count) + ')</span></td>' +
          '<td class="num">' + (missedL > 0 ? ('<span class="text-warn">' + fmtInt(missedL) + '</span>') : '<span class="muted">0</span>') + '</td>' +
          '<td class="num">' + branchCell + '</td>' +
          '<td class="num">' + missedBCell + '</td>' +
          '<td class="num">' + fmtPct(fr.percent, 2) + '</td>' +
          '<td class="num">' + fmtPct(ff.percent, 2) + '</td>' +
          '</tr>';
      }).filter(Boolean).join('\n');

      const subHint = ready
        ? 'Click any source file to open its annotated HTML coverage view.'
        : 'Summary percentages ready; annotated source HTML links will activate automatically once llvm-cov finishes.';
      return '<div id="' + pairDom + '" style="margin-bottom: 28px;">' +
        '<div class="fuzzer-banner"><div><h2><span class="legend-dot" style="background:' + color + '"></span> ' + escapeHtml(p.label || '') + '</h2>' +
        '<p class="cmd-line">' + bits.join(' &bull; ') + '</p></div>' +
        '<div class="fuzzer-meta">' + btns.join('\n') + '</div></div>' +
        '<div class="kpi-grid">' +
        '<div class="kpi-card"><div class="kpi-label">Line Coverage</div><div class="kpi-value">' + fmtPct(pl.percent, 2) + '</div><div class="kpi-sub">' + fmtInt(pl.covered) + ' / ' + fmtInt(pl.count) + ' lines (' + fmtInt((Number(pl.count) || 0) - (Number(pl.covered) || 0)) + ' missed)</div></div>' +
        '<div class="kpi-card"><div class="kpi-label">Branch Coverage</div><div class="kpi-value">' + fmtPct(pb.percent, 2) + '</div><div class="kpi-sub">' + fmtInt(pb.covered) + ' / ' + fmtInt(pb.count) + ' branches (' + fmtInt((Number(pb.count) || 0) - (Number(pb.covered) || 0)) + ' missed)</div></div>' +
        '<div class="kpi-card"><div class="kpi-label">Region Coverage</div><div class="kpi-value">' + fmtPct(pr.percent, 2) + '</div><div class="kpi-sub">' + fmtInt(pr.covered) + ' / ' + fmtInt(pr.count) + ' regions (' + fmtInt((Number(pr.count) || 0) - (Number(pr.covered) || 0)) + ' missed)</div></div>' +
        '<div class="kpi-card"><div class="kpi-label">Function Coverage</div><div class="kpi-value">' + fmtPct(pf.percent, 2) + '</div><div class="kpi-sub">' + fmtInt(pf.covered) + ' / ' + fmtInt(pf.count) + ' functions (' + fmtInt((Number(pf.count) || 0) - (Number(pf.covered) || 0)) + ' missed)</div></div>' +
        '</div>' +
        '<div class="table-card"><div class="table-card-header"><div><h3>Per-File Coverage &mdash; <code>' + escapeHtml(p.label || '') + '</code></h3><p class="chart-sub">' + subHint + '</p></div></div>' +
        '<table><thead><tr><th>Source File</th><th class="num">Lines</th><th class="num">Missed L</th><th class="num">Branches</th><th class="num">Missed B</th><th class="num">Regions %</th><th class="num">Functions %</th></tr></thead>' +
        '<tbody>' + fileRows + '</tbody></table></div></div>';
    }).join('\n');

    const updatingPill = isUpdating ? ' &bull; <span class="cov-pending-inline"><span class="cov-pulse-dot"></span> Updating&hellip;</span>' : '';
    return '<div class="fuzzer-banner"><div>' +
      '<h2><span class="legend-dot" style="background:#34d399"></span> Source Coverage by (Source, Target) Pair</h2>' +
      '<p class="cmd-line">' + pairs.length + ' coverage target' + (pairs.length === 1 ? '' : 's') + ' &bull; Collected: ' + escapeHtml(generatedAt || '') + updatingPill + '</p>' +
      '</div></div>' + summaryCard + pairSections;
  }

  function applyCoveragePayload(rawPayload) {
    if (!rawPayload || typeof rawPayload !== 'object' || !Array.isArray(rawPayload.pairs)) return;
    const body = document.body;
    if (!body) return;

    const payloadStatus = rawPayload.status || 'complete';
    const seq = Number(rawPayload.sequence) || 0;
    const genAt = String(rawPayload.generated_at || '');

    if (body.dataset.covStatus === 'complete' && payloadStatus === 'complete' && body.dataset.covGeneratedAt && body.dataset.covGeneratedAt === genAt) {
      covPollFinished = true;
      return;
    }
    if (lastAppliedSeq && seq && seq < lastAppliedSeq) return;
    if (lastAppliedSeq && seq && seq === lastAppliedSeq && lastAppliedStatus === payloadStatus) {
      if (payloadStatus === 'complete') covPollFinished = true;
      return;
    }

    lastAppliedSeq = seq || lastAppliedSeq;
    lastAppliedStatus = payloadStatus;
    body.dataset.covStatus = payloadStatus;
    if (genAt) body.dataset.covGeneratedAt = genAt;
    if (seq) body.dataset.covSeq = String(seq);

    const covBase = body.dataset.covBase || 'coverage';
    const pairs = rawPayload.pairs.map(p => {
      const cp = Object.assign({}, p);
      ['report_rel_path', 'lcov_rel_path', 'summary_rel_path', 'file_report_prefix'].forEach(k => {
        if (cp[k]) cp[k] = resolveCovPath(cp[k], covBase);
      });
      if (Array.isArray(cp.files)) {
        cp.files = cp.files.map(fe => {
          if (!fe || typeof fe !== 'object') return fe;
          const cfe = Object.assign({}, fe);
          if (cfe.report_rel_path) cfe.report_rel_path = resolveCovPath(cfe.report_rel_path, covBase);
          return cfe;
        });
      }
      return cp;
    });

    const pairsById = {};
    pairs.forEach(p => { pairsById[String(p.id)] = p; });
    const activePairs = pairs.filter(p => p.has_coverage);
    const primaryPair = activePairs.find(p => p.id === rawPayload.primary_pair_id) || activePairs[0];

    let workerPairs = (rawPayload.worker_pairs && Object.keys(rawPayload.worker_pairs).length)
      ? rawPayload.worker_pairs
      : {};
    if (!Object.keys(workerPairs).length && body.dataset.workerPairs) {
      try { workerPairs = JSON.parse(body.dataset.workerPairs) || {}; } catch (_e) { workerPairs = {}; }
    }

    // 1. Header buttons
    const headerEl = document.getElementById('header-cov-btns');
    if (headerEl) {
      if (activePairs.length) {
        const btns = activePairs.map(p => {
          const lbl = activePairs.length > 1 ? (escapeHtml(p.label || p.id) + ' llvm-cov') : 'llvm-cov HTML';
          if (pairHtmlReady(p)) {
            return '<a class="cov-btn" href="' + escapeHtml(p.report_rel_path) + '" target="_blank" rel="noopener">' + lbl + ' &nearr;</a>';
          }
          if (p.html_ready === false) {
            return '<span class="sched-pill cov-pending-pill"><span class="cov-pulse-dot"></span> ' + lbl + ' (rendering&hellip;)</span>';
          }
          return '';
        }).filter(Boolean);
        if (payloadStatus === 'running') {
          btns.push('<span class="sched-pill cov-pending-pill"><span class="cov-pulse-dot"></span> Updating coverage&hellip;</span>');
        }
        headerEl.className = btns.length ? 'fuzzer-meta' : '';
        headerEl.innerHTML = btns.join(' ');
      } else if (payloadStatus === 'running') {
        headerEl.className = 'fuzzer-meta';
        headerEl.innerHTML = '<span class="sched-pill cov-pending-pill"><span class="cov-pulse-dot"></span> Collecting LLVM coverage&hellip;</span>';
      }
    }

    // 2. Nav tab button
    const tabSlot = document.getElementById('tab-btn-coverage-slot');
    const covPanel = document.getElementById('tab-coverage');
    const isActiveTab = !!(covPanel && covPanel.classList.contains('active'));
    if (tabSlot && (primaryPair || payloadStatus === 'running')) {
      const suffix = primaryPair
        ? (activePairs.length > 1 ? (activePairs.length + ' Pairs') : fmtPct(primaryPair.totals && primaryPair.totals.lines && primaryPair.totals.lines.percent, 2))
        : 'Collecting\u2026';
      tabSlot.innerHTML = '<button id="tab-btn-coverage" class="tab-btn' + (isActiveTab ? ' active' : '') + '" data-tab="coverage" onclick="selectTab(\'coverage\')">' +
        '<span class="legend-dot" style="background:#34d399"></span> Source Coverage (' + escapeHtml(suffix) + ')</button>';
    }

    // 3. Overview KPI cards
    const kpiSlot = document.getElementById('overview-cov-kpis');
    if (kpiSlot) {
      kpiSlot.innerHTML = renderOverviewKpis(activePairs);
    }

    // 4. Worker & Generator overview cells + detail banner buttons
    const resolveForWorker = (wname) => {
      let ids = workerPairs[wname];
      if ((!ids || !ids.length) && pairs.length === 1) ids = [pairs[0].id];
      return (Array.isArray(ids) ? ids : []).map(id => pairsById[String(id)]).filter(Boolean);
    };
    const isPending = (payloadStatus === 'running');
    document.querySelectorAll('[data-worker-cov-cell]').forEach(cell => {
      const wname = cell.dataset.workerCovCell;
      const wp = resolveForWorker(wname);
      const [covHtml, repHtml] = renderWorkerOverviewCells(wp, isPending);
      cell.innerHTML = covHtml;
      const row = cell.closest('tr');
      const repEl = row && row.querySelector('[data-worker-cov-rep]');
      if (repEl) repEl.innerHTML = repHtml;
    });
    const updateWorkerBannersIn = (rootEl) => {
      (rootEl || document).querySelectorAll('[data-worker-cov-banner]').forEach(slot => {
        const wname = slot.dataset.workerCovBanner;
        slot.innerHTML = renderWorkerBannerBtns(resolveForWorker(wname));
      });
    };
    applyLatestWorkerBannerCoverage = updateWorkerBannersIn;
    updateWorkerBannersIn(document);

    // 5. Coverage tab body
    if (covPanel) {
      covPanel.innerHTML = renderCoverageTabInner(pairs, activePairs, payloadStatus, genAt, rawPayload.stage);
      covPanel.dataset.chunkLoaded = '1';
    }

    if (payloadStatus === 'complete') {
      covPollFinished = true;
      if (covPollTimer) {
        clearTimeout(covPollTimer);
        covPollTimer = null;
      }
    }
  }

  window.__PRISM_FUZZER_ON_COVERAGE__ = applyCoveragePayload;

  function scheduleNextPoll() {
    if (covPollFinished || covPollAttempts >= 240) return;
    const st = (document.body && document.body.dataset.covStatus) || 'none';
    if (st === 'pending' || st === 'updating' || st === 'running') {
      covPollTimer = setTimeout(probeCoverageScript, 2500);
    }
  }

  function probeCoverageScript() {
    if (covPollFinished || covLoading || !document.body) return;
    const covJs = document.body.dataset.covJs;
    if (!covJs) return;
    const st = document.body.dataset.covStatus || 'none';
    const bustCache = (window.location.protocol === 'file:' || st === 'pending' || st === 'updating' || st === 'running');
    const url = bustCache ? (covJs + (covJs.includes('?') ? '&' : '?') + '_ts=' + Date.now()) : covJs;
    covLoading = true;
    covPollAttempts += 1;
    const script = document.createElement('script');
    script.async = true;
    script.src = url;
    script.onload = () => {
      covLoading = false;
      script.remove();
      scheduleNextPoll();
    };
    script.onerror = () => {
      covLoading = false;
      script.remove();
      scheduleNextPoll();
    };
    document.head.appendChild(script);
  }

  window.addEventListener('DOMContentLoaded', () => {
    if (window.__PRISM_FUZZER_PENDING_COVERAGE__) {
      const pending = window.__PRISM_FUZZER_PENDING_COVERAGE__;
      delete window.__PRISM_FUZZER_PENDING_COVERAGE__;
      applyCoveragePayload(pending);
    }
    probeCoverageScript();
  });
})();
