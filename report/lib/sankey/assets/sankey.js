function mountSankeyView(viewsMeta, initialState) {
  const root = document.querySelector('.sankey-root');
  if (!root) return;
  const state = Object.assign({ pinned: null }, initialState || {});
  const tooltip = document.getElementById('sk-tooltip');
  const summaryLine = document.getElementById('sk-summary-line');
  const clearBtn = document.getElementById('sk-clear-pin');

  function escapeHtml(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function currentKey() {
    return state.metric + '|' + state.group + '|' + state.layers + '|' + state.cap;
  }

  function activeView() {
    return root.querySelector('.sankey-view.active');
  }

  function collectConnected(svg, startKeys, isLink, srcKey, dstKey) {
    const links = Array.from(svg.querySelectorAll('.sk-link'));
    const nodeSet = new Set(startKeys);
    const linkSet = new Set();

    const walk = (seeds, matchFn, nextKeyFn) => {
      const queue = seeds.slice();
      const seen = new Set(seeds);
      while (queue.length) {
        const cur = queue.shift();
        links.forEach(l => {
          if (matchFn(l, cur)) {
            linkSet.add(l);
            const nxt = nextKeyFn(l);
            if (!seen.has(nxt)) {
              seen.add(nxt);
              nodeSet.add(nxt);
              queue.push(nxt);
            }
          }
        });
      }
    };

    if (isLink) {
      links.forEach(l => {
        if (l.dataset.src === srcKey && l.dataset.dst === dstKey) linkSet.add(l);
      });
      walk([srcKey], (l, cur) => l.dataset.dst === cur, l => l.dataset.src);
      walk([dstKey], (l, cur) => l.dataset.src === cur, l => l.dataset.dst);
    } else {
      const seed = startKeys[0];
      walk([seed], (l, cur) => l.dataset.dst === cur, l => l.dataset.src);
      walk([seed], (l, cur) => l.dataset.src === cur, l => l.dataset.dst);
    }
    return { nodeSet, linkSet };
  }

  function applyHighlight(target) {
    const view = activeView();
    if (!view) return;
    const svg = view.querySelector('svg');
    if (!svg) return;
    const allLinks = svg.querySelectorAll('.sk-link');
    const allNodes = svg.querySelectorAll('.sk-node');
    const allLabels = svg.querySelectorAll('.sk-label');

    allLinks.forEach(el => el.classList.remove('sk-dim', 'sk-hi'));
    allNodes.forEach(el => el.classList.remove('sk-dim', 'sk-pin'));
    allLabels.forEach(el => el.classList.remove('sk-dim'));

    if (!target) return;

    const res = target.type === 'link'
      ? collectConnected(svg, [target.src, target.dst], true, target.src, target.dst)
      : collectConnected(svg, [target.key], false);

    allLinks.forEach(l => {
      if (res.linkSet.has(l)) l.classList.add('sk-hi');
      else l.classList.add('sk-dim');
    });
    allNodes.forEach(n => {
      if (!res.nodeSet.has(n.dataset.key)) n.classList.add('sk-dim');
      if (target.type === 'node' && n.dataset.key === target.key) n.classList.add('sk-pin');
    });
    allLabels.forEach(t => {
      if (!res.nodeSet.has(t.dataset.key)) t.classList.add('sk-dim');
    });
  }

  function positionTooltip(ev) {
    const x = Math.min(ev.clientX + 14, window.innerWidth - tooltip.offsetWidth - 14);
    const y = Math.min(ev.clientY + 14, window.innerHeight - tooltip.offsetHeight - 14);
    tooltip.style.left = Math.max(8, x) + 'px';
    tooltip.style.top = Math.max(8, y) + 'px';
  }

  function showTooltip(ev, html) {
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
    positionTooltip(ev);
  }

  function switchView() {
    const key = currentKey();
    root.querySelectorAll('.sankey-view').forEach(v => {
      v.classList.toggle('active', v.dataset.viewKey === key);
    });
    state.pinned = null;
    clearBtn.style.display = 'none';
    applyHighlight(null);
    const meta = viewsMeta[key];
    if (meta) {
      const tailMsg = meta.collapsed > 0 ? (' (' + meta.collapsed + ' collapsed into Other)') : '';
      summaryLine.textContent = 'Showing ' + meta.total.toLocaleString() + ' flow units across ' + meta.clusters + ' clusters' + tailMsg + '. Hover to trace pathways; click a node or ribbon to lock.';
    }
  }

  root.querySelectorAll('.ctrl-group[data-axis]').forEach(grp => {
    const axis = grp.dataset.axis;
    grp.querySelectorAll('.ctrl-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state[axis] = btn.dataset.val;
        grp.querySelectorAll('.ctrl-btn').forEach(b => b.classList.toggle('active', b === btn));
        switchView();
      });
    });
  });

  clearBtn.addEventListener('click', () => {
    state.pinned = null;
    clearBtn.style.display = 'none';
    applyHighlight(null);
  });

  root.querySelectorAll('.sankey-view svg').forEach(svg => {
    svg.addEventListener('mousemove', ev => {
      if (tooltip.style.display === 'block') positionTooltip(ev);
    });
    svg.querySelectorAll('.sk-node').forEach(rect => {
      rect.addEventListener('mouseenter', ev => {
        const key = rect.dataset.key;
        const meta = viewsMeta[currentKey()]?.nodeMeta?.[key] || {};
        const head = meta.headline ? '<div style="margin-top:4px;color:#9ca3af;font-size:0.75rem;word-break:break-word;">' + escapeHtml(meta.headline) + '</div>' : '';
        const sub = meta.bucket_count ? '<div style="color:#9ca3af;font-size:0.75rem;">' + escapeHtml(meta.bucket_count) + ' buckets &bull; ' + Number(meta.occurrences || 0).toLocaleString() + ' total occ</div>' : '';
        showTooltip(ev, '<strong>' + escapeHtml(meta.label || rect.dataset.rawId) + '</strong><br/>Flow: ' + Number(rect.dataset.val).toLocaleString() + ' (' + escapeHtml(rect.dataset.pct) + '%)' + sub + head);
        if (!state.pinned) applyHighlight({ type: 'node', key });
      });
      rect.addEventListener('mouseleave', () => {
        tooltip.style.display = 'none';
        if (!state.pinned) applyHighlight(null);
      });
      rect.addEventListener('click', () => {
        const tgt = { type: 'node', key: rect.dataset.key };
        if (state.pinned && state.pinned.type === 'node' && state.pinned.key === tgt.key) {
          state.pinned = null;
          clearBtn.style.display = 'none';
          applyHighlight(null);
        } else {
          state.pinned = tgt;
          clearBtn.style.display = 'inline-block';
          applyHighlight(tgt);
        }
      });
    });
    svg.querySelectorAll('.sk-link').forEach(path => {
      path.addEventListener('mouseenter', ev => {
        const nm = viewsMeta[currentKey()]?.nodeMeta || {};
        const sl = nm[path.dataset.src]?.label || path.dataset.src;
        const dl = nm[path.dataset.dst]?.label || path.dataset.dst;
        showTooltip(ev, '<strong>' + escapeHtml(sl) + ' &rarr; ' + escapeHtml(dl) + '</strong><br/>Flow: ' + Number(path.dataset.val).toLocaleString() + '<br/>' + escapeHtml(path.dataset.pctS) + '% of source &bull; ' + escapeHtml(path.dataset.pctD) + '% of target');
        if (!state.pinned) applyHighlight({ type: 'link', src: path.dataset.src, dst: path.dataset.dst });
      });
      path.addEventListener('mouseleave', () => {
        tooltip.style.display = 'none';
        if (!state.pinned) applyHighlight(null);
      });
      path.addEventListener('click', () => {
        const tgt = { type: 'link', src: path.dataset.src, dst: path.dataset.dst };
        if (state.pinned && state.pinned.type === 'link' && state.pinned.src === tgt.src && state.pinned.dst === tgt.dst) {
          state.pinned = null;
          clearBtn.style.display = 'none';
          applyHighlight(null);
        } else {
          state.pinned = tgt;
          clearBtn.style.display = 'inline-block';
          applyHighlight(tgt);
        }
      });
    });
  });
}
