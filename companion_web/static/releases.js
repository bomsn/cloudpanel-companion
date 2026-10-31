/* Comparison is advisory. The server independently hashes the final selection. */
'use strict';
(() => {
  const root = document.getElementById('code-finder');
  if (!root) return;
  const byId = id => document.getElementById(id);
  const check = byId('check-changes'), progress = byId('scan-progress'), error = byId('scan-error');
  const list = byId('folder-list'), search = byId('folder-search'), form = byId('selection-form');
  const selected = new Map(), open = new Set(), detailCache = new Map();
  let comparison = null, filter = 'changed', busy = false, blocked = false, timer, failures = 0, workflowWasRunning = false;
  const iconUrl = root.querySelector('svg use').getAttribute('href').split('#')[0];
  const element = (tag, cls, text) => { const node = document.createElement(tag); if (cls) node.className = cls; if (text !== undefined) node.textContent = text; return node; };
  function icon(name, cls = '') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'icon ' + cls); svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(svg.namespaceURI, 'use'); use.setAttribute('href', iconUrl + '#' + name); svg.append(use); return svg;
  }
  function announce(message) { error.textContent = message; error.hidden = !message; }
  async function request(url, options = {}) {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch(url, {credentials: 'same-origin', signal: controller.signal, ...options, headers: {Accept: 'application/json', ...(options.headers || {})}});
      if (response.redirected || !response.headers.get('content-type')?.includes('application/json')) throw Error('Your session needs attention. Reload this page and sign in again.');
      const body = await response.json();
      if (!response.ok) throw Error(body.error || 'The check could not finish. Try again shortly.');
      return body;
    } catch (failure) {
      if (failure.name === 'AbortError') throw Error('The connection took too long. Check your connection and try again.');
      if (failure instanceof TypeError) throw Error('The connection was interrupted. Try again to load the file details.');
      throw failure;
    } finally { clearTimeout(timeout); }
  }
  function selectionState() {
    const paths = [...selected.keys()];
    byId('selected-files').value = paths.join('\n');
    const folders = [...selected.values()].filter(value => value.folder).length;
    const files = paths.length - folders;
    const labels = [];
    if (folders) labels.push(`${folders} folder${folders === 1 ? '' : 's'}`);
    if (files) labels.push(`${files} file${files === 1 ? '' : 's'}`);
    byId('selection-summary').textContent = labels.length ? labels.join(' and ') + ' selected' : 'No changes selected';
    byId('review-selection').disabled = !paths.length || busy || blocked;
    byId('clear-selection').disabled = !paths.length || busy;
    check.disabled = busy || blocked;
  }
  function wholeSelected(path) { return selected.has(path); }
  function badge(text, cls = '') { return element('span', 'badge ' + cls, text); }
  function refreshRows() {
    list.querySelectorAll('input[data-file]').forEach(input => {
      const whole = wholeSelected(input.dataset.folder);
      input.checked = whole || selected.has(input.dataset.file);
      input.disabled = whole || busy || blocked;
    });
    list.querySelectorAll('input[data-whole]').forEach(input => {input.checked = wholeSelected(input.dataset.whole); input.disabled = busy || blocked;});
    selectionState();
  }
  function showFiles(folder, target, data, append) {
    if (!append) target.replaceChildren();
    if (!append) {
      const note = folder.whole_folder ? 'Select this folder above to include its changed files. Website-only files are kept.' : 'Select individual eligible files. This folder contains exclusions or exceeds a whole-folder limit.';
      target.append(element('p', 'file-note', note));
    }
    for (const row of data.rows) {
      const line = element('div', 'file-row');
      const label = element('label');
      if (row.releasable) {
        const input = element('input'); input.type = 'checkbox'; input.dataset.file = row.file; input.dataset.folder = folder.path;
        input.addEventListener('change', () => { if (input.checked) selected.set(row.file, {folder: false}); else selected.delete(row.file); refreshRows(); });
        label.append(input);
      } else label.append(icon('file'));
      label.append(element('code', '', row.file.slice(folder.path.length + 1))); line.append(label);
      line.append(badge(row.status === 'website-only' ? 'Website only (kept)' : row.status === 'added' ? 'New' : 'Modified', row.status === 'website-only' ? '' : 'blue'));
      if (!row.releasable && row.status !== 'website-only') line.append(element('small', '', 'Too large for this release'));
      target.append(line);
    }
    if (!data.rows.length && !append) target.append(element('p', 'file-note', 'No file differences in this folder.'));
    target.querySelector('.load-more')?.remove();
    if (data.page < data.pages) {
      const more = element('button', 'secondary load-more', 'Show more files'); more.type = 'button';
      more.addEventListener('click', () => loadDetail(folder, target, data.page + 1, true)); target.append(more);
    }
    if (!append && data.excluded.length) {
      const disclosure = element('details', 'disclosure'); disclosure.append(element('summary', '', `${folder.excluded} excluded artifact${folder.excluded === 1 ? '' : 's'}`));
      const note = element('div');
      data.excluded.forEach(row => { const p = element('p', 'file-note'); p.append(element('code', '', row.file), document.createTextNode(` (${row.side}: ${row.reason})`)); note.append(p); });
      if (folder.excluded > data.excluded.length) note.append(element('p', 'file-note', 'The first 50 exclusions are shown. These artifacts cannot be selected.'));
      disclosure.append(note); target.append(disclosure);
    }
    refreshRows();
  }
  async function loadDetail(folder, target, page = 1, append = false) {
    const generation = comparison.generation;
    const key = generation + ':' + folder.id + ':' + page;
    target.setAttribute('aria-busy', 'true');
    if (!append) target.replaceChildren(element('p', 'file-note', 'Checking file details…'));
    else {const button = target.querySelector('.load-more'); if (button) {button.disabled = true; button.textContent = 'Loading files…';}}
    try {
      let data = detailCache.get(key);
      if (!data) {data = await request(root.dataset.filesUrl + '?' + new URLSearchParams({folder: folder.id, page, generation})); detailCache.set(key, data);}
      if (comparison.generation !== generation || !target.isConnected) return;
      showFiles(folder, target, data, append);
    } catch (failure) {
      if (!append) target.replaceChildren(); else target.querySelector('.load-more')?.remove();
      target.append(element('p', 'inline-error', failure.message || 'File details could not load.'));
      const retry = element('button', 'secondary load-more', 'Try again'); retry.type = 'button';
      retry.addEventListener('click', () => loadDetail(folder, target, page, append)); target.append(retry);
    } finally {target.removeAttribute('aria-busy');}
  }
  function render() {
    list.replaceChildren();
    if (!comparison) return;
    const term = search.value.trim().toLowerCase();
    const folders = comparison.folders.filter(folder => (filter === 'all' || folder.changed) && `${folder.label} ${folder.path}`.toLowerCase().includes(term));
    folders.sort((a,b) => b.changed - a.changed || a.label.localeCompare(b.label));
    byId('changed-count').textContent = comparison.changed_folders;
    byId('all-count').textContent = comparison.folders.length;
    byId('comparison-summary').textContent = `${comparison.changed_files} changed files in ${comparison.changed_folders} folders`;
    byId('comparison-time').textContent = 'Checked ' + new Intl.DateTimeFormat(undefined, {hour:'2-digit', minute:'2-digit', day:'numeric', month:'short'}).format(new Date(comparison.checked_at * 1000));
    byId('no-matches').hidden = folders.length > 0 || (filter === 'changed' && !comparison.changed_folders && !term);
    byId('no-changes').hidden = !(filter === 'changed' && !comparison.changed_folders && !term);
    for (const folder of folders) {
      const row = element('div', 'folder-row'), header = element('div', 'folder-header');
      const selection = element('label', 'folder-selection');
      if (folder.whole_folder && folder.changed) {
        const box = element('input'); box.type = 'checkbox'; box.dataset.whole = folder.path; box.setAttribute('aria-label', 'Select changed files in ' + folder.label);
        box.addEventListener('change', () => {
          [...selected.keys()].filter(path => path.startsWith(folder.path + '/')).forEach(path => selected.delete(path));
          if (box.checked) selected.set(folder.path, {folder:true}); else selected.delete(folder.path);
          refreshRows();
        }); selection.append(box);
      }
      const toggle = element('button', 'folder-toggle'); toggle.type = 'button'; toggle.setAttribute('aria-expanded', open.has(folder.id)); toggle.setAttribute('aria-controls', 'files-' + folder.id);
      const title = element('span', 'folder-title'); title.append(element('strong', '', folder.label), element('small', '', `${folder.kind === 'themes' ? 'Theme' : 'Plugin'} / ${folder.name}`));
      toggle.append(icon('folder'), title, icon('chevron-right', 'chevron'));
      const counts = element('div', 'folder-counts');
      if (folder.changed) counts.append(badge(`${folder.changed} changed`, 'blue'));
      if (folder.website_only) counts.append(badge(`${folder.website_only} website only`));
      if (folder.excluded) counts.append(badge(`${folder.excluded} excluded`, 'warning'));
      if (!folder.changed && !folder.website_only && !folder.excluded) counts.append(badge('Matches', 'good'));
      header.append(selection, toggle, counts);
      const content = element('div', 'folder-content'); content.id = 'files-' + folder.id; content.hidden = !open.has(folder.id);
      toggle.addEventListener('click', () => {
        const expanded = toggle.getAttribute('aria-expanded') !== 'true'; toggle.setAttribute('aria-expanded', expanded); content.hidden = !expanded;
        if (expanded) {open.add(folder.id); if (!content.childNodes.length) loadDetail(folder, content);} else open.delete(folder.id);
      });
      row.append(header, content); list.append(row);
      if (open.has(folder.id)) loadDetail(folder, content);
    }
    refreshRows();
  }
  function jobState(job) {
    busy = Boolean(job?.running); blocked = Boolean(job?.blocked);
    progress.hidden = !busy;
    root.setAttribute('aria-busy', busy ? 'true' : 'false');
    if (busy) {
      if (job.operation !== 'compare') workflowWasRunning = true;
      const phases = {'scanning-website':'Checking website files', 'scanning-staging':'Checking staging files', 'comparing-code':'Comparing the files', 'queued':'Starting the file check'};
      byId('scan-phase').textContent = job.operation === 'compare' ? (phases[job.phase] || 'Checking code changes') : job.operation === 'deploy' ? 'Checking the code release' : 'Refreshing staging';
      progress.querySelector('p').textContent = job.operation === 'compare' ? 'Reading file contents to compare them. Nothing is being copied.' : 'Controls stay locked until this workflow finishes. The final result appears automatically.';
    }
    refreshRows();
  }
  async function poll() {
    clearTimeout(timer);
    try {
      const result = await request(root.dataset.statusUrl); failures = 0; announce(''); jobState(result.job);
      if (workflowWasRunning && !busy) {window.location.reload(); return;}
      if (result.comparison && result.comparison.generation !== comparison?.generation) {
        comparison = result.comparison; selected.clear(); open.clear(); detailCache.clear(); render();
      }
      if (!result.comparison && comparison) {comparison = null; selected.clear(); open.clear(); detailCache.clear(); list.replaceChildren(); selectionState();}
      byId('scan-results').hidden = !comparison || busy;
      byId('scan-empty').hidden = Boolean(comparison) || busy;
      if (result.job?.operation === 'compare' && result.job.failed && !busy) announce('The last file check did not finish. Nothing was changed. Try Check changes again.');
      if (blocked) announce('A release needs recovery before another check can start. Use Release history below.');
      if (busy) timer = setTimeout(poll, 1800);
    } catch (failure) {
      failures++; announce(failure.message || 'The current state could not be read. Try again shortly.');
      if (busy && failures < 4) timer = setTimeout(poll, 4000);
      else {busy = false; progress.hidden = true; root.setAttribute('aria-busy', 'false'); check.disabled = false; byId('review-selection').disabled = true;}
    }
  }
  check.addEventListener('click', async () => {
    if (busy || blocked) return;
    announce(''); busy = true; selectionState(); progress.hidden = false; byId('scan-empty').hidden = true;
    byId('scan-results').hidden = true;
    byId('scan-phase').textContent = 'Starting the file check';
    try {
      await request(root.dataset.checkUrl, {method:'POST', headers:{'X-CSRFToken': form.querySelector('[name=csrfmiddlewaretoken]').value}});
      await poll();
    } catch (failure) {busy = false; progress.hidden = true; announce(failure.message || 'The check could not start. Try again shortly.'); selectionState();}
  });
  byId('clear-selection').addEventListener('click', () => {selected.clear(); refreshRows();});
  let searchTimer;
  search.addEventListener('input', () => {clearTimeout(searchTimer); searchTimer = setTimeout(render, 120);});
  root.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => {
    filter = button.dataset.filter; root.querySelectorAll('[data-filter]').forEach(item => item.setAttribute('aria-pressed', item === button)); render();
  }));
  form.addEventListener('submit', event => {
    if (!selected.size || busy || blocked || byId('selected-files').value.length > 50000) {
      event.preventDefault(); delete form.dataset.submitting; form.removeAttribute('aria-busy');
      document.querySelectorAll('.submission-state').forEach(node => node.remove());
      announce('Choose a smaller group of files, or select a whole folder, before reviewing.');
    }
  });
  document.addEventListener('visibilitychange', () => {if (!document.hidden && !busy) poll();});
  poll();
})();
