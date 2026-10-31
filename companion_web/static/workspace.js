/* Keep normal form navigation and browser validation; prevent duplicate work. */
'use strict';
function dependentFields(input) {
  document.querySelectorAll('[data-visible-for="' + input.id + '"]').forEach(group => {
    group.hidden = !input.checked;
    if (group.tagName === 'FIELDSET') group.disabled = !input.checked;
  });
}
document.querySelectorAll('[data-controls-fields]').forEach(input => {
  dependentFields(input);
  input.addEventListener('change', () => {
    dependentFields(input);
    const card = input.closest('section');
    if (card) {
      card.classList.add('unsaved');
      const status = card.querySelector('[data-setting-status]');
      if (status) {status.textContent = 'Unsaved'; status.className = 'badge warning';}
      const description = card.querySelector('.control-description');
      if (description) description.textContent = (input.checked ? input.dataset.onDescription : input.dataset.offDescription) + ' Save to apply.';
    }
    const form = input.closest('form');
    if (form) {const save = form.querySelector('[data-save-settings]'); if (save) save.disabled = false;}
    form?.querySelector('[data-settings-feedback]')?.replaceChildren(document.createTextNode('You have unsaved changes'));
  });
});
document.querySelectorAll('[data-track-settings] textarea').forEach(input => input.addEventListener('input', () => {
  input.closest('section').classList.add('unsaved');
  const form = input.closest('form'); form.querySelector('[data-save-settings]').disabled = false;
  form.querySelector('[data-settings-feedback]').textContent = 'You have unsaved changes';
}));
document.querySelectorAll('[data-access-switch]').forEach(form => {
  const input = form.querySelector('[role=switch]'), feedback = form.querySelector('[data-access-feedback]');
  input.addEventListener('change', async () => {
    input.disabled = true;
    feedback.textContent = 'Saving access…';
    const body = new FormData(form);
    // Disabled controls are omitted by FormData; preserve this explicit intent.
    body.set('enabled', input.checked ? 'true' : 'false');
    try {
      const response = await fetch(form.action, {method:'POST', body, credentials:'same-origin',
        headers:{Accept:'application/json'}, signal:AbortSignal.timeout(45000)});
      if (response.redirected || !response.headers.get('content-type')?.includes('application/json')) throw Error();
      const result = await response.json();
      if (!response.ok) {
        if (result.reauthenticate) {
          input.checked = !input.checked;
          feedback.replaceChildren(document.createTextNode(result.error + ' '));
          const link = document.createElement('a'); link.href = result.reauthenticate; link.textContent = 'Unlock changes'; feedback.append(link);
          input.disabled = false;
          return;
        }
        throw Error();
      }
      input.checked = result.protected;
      dependentFields(input);
      const badge = document.getElementById('access-badge');
      badge.textContent = result.protected ? 'Password required' : 'Public';
      badge.className = 'badge ' + (result.protected ? 'good' : 'warning');
      document.getElementById('access-description').textContent = result.protected ? 'Only people with the staging password can open this copy.' : 'Anyone with the staging URL can view this copy.';
      feedback.textContent = 'Saved';
      input.disabled = false;
    } catch (_) {
      feedback.replaceChildren(document.createTextNode('The saved state could not be verified. '));
      const link = document.createElement('a'); link.href = window.location.pathname; link.textContent = 'Reload to check'; feedback.append(link);
      // Unknown is not reported as either the previous state or a saved change.
      const badge = document.getElementById('access-badge'); badge.textContent = 'Check required'; badge.className = 'badge warning';
    }
  });
});
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', event => {
    if (event.defaultPrevented || form.dataset.submitting === 'true') {
      if (form.dataset.submitting === 'true') event.preventDefault();
      return;
    }
    form.dataset.submitting = 'true';
    form.setAttribute('aria-busy', 'true');
    if (event.submitter) {
      // Retain successful button name/value, including allauth's action controls.
      event.submitter.setAttribute('aria-disabled', 'true');
    }
    const label = document.createElement('span');
    label.className = 'submission-state';
    label.setAttribute('role', 'status');
    label.textContent = form.dataset.submitLabel || 'Saving…';
    (event.submitter || form).insertAdjacentElement('afterend', label);
  });
});
window.addEventListener('pageshow', () => {
  document.querySelectorAll('form[data-submitting]').forEach(form => {
    delete form.dataset.submitting;
    form.removeAttribute('aria-busy');
    form.querySelectorAll('[aria-disabled="true"]').forEach(button => button.removeAttribute('aria-disabled'));
  });
  document.querySelectorAll('.submission-state').forEach(node => node.remove());
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') document.querySelectorAll('.account-nav[open]').forEach(details => {
    details.open = false;
    details.querySelector('summary').focus();
  });
});
document.querySelectorAll('[data-job-watch]').forEach(target => {
  let failures = 0;
  async function update() {
    try {
      const response = await fetch(target.dataset.jobWatch, {credentials:'same-origin', signal:AbortSignal.timeout(45000)});
      if (!response.ok || response.redirected || !response.headers.get('content-type')?.includes('application/json')) throw Error();
      const result = await response.json();
      if (!result.job?.running) {window.location.reload(); return;}
      target.querySelector('[data-job-label]').textContent = result.label;
      failures = 0;
    } catch (_) {
      if (++failures >= 4) {
        target.querySelector('[data-job-label]').textContent = 'The current state could not be checked.';
        const link = document.createElement('a'); link.href = window.location.pathname; link.textContent = 'Reload to check the result';
        target.append(link); return;
      }
    }
    setTimeout(update, 2200);
  }
  update();
});

if (document.querySelector('[data-history-refresh]')) {
  async function refreshHistory() {
    const target = document.querySelector('[data-history-refresh]');
    const feedback = document.getElementById('history-refresh-status');
    // Do not interrupt keyboard navigation or text selection while inspecting
    // a table. Hidden tabs make no monitoring requests.
    if (document.visibilityState === 'visible' && !window.getSelection()?.toString() && !target.contains(document.activeElement)) {
      try {
        const response = await fetch(window.location.href, {credentials:'same-origin', signal:AbortSignal.timeout(15000)});
        if (!response.ok || response.redirected || !response.headers.get('content-type')?.includes('text/html')) throw Error();
        const parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
        const replacement = parsed.querySelector('[data-history-refresh]');
        if (!replacement) throw Error();
        const open = new Set(Array.from(target.querySelectorAll('details[open]')).map(node => node.querySelector('summary').textContent.trim()));
        replacement.querySelectorAll('details').forEach(node => {node.open = open.has(node.querySelector('summary').textContent.trim());});
        target.replaceWith(replacement);
        const current = document.querySelector('.monitor-toolbar>.muted');
        current.textContent = parsed.querySelector('.monitor-toolbar>.muted').textContent;
        feedback.textContent = 'Updates every minute while this page is open.';
        feedback.className = 'field-help';
      } catch (_) {
        feedback.textContent = 'Automatic updates are unavailable. The values below are the last loaded snapshot. Refresh to check again.';
        feedback.className = 'notice warning';
      }
    }
    setTimeout(refreshHistory, 60000);
  }
  setTimeout(refreshHistory, 60000);
}
