/* Keep normal form navigation and browser validation; prevent duplicate work. */
'use strict';
function dependentFields(input) {
  document.querySelectorAll('[data-visible-for="' + input.id + '"]').forEach(group => {
    group.hidden = !input.checked;
    if (group.tagName === 'FIELDSET') group.disabled = !input.checked;
  });
}
function markUnsaved(input) {
  const card = input.closest('section'), form = input.closest('[data-track-settings]');
  card.classList.add('unsaved');
  const status = card.querySelector('[data-setting-status]');
  status.textContent = 'Unsaved'; status.className = 'pill pill-warning';
  form.querySelector('[data-save-settings]').disabled = false;
  form.querySelector('[data-settings-feedback]').textContent = 'You have unsaved changes';
}
document.querySelectorAll('[data-controls-fields]').forEach(input => {
  dependentFields(input);
  input.addEventListener('change', () => {
    dependentFields(input);
    markUnsaved(input);
    input.closest('section').querySelector('.control-description').textContent =
      (input.checked ? input.dataset.onDescription : input.dataset.offDescription) + ' Save to apply.';
  });
});
document.querySelectorAll('[data-track-settings] textarea').forEach(input => input.addEventListener('input', () => markUnsaved(input)));
// The badge's icon follows data-access; its tone is the same for unknown and public.
function accessBadge(state, text) {
  const badge = document.getElementById('access-badge');
  badge.dataset.access = state;
  badge.className = 'pill ' + (state === 'protected' ? 'pill-success' : 'pill-warning');
  badge.querySelector('[data-access-text]').textContent = text;
}
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
      accessBadge(result.protected ? 'protected' : 'public', result.protected ? 'Password required' : 'Public');
      document.getElementById('access-description').textContent = result.protected ? 'Only people with the staging password can open this copy.' : 'Anyone with the staging URL can view this copy.';
      feedback.textContent = 'Saved';
      input.disabled = false;
    } catch (_) {
      feedback.replaceChildren(document.createTextNode('The saved state could not be verified. '));
      const link = document.createElement('a'); link.href = window.location.pathname; link.textContent = 'Reload to check'; feedback.append(link);
      // Unknown is not reported as either the previous state or a saved change.
      accessBadge('unknown', 'Check required');
    }
  });
});
// Listening on the document lets a page's own form check run first and cancel
// the submission before this marks the form as busy.
document.addEventListener('submit', event => {
  const form = event.target;
  if (form.dataset.submitting === 'true') {event.preventDefault(); return;}
  if (event.defaultPrevented) return;
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
window.addEventListener('pageshow', () => {
  document.querySelectorAll('form[data-submitting]').forEach(form => {
    delete form.dataset.submitting;
    form.removeAttribute('aria-busy');
    form.querySelectorAll('[aria-disabled="true"]').forEach(button => button.removeAttribute('aria-disabled'));
  });
  document.querySelectorAll('.submission-state').forEach(node => node.remove());
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') document.querySelectorAll('.user-menu[open]').forEach(details => {
    details.open = false;
    details.querySelector('summary').focus();
  });
});
document.addEventListener('click', event => {
  document.querySelectorAll('.user-menu[open]').forEach(details => {
    if (!details.contains(event.target)) details.open = false;
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
      if (result.step !== null) target.querySelectorAll('[data-step]').forEach((step, index) => {
        step.dataset.state = index < result.step ? 'done' : index === result.step ? 'current' : 'pending';
        if (index === result.step) step.setAttribute('aria-current', 'step'); else step.removeAttribute('aria-current');
      });
      failures = 0;
    } catch (_) {
      if (++failures >= 4) {
        target.querySelector('[data-job-label]').textContent = 'The current state could not be checked.';
        const link = document.createElement('a'); link.href = window.location.pathname; link.textContent = 'Reload to check the result';
        target.querySelector('[data-job-label]').after(' ', link); return;
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
        document.getElementById('history-updated').textContent = parsed.getElementById('history-updated').textContent;
        feedback.textContent = 'Updates every minute while this page is open.';
        feedback.className = 'toolbar-note';
      } catch (_) {
        feedback.textContent = 'Automatic updates are unavailable. The values below are the last loaded snapshot. Refresh to check again.';
        feedback.className = 'alert alert-warning';
      }
    }
    setTimeout(refreshHistory, 60000);
  }
  setTimeout(refreshHistory, 60000);
}
