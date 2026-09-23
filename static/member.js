const token = document.getElementById('mail-token');
if (token) {
  const fragment = location.hash.slice(1);
  if (fragment.startsWith('token=')) {
    const values = new URLSearchParams(fragment);
    token.value = values.get('token') || '';
    document.getElementById('mail-next').value = values.get('next') || '';
  } else {
    token.value = fragment;
  }
  history.replaceState(null, '', location.pathname);
}

const returnToApp = document.getElementById('return-to-app');
if (returnToApp) {
  const android = /Android/i.test(navigator.userAgent);
  if (android) returnToApp.href = returnToApp.dataset.androidReturnUri;
}

const textarea = document.getElementById('configuration');
const sources = document.getElementById('sources');
if (textarea && sources) {
  const form = document.getElementById('config-form');
  const revision = document.getElementById('configuration-revision');
  const saveStatus = document.getElementById('save-status');
  const globalRulesMode = document.getElementById('global-rules-mode');
  const globalRulesLink = document.getElementById('global-rules-link');
  const rulesDetection = document.getElementById('rules-detection');
  const rulesPrimary = document.getElementById('rules-primary');
  const rulesCancel = document.getElementById('rules-cancel');
  const canonicalLoyalsoldier = 'https://github.com/Loyalsoldier/clash-rules';
  let data = JSON.parse(textarea.value);
  data.appBypass ||= { windowsExecutables: [], androidPackages: [] };
  data.globalRules ||= { mode: 'subscription' };
  data.defaultSubscriptionId ||= data.subscriptions[0]?.id;
  let lastSaved = JSON.stringify(data);
  let saveTimer = null;
  let saving = false;
  let saveAgain = false;
  let advancedValid = true;
  let draftSource = null;
  let editingSource = null;
  let editingSourceDirty = false;
  let rulesEditing = !data.globalRules.sourceUrl;
  let rulesDirty = false;

  const persist = () => { textarea.value = JSON.stringify(data, null, 2); };
  const setSaveStatus = (message, state = '') => {
    saveStatus.textContent = message;
    saveStatus.dataset.state = state;
  };
  const showSavedStatus = version => setSaveStatus(
    draftSource
      ? 'Settings saved · new subscription still needs Add'
      : `Saved automatically · version ${version}`,
    'saved',
  );
  const sourceReady = entry => {
    if (!String(entry.name || '').trim()) return false;
    try {
      const url = new URL(entry.url);
      return url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password && !url.hash;
    } catch {
      return false;
    }
  };
  const configurationReady = () => data.subscriptions.every(sourceReady) && (() => {
    const sourceUrl = String(data.globalRules.sourceUrl || '').trim();
    if (data.globalRules.mode === 'subscription') return !sourceUrl;
    try {
      const url = new URL(sourceUrl);
      return url.protocol === 'https:'
        && ['github.com', 'raw.githubusercontent.com'].includes(url.hostname.toLowerCase())
        && !url.username && !url.password && !url.hash
        && url.pathname.split('/').filter(Boolean).length >= 2;
    } catch {
      return false;
    }
  })();
  const saveNow = async () => {
    clearTimeout(saveTimer);
    saveTimer = null;
    persist();
    if (!advancedValid) {
      setSaveStatus('Not saved · fix the Advanced JSON', 'error');
      return false;
    }
    if (!configurationReady()) {
      setSaveStatus('Waiting for complete saved subscription details', 'waiting');
      return false;
    }
    const serialized = JSON.stringify(data);
    if (serialized === lastSaved) {
      showSavedStatus(revision.value);
      return true;
    }
    if (saving) {
      saveAgain = true;
      return false;
    }
    saving = true;
    setSaveStatus('Saving…', 'saving');
    const body = new FormData(form);
    try {
      const response = await fetch(form.action || location.pathname, {
        method: 'POST',
        body,
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      });
      const result = await response.json();
      if (!response.ok || !result.saved) {
        throw Object.assign(new Error(result.error || 'Could not save.'), { conflict: response.status === 409 });
      }
      revision.value = String(result.revision);
      lastSaved = serialized;
      showSavedStatus(result.revision);
      return true;
    } catch (error) {
      setSaveStatus(
        error.conflict
          ? 'Not saved · this configuration changed elsewhere. Reload the latest saved version.'
          : `Not saved · ${error.message}`,
        'error',
      );
      return false;
    } finally {
      saving = false;
      if (saveAgain) {
        saveAgain = false;
        saveNow();
      }
    }
  };
  const queueSave = (delay = 1200) => {
    persist();
    setSaveStatus('Unsaved changes…', 'pending');
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, delay);
  };
  const sourceTitle = entry => String(entry.name || '').trim() || 'New subscription';
  const createTrashIcon = () => {
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M9 3h6l1 2h4v2H4V5h4l1-2Zm-3 6h12l-1 12H7L6 9Zm3 2v7h2v-7H9Zm4 0v7h2v-7h-2Z');
    icon.append(path);
    return icon;
  };

  const render = ({ openId = null, focusNameId = null } = {}) => {
    sources.replaceChildren();
    const entries = [...data.subscriptions, ...(draftSource ? [draftSource] : [])];
    for (const storedEntry of entries) {
      const isDraft = storedEntry === draftSource;
      const isEditing = !isDraft && editingSource?.id === storedEntry.id;
      const entry = isEditing ? editingSource.value : storedEntry;
      const row = document.createElement('details');
      row.className = `source${isDraft ? '' : ' is-saved'}`;
      row.open = entry.id === openId || isEditing;
      const summary = document.createElement('summary');
      summary.className = 'source-summary';
      summary.textContent = sourceTitle(entry);
      const fields = document.createElement('div');
      fields.className = 'source-fields';
      row.append(summary, fields);

      for (const [key, label] of [['name', 'Name'], ['url', 'Subscription URL']]) {
        const wrap = document.createElement('label');
        wrap.textContent = label;
        const field = document.createElement('input');
        field.value = entry[key];
        field.disabled = !isDraft && !isEditing;
        field.autocomplete = 'off';
        field.spellcheck = false;
        field.required = true;
        if (key === 'url') {
          field.type = 'url';
          field.inputMode = 'url';
        }
        field.addEventListener('invalid', () => { row.open = true; });
        field.addEventListener('input', () => {
          entry[key] = field.value;
          if (key === 'name') summary.textContent = sourceTitle(entry);
          if (isDraft) {
            setSaveStatus(
              sourceReady(entry) ? 'Ready to add subscription' : 'Complete the new subscription, then choose Add',
              'waiting',
            );
          } else {
            editingSourceDirty = true;
            setSaveStatus('Editing subscription · choose Save or Cancel', 'pending');
          }
        });
        wrap.append(field);
        fields.append(wrap);
        if (key === 'name' && entry.id === focusNameId) requestAnimationFrame(() => field.focus());
      }

      const actions = document.createElement('div');
      actions.className = 'source-actions';
      if (isDraft) {
        const add = document.createElement('button');
        add.type = 'button';
        add.className = 'source-add';
        add.textContent = 'Add';
        add.onclick = async () => {
          if (!sourceReady(entry)) {
            for (const field of fields.querySelectorAll('input')) field.reportValidity();
            setSaveStatus('Complete the new subscription, then choose Add', 'waiting');
            return;
          }
          if (saving) {
            setSaveStatus('Please wait for the current save to finish', 'waiting');
            return;
          }
          add.disabled = true;
          draftSource = null;
          data.subscriptions.push(entry);
          data.defaultSubscriptionId ||= entry.id;
          const saved = await saveNow();
          if (!saved) {
            data.subscriptions = data.subscriptions.filter(item => item !== entry);
            if (data.defaultSubscriptionId === entry.id) data.defaultSubscriptionId = data.subscriptions[0]?.id;
            draftSource = entry;
            persist();
          }
          render({ openId: entry.id });
        };
        actions.append(add);
      } else if (isEditing) {
        const save = document.createElement('button');
        save.type = 'button';
        save.textContent = 'Save';
        save.onclick = async () => {
          if (!sourceReady(entry)) {
            for (const field of fields.querySelectorAll('input')) field.reportValidity();
            setSaveStatus('Complete the name and HTTPS subscription URL', 'waiting');
            return;
          }
          const index = data.subscriptions.findIndex(item => item.id === storedEntry.id);
          const previous = data.subscriptions[index];
          data.subscriptions[index] = entry;
          const saved = await saveNow();
          if (saved) {
            editingSource = null;
            editingSourceDirty = false;
          } else {
            data.subscriptions[index] = previous;
          }
          render({ openId: entry.id });
        };
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'secondary';
        cancel.textContent = 'Cancel';
        cancel.onclick = () => {
          editingSource = null;
          editingSourceDirty = false;
          showSavedStatus(revision.value);
          render({ openId: storedEntry.id });
        };
        actions.append(save, cancel);
      } else {
        const edit = document.createElement('button');
        edit.type = 'button';
        edit.className = 'secondary';
        edit.textContent = 'Edit';
        edit.onclick = () => {
          editingSource = { id: storedEntry.id, value: structuredClone(storedEntry) };
          editingSourceDirty = false;
          render({ openId: storedEntry.id, focusNameId: storedEntry.id });
        };
        const makeDefault = document.createElement('button');
        makeDefault.type = 'button';
        makeDefault.className = 'secondary default-button';
        makeDefault.disabled = data.defaultSubscriptionId === storedEntry.id;
        makeDefault.textContent = data.defaultSubscriptionId === storedEntry.id ? '★ Default' : '☆ Make default';
        makeDefault.onclick = () => {
          data.defaultSubscriptionId = storedEntry.id;
          render({ openId: storedEntry.id });
          queueSave(0);
        };
        actions.append(edit, makeDefault);
      }

      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'danger icon-button';
      remove.title = 'Remove source';
      remove.setAttribute('aria-label', 'Remove source');
      remove.append(createTrashIcon());
      remove.onclick = () => {
        if (isDraft) {
          draftSource = null;
          render();
          showSavedStatus(revision.value);
          return;
        }
        editingSource = null;
        editingSourceDirty = false;
        data.subscriptions = data.subscriptions.filter(item => item.id !== storedEntry.id);
        if (data.defaultSubscriptionId === storedEntry.id) data.defaultSubscriptionId = data.subscriptions[0]?.id;
        persist();
        render();
        queueSave(0);
      };
      actions.append(remove);
      fields.append(actions);
      sources.append(row);
    }
  };

  document.getElementById('add-source').onclick = () => {
    if (draftSource) {
      render({ openId: draftSource.id, focusNameId: draftSource.id });
      setSaveStatus('Complete the new subscription, then choose Add', 'waiting');
      return;
    }
    editingSource = null;
    editingSourceDirty = false;
    draftSource = {
      id: crypto.randomUUID().replaceAll('-', ''),
      name: '',
      url: '',
      rules: [],
      autoUpdateHours: 24,
    };
    render({ openId: draftSource.id, focusNameId: draftSource.id });
    setSaveStatus('Complete the new subscription, then choose Add', 'waiting');
  };

  const identifyRulesLink = (value, preferredMode = '') => {
    const sourceUrl = String(value || '').trim();
    if (!sourceUrl) return { mode: 'subscription', sourceUrl: '', message: "Using each subscription's own rules.", state: '' };
    try {
      const url = new URL(sourceUrl);
      const host = url.hostname.toLowerCase();
      const parts = url.pathname.split('/').filter(Boolean);
      if (url.protocol !== 'https:' || !['github.com', 'raw.githubusercontent.com'].includes(host) || url.username || url.password || url.hash || parts.length < 2) throw Error();
      if (parts[0].toLowerCase() === 'loyalsoldier' && parts[1].replace(/\.git$/i, '').toLowerCase() === 'clash-rules') {
        const mode = preferredMode === 'loyalsoldier-blacklist' ? preferredMode : 'loyalsoldier-whitelist';
        const label = mode === 'loyalsoldier-blacklist' ? 'blacklist setup' : 'recommended whitelist setup';
        return { mode, sourceUrl: canonicalLoyalsoldier, message: `Recognized Loyalsoldier rules · ${label} selected.`, state: 'recognized' };
      }
      return { mode: 'github-auto', sourceUrl, message: 'GitHub link accepted · choose Add or Save to apply it.', state: 'recognized' };
    } catch {
      return { mode: null, sourceUrl, message: 'Use an HTTPS GitHub repository, folder, file, or raw-file link.', state: 'error' };
    }
  };
  const showRulesDetection = identified => {
    rulesDetection.textContent = identified.message;
    rulesDetection.dataset.state = identified.state;
  };
  const resetRulesControls = () => {
    globalRulesMode.value = data.globalRules.mode;
    globalRulesLink.value = data.globalRules.sourceUrl || '';
    globalRulesLink.disabled = !rulesEditing;
    globalRulesMode.disabled = !rulesEditing;
    rulesPrimary.textContent = rulesEditing
      ? (data.globalRules.sourceUrl ? 'Save' : 'Add')
      : 'Edit';
    rulesCancel.hidden = !rulesEditing || !data.globalRules.sourceUrl;
    showRulesDetection(identifyRulesLink(globalRulesLink.value, data.globalRules.mode));
  };
  rulesPrimary.addEventListener('click', async () => {
    if (!rulesEditing) {
      rulesEditing = true;
      rulesDirty = false;
      resetRulesControls();
      globalRulesLink.focus();
      return;
    }
    const identified = identifyRulesLink(globalRulesLink.value, globalRulesMode.value);
    if (!identified.mode || (!identified.sourceUrl && !data.globalRules.sourceUrl)) {
      globalRulesLink.reportValidity();
      setSaveStatus('Enter a valid GitHub rules link, then choose Add', 'waiting');
      return;
    }
    const previous = data.globalRules;
    data.globalRules = identified.sourceUrl
      ? { mode: identified.mode, sourceUrl: identified.sourceUrl }
      : { mode: 'subscription' };
    const saved = await saveNow();
    if (saved) {
      rulesEditing = false;
      rulesDirty = false;
    } else {
      data.globalRules = previous;
    }
    resetRulesControls();
  });
  rulesCancel.addEventListener('click', () => {
    rulesEditing = false;
    rulesDirty = false;
    resetRulesControls();
    showSavedStatus(revision.value);
  });
  globalRulesLink.addEventListener('input', () => {
    const identified = identifyRulesLink(globalRulesLink.value, globalRulesMode.value);
    showRulesDetection(identified);
    if (identified.mode) globalRulesMode.value = identified.mode;
    rulesDirty = true;
    setSaveStatus(identified.mode ? 'Ready to add or save rules link' : 'Not saved · check the GitHub rules link', identified.mode ? 'pending' : 'error');
  });
  globalRulesMode.addEventListener('change', () => {
    if (globalRulesMode.value === 'subscription') globalRulesLink.value = '';
    if (['loyalsoldier-whitelist', 'loyalsoldier-blacklist'].includes(globalRulesMode.value)) globalRulesLink.value = canonicalLoyalsoldier;
    showRulesDetection(identifyRulesLink(globalRulesLink.value, globalRulesMode.value));
    rulesDirty = true;
    setSaveStatus('Ready to save rules setting', 'pending');
  });
  resetRulesControls();

  for (const [id, key] of [['windows-bypass', 'windowsExecutables'], ['android-bypass', 'androidPackages']]) {
    const field = document.getElementById(id);
    field.value = (data.appBypass[key] || []).join('\n');
    field.addEventListener('input', () => {
      data.appBypass[key] = [...new Set(field.value.split('\n').map(value => value.trim()).filter(Boolean))];
      queueSave();
    });
    field.addEventListener('change', saveNow);
  }

  textarea.addEventListener('input', () => {
    advancedValid = false;
    setSaveStatus('Unsaved changes…', 'pending');
  });
  textarea.addEventListener('change', () => {
    try {
      const parsed = JSON.parse(textarea.value);
      if (!Array.isArray(parsed.subscriptions)) throw Error();
      data = parsed;
      data.appBypass ||= { windowsExecutables: [], androidPackages: [] };
      data.globalRules ||= { mode: 'subscription' };
      data.defaultSubscriptionId ||= data.subscriptions[0]?.id;
      document.getElementById('windows-bypass').value = (data.appBypass.windowsExecutables || []).join('\n');
      document.getElementById('android-bypass').value = (data.appBypass.androidPackages || []).join('\n');
      editingSource = null;
      editingSourceDirty = false;
      rulesEditing = !data.globalRules.sourceUrl;
      rulesDirty = false;
      advancedValid = true;
      resetRulesControls();
      render();
      document.getElementById('editor-error').textContent = '';
      queueSave(0);
    } catch {
      advancedValid = false;
      document.getElementById('editor-error').textContent = 'Invalid JSON. Review the configuration before saving.';
      setSaveStatus('Not saved · fix the Advanced JSON', 'error');
    }
  });
  form.addEventListener('submit', event => {
    event.preventDefault();
    saveNow();
  });
  window.addEventListener('beforeunload', event => {
    if (draftSource || editingSourceDirty || rulesDirty || saveTimer || saving) {
      event.preventDefault();
      event.returnValue = '';
    }
  });
  render();
}

for (const form of document.querySelectorAll('form:not(#config-form)')) {
  form.addEventListener('submit', () => {
    const button = form.querySelector('button:not([type="button"])');
    if (button && !button.name) {
      button.disabled = true;
      button.textContent = 'Working…';
    }
  });
}
