// Firewatch EDR — Frontend Logic
// Connects the dashboard to the Remediation Engine API.

const API = '';  // nginx proxies /api/ → backend:8000
let DEMO = { tenant_id: null, incident_id: null };
let currentExecId = null;
let actionLogMap = {};  // action title → DOM element (for live updates)

// ── First-run setup wizard ─────────────────────────────────────────────────────

async function checkSetup() {
  try {
    const r = await fetch(`${API}/api/setup/status`);
    if (!r.ok) return false;
    const { complete } = await r.json();
    return complete;
  } catch {
    return false;
  }
}

async function completeSetup() {
  const orgName   = document.getElementById('setup-org').value.trim();
  const apiKey    = document.getElementById('setup-apikey').value.trim();
  const errEl     = document.getElementById('setup-error');

  errEl.style.display = 'none';

  if (!orgName) {
    errEl.textContent = 'Organization name is required.';
    errEl.style.display = 'block';
    return;
  }

  try {
    const r = await fetch(`${API}/api/setup/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ org_name: orgName, anthropic_api_key: apiKey || null }),
    });

    if (!r.ok) {
      const err = await r.json();
      errEl.textContent = err.detail || 'Setup failed.';
      errEl.style.display = 'block';
      return;
    }

    const data = await r.json();
    document.getElementById('setup-wizard').style.display = 'none';
    document.querySelector('.user-name').textContent = data.tenant_name;
    showToast('Setup complete. Welcome to Firewatch EDR!', 'info');

    // Load demo incident for this tenant
    await loadDemoState();

  } catch (e) {
    errEl.textContent = 'Could not connect to backend. Is Docker running?';
    errEl.style.display = 'block';
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

async function loadDemoState() {
  try {
    const r = await fetch(`${API}/api/demo/state`);
    if (!r.ok) return;
    DEMO = await r.json();
    document.querySelector('.user-name').textContent = DEMO.tenant_name || 'Tu empresa';
    setBackendStatus(true);
  } catch {
    setBackendStatus(false);
  }
}

async function init() {
  // Check if first-run setup is needed
  const setupComplete = await checkSetup();

  if (!setupComplete) {
    // Show wizard — check if ANTHROPIC_API_KEY is configured
    const healthR = await fetch(`${API}/health`).catch(() => null);
    if (healthR?.ok) {
      const health = await healthR.json();
      if (!health.anthropic_configured) {
        document.getElementById('setup-apikey-row').style.display = 'block';
      }
    }
    document.getElementById('setup-wizard').style.display = 'flex';
    return;
  }

  await loadDemoState();
}

function setBackendStatus(online) {
  const dot = document.querySelector('.live-dot');
  const badge = document.querySelector('.live-badge');
  if (online) {
    dot.style.background = 'var(--green)';
    badge.innerHTML = '<div class="live-dot"></div>En vivo';
  } else {
    dot.style.background = 'var(--amber)';
    badge.innerHTML = '<div class="live-dot" style="background:var(--amber)"></div>Demo';
  }
}

// ── Remediation entry points ──────────────────────────────────────────────────

async function handleRemediate(mode) {
  // mode: 'full' | 'autonomous' | 'monitor'
  if (!DEMO.incident_id) {
    showToast('Backend no disponible', 'error');
    return;
  }

  if (mode === 'monitor') {
    showToast('Modo monitoreo activado — sin intervención', 'info');
    return;
  }

  showLoading('AI analizando incidente...');

  try {
    // 1. Generate plan via Claude AI
    const planRes = await fetch(`${API}/api/remediation/plans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_id: DEMO.incident_id,
        tenant_id: DEMO.tenant_id,
      }),
    });
    if (!planRes.ok) throw new Error(await planRes.text());
    const planMeta = await planRes.json();

    // 2. Get full consent payload
    const consentRes = await fetch(
      `${API}/api/remediation/plans/${planMeta.plan_id}/consent?tenant_id=${DEMO.tenant_id}`
    );
    if (!consentRes.ok) throw new Error(await consentRes.text());
    const consent = await consentRes.json();

    hideLoading();

    if (mode === 'autonomous') {
      // Auto-approve without showing consent UI (AI autonomous mode)
      showToast('Modo autónomo — ejecutando sin intervención...', 'info');
      await approveAndExecute(consent.plan_id, [], 'AI Autónomo');
    } else {
      // Show consent modal for user review
      showConsentModal(consent);
    }
  } catch (e) {
    hideLoading();
    showToast('Error: ' + (e.message || 'desconocido'), 'error');
    console.error(e);
  }
}

// ── Consent Modal ─────────────────────────────────────────────────────────────

function showConsentModal(consent) {
  const modal = document.getElementById('consent-modal');

  document.getElementById('cm-title').textContent = consent.title;
  document.getElementById('cm-analysis').textContent = consent.ai_analysis || 'Sin análisis disponible.';
  document.getElementById('cm-confidence').textContent =
    Math.round((consent.ai_confidence || 0) * 100) + '%';

  const impactEl = document.getElementById('cm-impact');
  impactEl.textContent = consent.overall_impact?.toUpperCase();
  impactEl.className = 'badge ' + impactBadge(consent.overall_impact);

  document.getElementById('cm-duration').textContent =
    (consent.estimated_duration_seconds || 0) + 's estimados';

  // Actions list
  document.getElementById('cm-actions').innerHTML = (consent.actions || []).map(a => `
    <div class="cm-action">
      <div class="cm-action-head">
        <span class="impact-dot impact-${a.impact_level}"></span>
        <span class="cm-action-title">${escHtml(a.title)}</span>
        ${a.target ? `<span class="cm-action-target">${escHtml(a.target)}</span>` : ''}
        <span class="cm-action-badges">
          <span class="badge ${impactBadge(a.impact_level)}">${a.impact_level}</span>
          ${a.reversible
            ? '<span class="badge bb">reversible</span>'
            : '<span class="badge bc">irreversible ⚠</span>'}
        </span>
      </div>
      ${a.impact_description
        ? `<div class="cm-action-desc">${escHtml(a.impact_description)}</div>`
        : ''}
    </div>
  `).join('');

  // Warnings
  const warnEl = document.getElementById('cm-warnings');
  if (consent.warnings?.length) {
    warnEl.innerHTML = consent.warnings.map(w =>
      `<div class="cm-warning">⚠️ ${escHtml(w)}</div>`
    ).join('');
    warnEl.style.display = 'block';
  } else {
    warnEl.style.display = 'none';
  }

  modal.dataset.planId = consent.plan_id;
  modal.style.display = 'flex';
}

function hideConsentModal() {
  document.getElementById('consent-modal').style.display = 'none';
}

async function approveConsent() {
  const planId = document.getElementById('consent-modal').dataset.planId;
  hideConsentModal();
  await approveAndExecute(planId, [], 'pablo.sosto');
}

async function rejectPlan() {
  const planId = document.getElementById('consent-modal').dataset.planId;
  try {
    await fetch(`${API}/api/remediation/plans/${planId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: DEMO.tenant_id,
        actor: 'pablo.sosto',
        notes: 'Rechazado manualmente desde el dashboard',
      }),
    });
  } catch {}
  hideConsentModal();
  showToast('Plan rechazado', 'info');
}

// ── Execute ───────────────────────────────────────────────────────────────────

async function approveAndExecute(planId, excludedIds, actor) {
  showLoading('Iniciando ejecución...');
  try {
    const res = await fetch(`${API}/api/remediation/plans/${planId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: DEMO.tenant_id,
        actor: actor || 'pablo.sosto',
        excluded_action_ids: excludedIds || [],
      }),
    });
    if (!res.ok) throw new Error(await res.text());
    const exec = await res.json();

    hideLoading();
    showExecutionModal(exec.execution_id);
  } catch (e) {
    hideLoading();
    showToast('Error al aprobar: ' + e.message, 'error');
  }
}

// ── Execution Modal ───────────────────────────────────────────────────────────

function showExecutionModal(executionId) {
  currentExecId = executionId;
  actionLogMap = {};

  // Reset UI
  const modal = document.getElementById('exec-modal');
  document.getElementById('em-log').innerHTML = '';
  document.getElementById('em-progress').style.cssText = 'width:0%;background:var(--green)';
  document.getElementById('em-status').textContent = 'Ejecutando...';
  document.getElementById('em-status').className = 'em-status running';
  document.getElementById('em-rollback-btn').style.display = 'none';
  document.getElementById('em-close-btn').style.display = 'none';
  document.getElementById('em-exec-id').textContent = executionId.slice(0, 8) + '...';

  modal.style.display = 'flex';

  // WebSocket
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/api/remediation/executions/${executionId}/ws`);

  ws.onopen = () => appendLog('🔌 Conectado al motor de ejecución', 'info');
  ws.onerror = () => {
    appendLog('⚠️ WebSocket no disponible — usando polling', 'warn');
    pollExecution(executionId);
  };
  ws.onmessage = (e) => {
    try { handleExecEvent(JSON.parse(e.data)); } catch {}
  };
}

function handleExecEvent(ev) {
  const progress = document.getElementById('em-progress');

  switch (ev.event) {
    case 'started':
      appendLog('🚀 Ejecución iniciada', 'info');
      animateProgress(20);
      break;

    case 'action_started':
      appendLog(
        `⏳ ${ev.action}${ev.target ? '  →  ' + ev.target : ''}`,
        'running',
        ev.action
      );
      break;

    case 'action_success':
      updateLog(
        ev.action,
        'success',
        `✅ ${ev.action}${ev.duration_ms ? '  (' + ev.duration_ms + 'ms)' : ''}`
      );
      incrementProgress();
      break;

    case 'action_failed':
      updateLog(ev.action, 'failed', `❌ ${ev.action}: ${ev.error || 'error desconocido'}`);
      break;

    case 'action_skipped':
      appendLog(`⏭️ Omitido: ${ev.action}`, 'warn');
      break;

    case 'rollback_started':
      appendLog('↩️ Rollback iniciado automáticamente...', 'warn');
      document.getElementById('em-status').textContent = 'Rollback en progreso...';
      document.getElementById('em-status').className = 'em-status rolling-back';
      progress.style.background = 'var(--amber)';
      break;

    case 'rollback_action':
      appendLog(
        `${ev.success ? '↩️' : '⚠️'} Rollback: ${ev.action}`,
        ev.success ? 'info' : 'warn'
      );
      break;

    case 'rollback_completed':
      appendLog('✅ Rollback completado', 'info');
      setFinalStatus('rolled_back');
      break;

    case 'completed':
      setFinalStatus(ev.status, ev.summary);
      break;
  }
}

function setFinalStatus(status, summary) {
  const statusEl = document.getElementById('em-status');
  const progress = document.getElementById('em-progress');

  const configs = {
    completed:   { text: '✅ Completado exitosamente', cls: 'completed',   prog: '100%', bg: 'var(--green)' },
    failed:      { text: '❌ Ejecución fallida',        cls: 'failed',      prog: null,   bg: 'var(--red)'   },
    rolled_back: { text: '↩️ Revertido',                cls: 'rolled-back', prog: '100%', bg: 'var(--amber)' },
  };

  const cfg = configs[status] || configs.failed;
  statusEl.textContent = cfg.text;
  statusEl.className = 'em-status ' + cfg.cls;
  if (cfg.prog) progress.style.width = cfg.prog;
  progress.style.background = cfg.bg;

  if (summary) appendLog(summary, 'info');
  if (status === 'failed') document.getElementById('em-rollback-btn').style.display = 'inline-flex';
  document.getElementById('em-close-btn').style.display = 'inline-flex';
}

// ── Log helpers ───────────────────────────────────────────────────────────────

function appendLog(text, type = 'info', actionKey = null) {
  const log = document.getElementById('em-log');
  const item = document.createElement('div');
  item.className = `em-log-item ${type}`;
  item.textContent = text;
  if (actionKey) actionLogMap[actionKey] = item;
  log.appendChild(item);
  log.scrollTop = log.scrollHeight;
  return item;
}

function updateLog(actionKey, type, text) {
  const item = actionLogMap[actionKey];
  if (item) { item.className = `em-log-item ${type}`; item.textContent = text; }
  else appendLog(text, type);
}

let progressValue = 0;
function animateProgress(to) {
  progressValue = to;
  document.getElementById('em-progress').style.width = to + '%';
}
function incrementProgress() {
  progressValue = Math.min(progressValue + 15, 95);
  document.getElementById('em-progress').style.width = progressValue + '%';
}

// ── Rollback & close ──────────────────────────────────────────────────────────

async function triggerRollback() {
  if (!currentExecId) return;
  document.getElementById('em-rollback-btn').style.display = 'none';
  appendLog('↩️ Rollback manual iniciado...', 'warn');
  try {
    await fetch(`${API}/api/remediation/executions/${currentExecId}/rollback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor: 'pablo.sosto' }),
    });
  } catch (e) {
    appendLog('Error al iniciar rollback: ' + e.message, 'failed');
  }
}

function closeExecutionModal() {
  document.getElementById('exec-modal').style.display = 'none';
  currentExecId = null;
}

// ── Polling fallback (if WebSocket unavailable) ───────────────────────────────

async function pollExecution(executionId) {
  for (let i = 0; i < 60; i++) {
    await sleep(2000);
    try {
      const r = await fetch(`${API}/api/remediation/executions/${executionId}`);
      const data = await r.json();

      document.getElementById('em-exec-id').textContent = executionId.slice(0, 8) + '...';

      // Update log from results
      (data.action_results || []).forEach(ar => {
        if (!actionLogMap[ar.action]) {
          const icon = ar.status === 'success' ? '✅' : ar.status === 'failed' ? '❌' : '⏳';
          appendLog(`${icon} ${ar.action}`, ar.status === 'success' ? 'success' : ar.status === 'failed' ? 'failed' : 'running', ar.action);
        }
      });

      if (['completed', 'failed', 'rolled_back', 'cancelled'].includes(data.status)) {
        setFinalStatus(data.status, data.summary);
        return;
      }
    } catch {}
  }
}

// ── Shared UI helpers ─────────────────────────────────────────────────────────

function showLoading(msg = 'Cargando...') {
  document.getElementById('loading-text').textContent = msg;
  document.getElementById('loading-overlay').style.display = 'flex';
}
function hideLoading() {
  document.getElementById('loading-overlay').style.display = 'none';
}

function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast ${type} visible`;
  setTimeout(() => t.classList.remove('visible'), 3500);
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function impactBadge(level) {
  return { informational: 'bb', low: 'bb', medium: 'bm', high: 'bh', critical: 'bc' }[level] || 'bb';
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Clock ─────────────────────────────────────────────────────────────────────

function updateClock() {
  const n = new Date();
  document.getElementById('clock').textContent =
    n.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ART';
}
updateClock();
setInterval(updateClock, 1000);

// ── AI Toggle ─────────────────────────────────────────────────────────────────

let autoMode = true;
function toggleAI() {
  autoMode = !autoMode;
  const t = document.getElementById('aiToggle');
  const l = document.getElementById('aiLabel');
  t.classList.toggle('on', autoMode);
  l.textContent = autoMode ? 'AI Autónomo' : 'AI Manual';
}

// ── Init ──────────────────────────────────────────────────────────────────────

init();
