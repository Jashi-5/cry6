// API helpers and the components both pages share: Reveal, the log feed and Evaluation.
// API text only ever reaches the page through textContent.

const API = '/api/v1';
const DEMO_TENANT = 'demo_bank';

function postJson(url, body, signal, headers = {}) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal,
  });
}

async function* readAttackEvents(res) {
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += value;
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) if (line) yield JSON.parse(line);
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function chip(label) {
  return el('span', `chip chip-${String(label).replace(/\W/g, '_')}`, label);
}

// The Payment preset, marked as payment processing, which is what the policy encrypts.
const SAMPLE_PAYMENT = {
  endpoint: '/api/v1/payments',
  http_method: 'POST',
  destination_service: 'internal_payment',
  tenant_id: DEMO_TENANT,
  processing_purpose_hint: 'PAYMENT_PROCESSING',
  payload: {
    customer_name: 'Rohan Gupta',
    email: 'rohan.gupta@example.in',
    phone: '+919876543210',
    pan: 'ABCPE1234F',
    account_number: '123456789012',
    ifsc_code: 'HDFC0001234',
    aadhaar: '4567 8901 2345',
    amount: 75000,
  },
};

const pickSealed = (entities) => {
  const encrypted = entities.filter((e) => e.ciphertext_b64);
  return encrypted.find((e) => e.entity_type === 'ACCOUNT_NUMBER') || encrypted[0] || null;
};

// ---- Reveal: every attempt goes to the real /decrypt. The server decides, this only shows it. ----
function mountReveal(root, { onAttempt } = {}) {
  root.classList.add('kit');
  root.innerHTML = `
    <div class="reveal">
      <div class="reveal-card" data-r="card">
        <div class="reveal-front s-ink" data-r="front">
          <i class="crest"></i>
          <p class="qcap" data-r="type">No value yet</p>
          <p class="reveal-title" data-r="title">Locked</p>
          <div class="reveal-face mono" data-r="face" aria-live="polite"></div>
          <span class="qpill" data-r="state">Sealed</span>
        </div>
      </div>
      <button type="button" class="btn btn-ghost" data-r="seal">Encrypt a sample value</button>
      <p class="note" data-r="meta"></p>
      <div>
        <label for="reveal-key-${root.id}" style="display:block;margin-bottom:6px;font-weight:600">Service API key</label>
        <input id="reveal-key-${root.id}" data-r="key" class="field" type="password" autocomplete="off" spellcheck="false"
               placeholder="Leave empty to try with no key">
        <p class="note" style="margin:6px 0 0">Kept in this page's memory only. It's sent to the server for this attempt, never saved.</p>
      </div>
      <div class="reveal-row">
        <button type="button" class="btn" data-r="try" disabled>Try to decrypt</button>
        <button type="button" class="btn btn-ghost" data-r="hide" hidden>Hide value</button>
      </div>
      <ol class="reveal-attempts" data-r="attempts" aria-live="polite"></ol>
    </div>`;
  const part = (name) => root.querySelector(`[data-r="${name}"]`);
  let sealed = null;

  // Turns the card over to show its patterned back on the way through.
  function setCard(open) {
    part('front').classList.toggle('s-ink', !open);
    part('front').classList.toggle('s-pale', open);
    part('title').textContent = open ? 'Opened' : 'Locked';
    part('state').textContent = open ? 'Authorized' : 'Sealed';
    if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      part('card').animate([{ transform: 'rotateY(360deg)' }, { transform: 'rotateY(0deg)' }], { duration: 800, easing: 'cubic-bezier(.2,.8,.2,1)' });
    }
  }

  function showSealed() {
    part('face').textContent = sealed ? `[ENCRYPTED:${sealed.cipher_id}]` : 'Nothing encrypted yet.';
    part('hide').hidden = true;
  }

  function setSealed(entity) {
    sealed = entity;
    part('seal').hidden = Boolean(entity);
    part('try').disabled = !entity;
    part('type').textContent = entity ? entity.entity_type : 'No value yet';
    part('meta').textContent = entity ? `${entity.entity_type}, encrypted for ${entity.purpose}, tenant ${DEMO_TENANT}` : '';
    showSealed();
  }

  function logAttempt(status, text) {
    const row = el('li');
    row.append(chip(status === 200 ? 'ALLOWED' : status ? 'DENIED' : 'ERROR'), el('span', 'mono', status ? `HTTP ${status}` : '–'), el('span', '', text));
    part('attempts').prepend(row);
  }

  part('seal').addEventListener('click', async () => {
    part('seal').disabled = true;
    try {
      const res = await postJson(`${API}/protect`, SAMPLE_PAYMENT);
      if (!res.ok) throw new Error(res.status === 401 ? 'The live demo runs in development mode.' : `The server returned HTTP ${res.status}.`);
      const found = pickSealed((await res.json()).entity_decisions);
      if (!found) throw new Error('The policy did not encrypt this request, so there is nothing to reveal.');
      setSealed(found);
      onAttempt?.();
    } catch (err) {
      logAttempt(0, err instanceof TypeError ? 'Unable to reach the server.' : err.message);
    } finally {
      part('seal').disabled = false;
    }
  });

  part('try').addEventListener('click', async () => {
    const key = part('key').value.trim();
    part('try').disabled = true;
    try {
      const res = await postJson(`${API}/decrypt`, {
        cipher_id: sealed.cipher_id,
        ciphertext_b64: sealed.ciphertext_b64,
        entity_type: sealed.entity_type,
        purpose: sealed.purpose,
        tenant_id: DEMO_TENANT,
      }, undefined, key ? { 'X-API-Key': key } : {});
      if (res.ok) {
        const data = await res.json();
        part('face').textContent = data.decrypted_value;
        part('hide').hidden = false;
        logAttempt(200, 'Authorized. Value decrypted and the access recorded in the audit log.');
        setCard(true);
      } else if (res.status === 401) {
        logAttempt(401, 'Refused: no valid key. The attempt was recorded in the audit log.');
      } else if (res.status === 403) {
        logAttempt(403, 'Refused: this service may not decrypt. The attempt was recorded in the audit log.');
      } else {
        logAttempt(res.status, 'The server could not decrypt this value.');
      }
    } catch {
      logAttempt(0, 'Unable to reach the server.');
    }
    part('try').disabled = false;
    part('key').value = '';
    onAttempt?.();
  });

  part('hide').addEventListener('click', () => {
    showSealed();
    setCard(false);
    part('try').focus();
  });

  setSealed(null);
  return { setSealed };
}

// ---- Log feed ----
function mountFeed(root, { filter = false, onRender } = {}) {
  root.classList.add('kit');
  root.innerHTML = `
    <div class="reveal-row" style="align-items:center;justify-content:space-between;margin-bottom:12px">
      <p class="note" data-f="status" aria-live="polite" style="margin:0"></p>
      <div class="reveal-row">
        ${filter ? `<label class="note" style="display:flex;gap:8px;align-items:center">Action
          <select data-f="filter" class="field" style="width:auto"><option value="">All</option></select></label>` : ''}
        <button type="button" class="btn btn-ghost" data-f="refresh">Refresh</button>
      </div>
    </div>
    <div class="feed-scroll" data-lenis-prevent tabindex="0" role="region" aria-label="Audit log">
      <table class="feed">
        <thead><tr><th scope="col">Seq</th><th scope="col">Event</th><th scope="col">Data types</th><th scope="col">Class</th><th scope="col">Action</th><th scope="col">Risk</th><th scope="col">Hash</th><th scope="col">Time</th></tr></thead>
        <tbody data-f="rows"></tbody>
      </table>
    </div>`;
  const part = (name) => root.querySelector(`[data-f="${name}"]`);
  let events = [];

  function draw() {
    const wanted = filter ? part('filter').value : '';
    const shown = wanted ? events.filter((e) => e.protection_action === wanted) : events;
    const rows = shown.map((e) => {
      const tr = el('tr');
      const action = el('td');
      if (e.protection_action) action.append(chip(e.protection_action));
      tr.append(
        el('td', '', `#${e.sequence_number}`),
        el('td', '', e.event_type),
        el('td', '', e.entity_types.join(', ') || '–'),
        el('td', '', e.sensitivity_class || '–'),
        action,
        el('td', '', e.risk_score == null ? '–' : Number(e.risk_score).toFixed(2)),
        el('td', '', `${e.hash_prefix}…`),
        el('td', '', new Date(e.created_at).toLocaleTimeString()),
      );
      return tr;
    });
    part('rows').replaceChildren(...rows);
    return rows;
  }

  async function refresh() {
    try {
      const res = await fetch(`${API}/audit/events?tenant_id=${DEMO_TENANT}&limit=50`);
      if (!res.ok) throw new Error();
      events = await res.json();
      part('status').textContent = events.length
        ? `Newest ${events.length} events for tenant ${DEMO_TENANT}.`
        : 'No events yet. Run a request above and refresh.';
      if (filter) {
        const select = part('filter');
        const chosen = select.value;
        const actions = [...new Set(events.map((e) => e.protection_action).filter(Boolean))].sort();
        select.replaceChildren(el('option', '', 'All'), ...actions.map((a) => el('option', '', a)));
        select.options[0].value = '';
        select.value = actions.includes(chosen) ? chosen : '';
      }
      onRender?.(draw());
    } catch {
      part('status').textContent = 'Live log unavailable.';
      part('rows').replaceChildren();
      onRender?.([]);
    }
  }

  part('refresh').addEventListener('click', refresh);
  if (filter) part('filter').addEventListener('change', draw);
  return { refresh };
}

// ---- Evaluation: every number comes from GET /evaluation, plus one live attack run. ----
// Reports hold 4 decimals. Round from those so .7755 shows as .776, not the float's .775.
const f3 = (n) => (Math.round(Math.round(n * 1e4) / 10) / 1000).toFixed(3).replace(/^0(?=\.)/, '');
const STAT_SURFACE = ['s-ember', 's-air', 's-ink'];
const TYPE_ORDER = ['EMAIL', 'PHONE', 'PERSON', 'ACCOUNT_NUMBER', 'UPI_ID', 'PAN', 'AADHAAR'];

async function mountEvaluation(root, { onRender } = {}) {
  root.classList.add('kit');
  root.textContent = 'Loading the test reports…';
  let report;
  try {
    const res = await fetch(`${API}/evaluation`);
    if (!res.ok) throw new Error();
    report = await res.json();
  } catch {
    root.textContent = 'The test reports are unavailable. Check that the server is running.';
    return;
  }

  const { test_records: records, systems } = report.head_to_head;
  const names = Object.keys(systems);
  const [ours, stock, combined] = names.map((n) => systems[n]);

  const intro = el('p', 'note', `${records} synthetic test records from the held-out split. This compares detection only: encryption, tokens and exposure scoring aren't part of this test. EBCP-Guard's row is its regex detector.`);
  intro.style.marginBottom = '32px';

  const stats = el('div', 'eval-stats');
  names.forEach((name) => {
    const { scores: { micro }, latency } = systems[name];
    const card = el('section', `eval-stat ${STAT_SURFACE[names.indexOf(name)]}`);
    const f1 = el('span', 'eval-f1', f3(micro.f1));
    f1.dataset.count = micro.f1;
    const dl = el('dl');
    [['Overall F1', null], ['Precision', f3(micro.precision)], ['Recall', f3(micro.recall)],
      ['Mean latency', `${latency.mean_ms.toFixed(3)} ms`], ['P95 latency', `${latency.p95_ms.toFixed(3)} ms`]]
      .filter(([, v]) => v).forEach(([k, v]) => dl.append(el('dt', '', k), el('dd', '', v)));
    card.append(el('h3', '', name), f1, el('span', 'note', 'Overall F1'), dl);
    stats.append(card);
  });

  const legend = el('ul', 'eval-legend');
  legend.setAttribute('aria-hidden', 'true');
  names.forEach((name, i) => {
    const item = el('li');
    item.append(el('span', `eval-swatch series-${i}`), el('span', '', name));
    legend.append(item);
  });

  const panels = el('div', 'eval-panels');
  TYPE_ORDER.forEach((type) => {
    const panel = el('section', 'eval-panel');
    panel.append(el('h3', '', type));
    names.forEach((name, i) => {
      const value = systems[name].scores.per_type[type]?.f1 ?? 0;
      const row = el('div', 'eval-bar-row');
      const track = el('div', 'eval-track');
      const bar = el('div', `eval-bar series-${i}`);
      bar.style.width = `${value * 100}%`;
      track.append(bar);
      row.append(el('span', 'eval-bar-name', name), track, el('span', 'eval-bar-value', f3(value)));
      panel.append(row);
    });
    panels.append(panel);
  });

  const short = el('div', 'eval-short');
  const list = el('ul');
  const span = report.model_evaluation.entity_detection;
  const typeF1 = (s, t) => f3(s.scores.per_type[t].f1);
  [
    `The regex detector doesn't find person names at all (F1 ${typeF1(ours, 'PERSON')}), so names pass through it unprotected.`,
    `Presidio + regexes has higher recall (${f3(combined.scores.micro.recall)} vs ${f3(ours.scores.micro.recall)}). It misses less, but its precision is ${f3(combined.scores.micro.precision)} vs ${f3(ours.scores.micro.precision)}, so it raises far more false alarms.`,
    `Stock Presidio beats it on phone numbers (F1 ${typeF1(stock, 'PHONE')} vs ${typeF1(ours, 'PHONE')}).`,
    `Exact entity boundaries are harder: ${span.exact_matches} of ${span.total_gold_entities} matched exactly (F1 ${f3(span.span_exact_f1)}).`,
  ].forEach((text) => list.append(el('li', '', text)));
  const evasionItem = el('li', '', 'Disguised values: run the "Disguise the data" attack to see how many get through.');
  list.append(evasionItem);
  short.append(el('h3', '', 'Where it falls short'), list);

  const chart = el('div', 'eval-chart');
  chart.append(legend, panels);
  root.replaceChildren(intro, stats, chart, short);
  onRender?.(root);

  try {
    const res = await postJson(`${API}/simulate-attack`, { scenario: 'evasion', tenant_id: DEMO_TENANT });
    if (res.ok) {
      const { details } = await res.json();
      const found = details.samples.filter((s) => s.matches_found > 0).length;
      const total = details.samples.length;
      evasionItem.textContent = `Disguised values: ${total - found} of ${total} samples got past the detector in the latest run.`;
    }
  } catch { /* the line above stays accurate without this number */ }
}
