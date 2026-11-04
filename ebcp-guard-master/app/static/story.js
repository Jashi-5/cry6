// Story page: live demos first, motion second. Everything works with the motion section removed.

const $ = (id) => document.getElementById(id);
const motionOk = () => window.matchMedia('(prefers-reduced-motion: no-preference)').matches;
let lenis = null;

const relayout = () => { if (window.ScrollTrigger) ScrollTrigger.refresh(); };

// ---- Gateway demo ----
const PRESETS = {
  payment: SAMPLE_PAYMENT,
  marketing: {
    endpoint: '/api/v1/customer/profile', http_method: 'POST', destination_service: 'marketing_crm', tenant_id: DEMO_TENANT,
    payload: { customer_name: 'Priya Sharma', email: 'priya.sharma@example.com', phone: '+919811223344', pan: 'ABCPS1234F', account_number: '987654321098', ifsc_code: 'ICIC0002345', amount: 2500 },
  },
  log: {
    endpoint: '/api/v1/auth/logs', http_method: 'POST', destination_service: 'application_logs', tenant_id: DEMO_TENANT,
    payload: { customer_name: 'Vikram Adani', email: 'vikram.adani@example.in', phone: '+919876500000', pan: 'ABCDE1234F', account_number: '554433221100', ifsc_code: 'SBIN0001111', amount: 100 },
  },
  blacklisted: {
    endpoint: '/api/v1/analytics/events', http_method: 'POST', destination_service: 'untrusted_external', tenant_id: DEMO_TENANT,
    payload: { customer_name: 'Ananya Iyer', email: 'ananya.iyer@exfil-test.com', phone: '+919988776655', pan: 'ABCPA5678K', account_number: '998877665544', ifsc_code: 'KKBK0001234', aadhaar: '9988 7766 5544', amount: 500000 },
  },
};

const VERDICTS = {
  ALLOW: ['Allowed through', 'Nothing here needed protecting under this policy.'],
  MASK: ['Masked', 'Identifying characters were removed. Masked values cannot be restored from the output.'],
  TOKENIZE: ['Tokenized', 'Sensitive values became tokens tied to this tenant, purpose and time period. Tokens cannot be reversed without the secret key.'],
  ENCRYPT: ['Encrypted', 'Sensitive values were encrypted with AES-256-GCM. Only an authorized service can read them. Try that in Chapter 04.'],
  BLOCK: ['Blocked', 'This destination may not receive this data. Nothing was sent onward.'],
  QUARANTINE: ['Held for review', 'The request is held for a person to check. Nothing was sent onward.'],
};

function selectPreset(name) {
  $('gw-input').value = JSON.stringify(PRESETS[name], null, 2);
  document.querySelectorAll('[data-preset]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.preset === name)));
}

function showGatewayMessage(text) {
  $('gw-result').replaceChildren(el('p', 'note', text));
}

function showGatewayResult(request, analyze, protect) {
  const action = protect.protection_decision;
  const [title, explanation] = VERDICTS[action] || [action, ''];
  const parts = [el('i', 'crest'), chip(action), el('h4', '', title), el('p', '', explanation)];

  const types = [...new Set(analyze.detected_entities.map((e) => e.entity_type))];
  const pills = el('div', 'result-pills');
  pills.append(...types.map((t) => chip(t)));
  if (types.length) parts.push(pills);

  parts.push(el('p', 'note', `Class ${analyze.sensitivity_class}, purpose ${analyze.purpose}, risk ${protect.risk_score.toFixed(2)} (${protect.risk_level})`));

  const blocked = action === 'BLOCK' || action === 'QUARANTINE';
  if (blocked) {
    parts.push(el('p', 'note', 'Protected output: none, because no data was sent.'));
  } else {
    const output = el('pre', '', JSON.stringify(protect.protected_payload, null, 2));
    output.setAttribute('data-lenis-prevent', '');
    output.tabIndex = 0;
    parts.push(output);
    const unchanged = Object.keys(request.payload).filter((k) =>
      typeof request.payload[k] === 'string' && request.payload[k] === protect.protected_payload[k]);
    if (unchanged.length) {
      const nameNote = unchanged.includes('customer_name') ? ' The regex detector does not recognise person names. See Chapter 06.' : '';
      parts.push(el('p', 'result-warn', `Passed through unchanged: ${unchanged.join(', ')}.${nameNote}`));
    }
  }
  parts.push(el('p', 'result-foot', `Request ${protect.request_id} · ${protect.processing_latency_ms} ms · Audit hash ${protect.audit_event_hash.slice(0, 16)}…`));
  $('gw-result').replaceChildren(...parts);
}

async function runGateway() {
  let request;
  try {
    request = JSON.parse($('gw-input').value);
    if (!request || typeof request.payload !== 'object' || Array.isArray(request.payload) || !Object.keys(request.payload ?? {}).length) throw new Error();
  } catch {
    showGatewayMessage('That is not valid here. It needs to be JSON with a non-empty "payload" object.');
    return;
  }

  const button = $('gw-run');
  button.disabled = true;
  showGatewayMessage('Running…');
  try {
    const [aRes, pRes] = await Promise.all([postJson(`${API}/analyze`, request), postJson(`${API}/protect`, request)]);
    const failed = !aRes.ok ? aRes : (!pRes.ok ? pRes : null);
    if (failed) {
      showGatewayMessage(failed.status === 401
        ? 'The live demo runs in development mode.'
        : failed.status >= 500
          ? `The gateway hit an internal error (HTTP ${failed.status}).`
          : `The gateway rejected this request (HTTP ${failed.status}). Check the JSON and try again.`);
      return;
    }
    const [analyze, protect] = await Promise.all([aRes.json(), pRes.json()]);
    showGatewayResult(request, analyze, protect);
    const sealed = pickSealed(protect.entity_decisions);
    if (sealed && request.tenant_id === DEMO_TENANT) reveal.setSealed(sealed);
    feed.refresh();
  } catch {
    showGatewayMessage('Unable to reach the gateway. Check that the server is running.');
  } finally {
    button.disabled = false;
    relayout();
  }
}

// ---- Break It ----
const ATTACKS = [
  ['audit_tamper', 'Edit the audit log', 'Can I cover my tracks?'],
  ['unauth_decrypt', 'Decrypt without permission', 'Can I read a value without rights?'],
  ['evasion', 'Disguise the data', 'Can I hide a value from the detector?'],
  ['plaintext_log', 'Read the logs', 'Can I read customer data from logs?'],
  ['dict_attack', 'Guess the hash', 'Can I reverse a token by guessing?'],
  ['cross_tenant', 'Link across systems', 'Can I match one customer between teams?'],
  ['cumulative', 'Add it up', 'Can many small requests add up?'],
  ['exfiltration', 'Send it outside', 'Can I send data to an outside service?'],
];

const OUTCOME_TITLE = { PROTECTED: 'The attack failed.', PARTIAL: 'Partly got through.', VULNERABLE: 'It got through.' };

const resultTitle = (data) => {
  const samples = data.details?.samples;
  const missed = samples ? samples.filter((s) => !s.matches_found).length : 0;
  return data.result === 'PARTIAL' && samples
    ? `Partly got through. ${samples.length - missed} of ${samples.length} found, ${missed} missed.`
    : OUTCOME_TITLE[data.result] || data.result;
};

function setAttackButtons(disabled) {
  document.querySelectorAll('.attack').forEach((b) => { b.disabled = disabled; });
}

function openSheet(question, data) {
  $('sheet-chip').replaceChildren(chip(data.result));
  const samples = data.details?.samples;
  $('sheet-title').textContent = resultTitle(data);
  $('sheet-question').textContent = question;
  $('sheet-baseline').textContent = data.baseline_outcome;
  $('sheet-guard').textContent = data.ebcp_guard_outcome;
  $('sheet-explain').textContent = data.explanation;

  const holder = $('sheet-samples');
  holder.replaceChildren();
  if (samples) {
    const table = el('table', 'samples');
    const head = el('tr');
    head.append(el('th', '', 'Disguised input'), el('th', '', 'Detector found'));
    head.querySelectorAll('th').forEach((th) => th.setAttribute('scope', 'col'));
    table.append(head);
    samples.forEach((s) => {
      const row = el('tr');
      row.append(el('td', '', s.input), el('td', '', s.matches_found ? s.entity_types.join(', ') : 'Missed'));
      table.append(row);
    });
    holder.append(table);
  }

  const sheet = $('attack-sheet');
  sheet.showModal();
  lenis?.stop();
  $('sheet-title').focus();
  if (window.gsap && motionOk()) gsap.from(sheet, { yPercent: 100, duration: .45, ease: 'power3.out', clearProps: 'transform' });
}

function closeSheet() {
  $('attack-sheet').close();
}

async function runAttack(scenario, name, question, button) {
  const list = $('live-stages');
  const pace = motionOk() ? 350 : 0; // the backend finishes in milliseconds; this only makes the steps readable
  list.replaceChildren();
  $('phone-title').textContent = name;
  $('phone-sheet').hidden = true;
  setAttackButtons(true);
  lastAttackButton = button;
  try {
    const res = await postJson(`${API}/simulate-attack/stream`, { scenario, tenant_id: DEMO_TENANT }, AbortSignal.timeout(30000));
    if (!res.ok) throw new Error(`The server returned HTTP ${res.status}.`);
    let result = null;
    for await (const event of readAttackEvents(res)) {
      if (event.stage === 'error') throw new Error(event.message);
      list.append(el('li', '', `+${event.elapsed_ms} ms  ${event.message}`));
      list.scrollTop = list.scrollHeight;
      if (event.stage === 'final_result') result = event.result;
      await new Promise((r) => setTimeout(r, pace));
    }
    if (!result) throw new Error('The server stopped before giving a result.');
    setAttackButtons(false);
    // Under 1024px the phone may be off screen, so the full result opens straight away.
    if (!window.matchMedia('(min-width: 1024px)').matches) { openSheet(question, result); return; }
    $('ps-chip').replaceChildren(chip(result.result));
    $('ps-title').textContent = resultTitle(result);
    $('ps-full').onclick = () => openSheet(question, result);
    $('phone-sheet').hidden = false;
    lastAttackButton = $('ps-full');
    $('ps-full').focus({ preventScroll: true });
  } catch (err) {
    list.append(el('li', '', err.name === 'TimeoutError' ? 'No response after 30 seconds.'
      : err instanceof TypeError ? 'Unable to reach the server.' : err.message));
    setAttackButtons(false);
    button.focus();
  } finally {
    relayout();
  }
}

let lastAttackButton = null;

function buildAttacks() {
  $('attacks').replaceChildren(...ATTACKS.map(([scenario, name, question]) => {
    const item = el('li');
    const button = el('button', 'attack');
    button.type = 'button';
    button.append(el('strong', '', name), el('span', '', question));
    button.addEventListener('click', () => runAttack(scenario, name, question, button));
    item.append(button);
    return item;
  }));
}

// Fills the phone in Chapter 01 from the live cumulative attack.
function showExposure({ per_request_analysis: requests, cumulative_analysis: total }) {
  const fill = (row, type, risk, action) => {
    row.dataset.risk = risk;
    row.querySelector('.er-type').textContent = type;
    row.querySelector('.er-score').textContent = risk;
    row.querySelector('.chip').replaceWith(chip(action));
  };
  [...$('expo-list').children].forEach((row, i) => fill(row, requests[i].entity_types.join(', '), requests[i].risk_score, requests[i].recommended_action));
  fill($('expo-total'), `${total.risk_level} RISK`, total.risk_score, total.recommended_action);
  // On the pinned layout, stay on whichever request the scroll has reached.
  $('expo-score').textContent = [...$('expo-list').children, $('expo-total')].filter((r) => !r.classList.contains('off')).pop().dataset.risk;
  $('expo-note').textContent = 'The gateway remembers what this customer has already exposed. Added together, the score reaches high risk and the decision changes. These scores came from the live server when this page loaded.';
}

// Every attack runs on load, so the scoreboard and log comparison are from this server, right now.
async function loadScoreboard() {
  try {
    const results = await Promise.all(ATTACKS.map(async ([scenario]) => {
      const res = await postJson(`${API}/simulate-attack`, { scenario, tenant_id: DEMO_TENANT });
      if (!res.ok) throw new Error();
      return res.json();
    }));
    const count = (r) => results.filter((x) => x.result === r).length;
    document.querySelectorAll('[data-score]').forEach((node) => {
      const value = count(node.dataset.score);
      node.textContent = value;
      if (window.gsap && motionOk()) {
        const n = { v: 0 };
        gsap.to(n, { v: value, duration: 1, snap: { v: 1 }, onUpdate: () => { node.textContent = n.v; },
          scrollTrigger: { trigger: '#score', start: 'top 85%', once: true } });
      }
    });
    $('score-note').textContent = `All ${results.length} attacks ran against this server when the page loaded. All data is made up.`;
    showExposure(results.find((x) => x.scenario === 'cumulative').details);
    const logs = results.find((x) => x.scenario === 'plaintext_log').details;
    $('log-baseline').textContent = logs.baseline_log;
    $('log-protected').textContent = logs.protected_log;
  } catch {
    $('score-note').textContent = 'The attacks could not run. Check that the server is running.';
    $('log-compare').hidden = true;
  }
}

async function runOwnCheck() {
  const text = $('own-input').value;
  const out = $('own-result');
  if (!text.trim()) { out.replaceChildren(el('span', 'note', 'Type something first.')); return; }
  $('own-run').disabled = true;
  try {
    const res = await postJson(`${API}/analyze`, { payload: { text }, endpoint: '/demo/disguise', tenant_id: DEMO_TENANT });
    if (res.status === 401) throw new Error('The live demo runs in development mode.');
    if (!res.ok) throw new Error(`The server returned HTTP ${res.status}.`);
    const types = [...new Set((await res.json()).detected_entities.map((e) => e.entity_type))];
    out.replaceChildren(...(types.length
      ? [el('span', '', 'Caught:'), ...types.map((t) => chip(t))]
      : [chip('MISSED'), el('span', '', 'Nothing detected. This disguise got past the detector.')]));
  } catch (err) {
    out.replaceChildren(el('span', 'note', err instanceof TypeError ? 'Unable to reach the server.' : err.message));
  } finally {
    $('own-run').disabled = false;
    relayout();
  }
}

// ---- Wiring ----
// The five policy actions. Outputs are in the real format of each action.
const ANSWERS = {
  ALLOW: ['amount 75000', '75000'],
  MASK: ['rohan.gupta@example.in', 'r*********a@example.in'],
  TOKENIZE: ['+919876543210', 'PHONE_861bccd30551160b6beae1'],
  ENCRYPT: ['123456789012', '[ENCRYPTED:AES256GCM_…]'],
  BLOCK: ['payload for untrusted_external', 'nothing is sent'],
};

function selectAnswer(action) {
  document.querySelectorAll('[data-totem-name]').forEach((n) => { n.textContent = action; });
  $('totem-index').textContent = `(${Object.keys(ANSWERS).indexOf(action) + 1})`;
  [$('totem-title').textContent, $('totem-text').textContent] = VERDICTS[action];
  [$('totem-in').textContent, $('totem-out').textContent] = ANSWERS[action];
  document.querySelectorAll('[data-action]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.action === action)));
  relayout();
}

const feed = mountFeed($('feed-mount'), { onRender: (rows) => {
  relayout();
  if (window.gsap && motionOk() && rows.length) gsap.from(rows, { opacity: 0, duration: .3, stagger: .015, clearProps: 'opacity' });
} });
const reveal = mountReveal($('reveal-mount'), { onAttempt: () => { feed.refresh(); relayout(); } });

document.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => selectPreset(b.dataset.preset)));
document.querySelectorAll('[data-action]').forEach((b) => b.addEventListener('click', () => selectAnswer(b.dataset.action)));
$('gw-run').addEventListener('click', runGateway);
$('own-run').addEventListener('click', runOwnCheck);
$('sheet-close').addEventListener('click', closeSheet);
$('attack-sheet').addEventListener('close', () => { lenis?.start(); lastAttackButton?.focus(); });
$('attack-sheet').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeSheet(); });

selectPreset('payment');
buildAttacks();
fetch('/docs').then((r) => { if (!r.ok) $('docs-link').hidden = true; }).catch(() => { $('docs-link').hidden = true; });
feed.refresh();

// ---- Motion: GSAP drives animation and pinning, Lenis smooths the scroll. ----
function setupMotion() {
  if (!window.gsap || !window.ScrollTrigger || !motionOk()) return;
  gsap.registerPlugin(ScrollTrigger);

  if (window.Lenis) {
    lenis = new Lenis({ lerp: 0.1, anchors: { offset: -60 } });
    lenis.on('scroll', ScrollTrigger.update);
    gsap.ticker.add((t) => lenis.raf(t * 1000));
    gsap.ticker.lagSmoothing(0);
  }

  // Hero headline
  const heading = document.querySelector('[data-split]');
  heading.setAttribute('aria-label', heading.textContent);
  [...heading.querySelectorAll('mark'), heading].forEach((holder) => {
    [...holder.childNodes].filter((n) => n.nodeType === Node.TEXT_NODE).forEach((node) => {
      const parts = node.textContent.split(/(\s+)/).map((part) => {
        if (!part.trim()) return part;
        const w = el('span', 'word', part);
        w.setAttribute('aria-hidden', 'true');
        return w;
      });
      node.replaceWith(...parts);
    });
  });
  gsap.from('.word', { y: 40, opacity: 0, duration: .8, stagger: .05, ease: 'power3.out', clearProps: 'all' });
  gsap.from('.hero .lede, .ring-stage, .cue', { y: 20, opacity: 0, duration: .7, delay: .45, stagger: .1, ease: 'power2.out', clearProps: 'all' });

  const mm = gsap.matchMedia();

  // Anything that pins needs room. Below these sizes the page simply scrolls.
  mm.add('(min-width: 768px) and (min-height: 680px)', () => {
    const root = document.documentElement;
    root.classList.add('motion', 'pinned-walk', 'motion-sheet');

    // 1. Hero: the ring turns and each card flips as it passes the front, then the ring collapses into one card.
    const heroTl = gsap.timeline({ scrollTrigger: { trigger: '#hero', pin: true, start: 'top top', end: '+=260%', scrub: .6 } });
    heroTl.to('.ring', { rotationY: -360, duration: .72, ease: 'none' }, 0);
    gsap.utils.toArray('.ring .qinner').forEach((inner, i) => {
      heroTl.to(inner, { rotationY: 180, duration: .1, ease: 'power1.inOut' }, i * .08);
    });
    heroTl.to('.ring', { '--spread': 0, duration: .12, ease: 'power2.in' }, .72)
      .to('.hero h1, .hero .lede, .cue', { opacity: 0, y: -30, duration: .1 }, .72)
      .to('.ring', { opacity: 0, duration: .04 }, .86)
      .fromTo('.qcard-one', { opacity: 0, scale: .7 }, { opacity: 1, scale: 1, duration: .08 }, .86)
      .to({}, { duration: .06 });

    // 2. Exposure: the giant score climbs behind the phone, request by request.
    const expoRows = [...gsap.utils.toArray('#expo-list li'), document.getElementById('expo-total')];
    const expoScore = document.getElementById('expo-score');
    let expoStep = -1;
    const setExpo = (i) => {
      if (i === expoStep) return;
      expoStep = i;
      expoRows.forEach((row, n) => row.classList.toggle('off', n > i));
      expoScore.textContent = expoRows[i].dataset.risk;
      expoScore.classList.toggle('final', i === expoRows.length - 1);
      gsap.fromTo(expoScore, { scale: .96 }, { scale: 1, duration: .25 });
    };
    setExpo(0);
    ScrollTrigger.create({
      trigger: '#expo', pin: true, start: 'top top', end: '+=220%',
      onUpdate: (self) => setExpo(Math.min(expoRows.length - 1, Math.floor(self.progress * expoRows.length))),
    });
    gsap.fromTo('.expo-rule', { scaleX: 0 }, { scaleX: 1, ease: 'none', scrollTrigger: { trigger: '#expo', start: 'top 60%', end: 'top top', scrub: true } });
    gsap.fromTo('#expo .phone, .stage-screen', { filter: 'blur(8px)' }, { filter: 'blur(0px)', ease: 'none', clearProps: 'filter', scrollTrigger: { trigger: '#expo', start: 'top 70%', end: 'top 10%', scrub: true } });

    // 3. Gateway: nine stages shown on the phone, pinned. Ends before the live demo.
    const stages = gsap.utils.toArray('.stages li');
    const count = document.querySelector('.stage-count');
    const code = document.querySelector('.stage-code');
    let current = -1;
    const setStage = (i) => {
      if (i === current) return;
      current = i;
      stages.forEach((s, n) => s.classList.toggle('on', n === i));
      count.textContent = `Step ${i + 1} of ${stages.length}`;
      code.textContent = stages[i].querySelector('code').textContent;
      document.querySelector('.stage-name').textContent = stages[i].querySelector('strong').textContent;
      document.querySelector('.stage-num').textContent = String(i + 1).padStart(2, '0');
      document.querySelector('.stage-explain').textContent = stages[i].querySelector('span').textContent;
      gsap.fromTo(code, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: .3, overwrite: true });
    };
    setStage(0);
    ScrollTrigger.create({
      trigger: '.walk', pin: true, start: 'top top', end: '+=320%',
      onUpdate: (self) => setStage(Math.min(stages.length - 1, Math.floor(self.progress * stages.length))),
    });

    // 6. Logs: a light sheet slides over Reveal, then settles flat. Reveal holds only after its form has passed.
    ScrollTrigger.create({ trigger: '#reveal', start: 'bottom bottom', endTrigger: '#logs', end: 'top top', pin: true, pinSpacing: false });
    gsap.fromTo('#logs', { rotation: 2, y: 40 }, {
      rotation: 0, y: 0, ease: 'none',
      scrollTrigger: { trigger: '#logs', start: 'top bottom', end: 'top top', scrub: true },
    });

    return () => {
      root.classList.remove('motion', 'pinned-walk', 'motion-sheet');
      expoRows.forEach((row) => row.classList.remove('off'));
      expoScore.classList.remove('final');
      expoScore.textContent = document.getElementById('expo-total').dataset.risk;
      expoStep = -1;
      current = -1;
    };
  });

  // Effects that only need scrolling, on every screen size.
  gsap.utils.toArray('.row').forEach((row) => {
    gsap.from(row, {
      clipPath: 'inset(0 30% 0 30%)', opacity: .2, ease: 'none',
      scrollTrigger: { trigger: row, start: 'top 95%', end: 'top 65%', scrub: true },
      clearProps: 'clipPath,opacity',
    });
  });
  gsap.to('.coin', { rotationY: 720, ease: 'none', scrollTrigger: { trigger: '.totem', start: 'top bottom', end: 'bottom top', scrub: true } });
  gsap.to('.totem', { scale: .92, ease: 'none', scrollTrigger: { trigger: '.totem', start: 'bottom 80%', end: 'bottom 30%', scrub: true } });
  // The pill drifts across the opening only. Pinned chapters keep text near the bottom edge, where it would cover words.
  gsap.fromTo('.float-pill', { x: '-28vw' }, { x: '28vw', ease: 'none', scrollTrigger: {
    start: 0, endTrigger: '#expo', end: 'top bottom', scrub: true, toggleClass: { targets: '.float-pill', className: 'on' },
  } });
  gsap.from('.attack', {
    y: 20, opacity: 0, stagger: .05, duration: .4, clearProps: 'all',
    scrollTrigger: { trigger: '.break-grid', start: 'top 90%', once: true },
  });
  gsap.fromTo('#reveal', { clipPath: 'inset(9% 0% 0% 0% round 40px 40px 0 0)' }, {
    clipPath: 'inset(0% 0% 0% 0% round 0px 0px 0 0)', ease: 'none',
    scrollTrigger: { trigger: '#reveal', start: 'top bottom', end: 'top 25%', scrub: true },
  });
  gsap.from('[data-cta]', {
    scale: 1.08, transformOrigin: 'left center', ease: 'none',
    scrollTrigger: { trigger: '#cta', start: 'top bottom', end: 'top 30%', scrub: true },
  });

  document.fonts?.ready.then(relayout);
}

function animateEvaluation(root) {
  relayout();
  if (!window.gsap || !motionOk()) return;
  gsap.from(root.querySelectorAll('.eval-bar'), {
    scaleX: 0, transformOrigin: 'left center', duration: .8, ease: 'power2.out', stagger: .02, clearProps: 'transform',
    scrollTrigger: { trigger: root.querySelector('.eval-panels'), start: 'top 85%', once: true },
  });
  root.querySelectorAll('[data-count]').forEach((node) => {
    const target = Number(node.dataset.count);
    const final = node.textContent;
    const n = { v: 0 };
    gsap.to(n, {
      v: target, duration: 1, ease: 'power2.out',
      onUpdate: () => { node.textContent = f3(n.v); },
      onComplete: () => { node.textContent = final; },
      scrollTrigger: { trigger: node, start: 'top 90%', once: true },
    });
  });
}

setupMotion();
loadScoreboard();
mountEvaluation($('eval-mount'), { onRender: animateEvaluation });
