'use strict';
document.body.classList.add('js');
const menu = document.querySelector('.menu-toggle');
const navigation = document.querySelector('#navigation');
const mobile = window.matchMedia('(max-width: 900px)');
function setMenu(open) {
  menu.setAttribute('aria-expanded', String(open));
  navigation.hidden = mobile.matches && !open;
}
setMenu(false);
mobile.addEventListener('change', () => setMenu(false));
menu.addEventListener('click', () => setMenu(menu.getAttribute('aria-expanded') !== 'true'));
navigation.addEventListener('click', event => {
  if (event.target.closest('a') && mobile.matches) setMenu(false);
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && mobile.matches && menu.getAttribute('aria-expanded') === 'true') {
    setMenu(false);
    menu.focus();
  }
});
for (const link of document.querySelectorAll('.language a')) {
  link.addEventListener('click', () => {
    document.cookie = `mcpzt_lang=${link.lang}; Path=/; Max-Age=31536000; SameSite=Lax`;
    if (location.hash) link.hash = location.hash;
  });
}
let statusTimer;
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    clearTimeout(statusTimer);
    status.textContent = '';
    try {
      await navigator.clipboard.writeText(code.textContent);
      status.textContent = document.body.dataset.copied;
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = document.body.dataset.copyFailed;
    }
    statusTimer = setTimeout(() => { status.textContent = ''; }, 10000);
  });
}
const demo = document.querySelector('.demo');
const caseButtons = [...document.querySelectorAll('[data-case]')];
caseButtons.forEach(button => { button.disabled = true; });
async function loadDemo() {
  try {
    const response = await fetch(demo.dataset.scenarios);
    if (!response.ok) throw new Error('Fixtures unavailable');
    const cases = await response.json();
    let activeCase = 0;
    let activeContract = 0;
    const contractMap = document.querySelector('.contract-map');
    const contractButtons = [...document.querySelectorAll('[data-contract]')];
    const fieldNames = [
      ['operation_id', 'authorization_id', 'decision', 'tool', 'request_digest', 'policy_binding'],
      ['operation_id', 'attempt_id', 'authorization_digest'],
      ['operation_id', 'authorization_id', 'attempt_id', 'attempt_digest', 'request_digest', 'effect', 'scope', 'transaction_ref'],
      ['evidence_digest', 'previous_digest', 'result', 'reason', 'source_status', 'scope', 'account']
    ];
    function showContract() {
      const documents = cases[activeCase].contracts;
      for (const [i, button] of contractButtons.entries()) {
        button.setAttribute('aria-pressed', String(i === activeContract));
        button.dataset.present = String(Boolean(documents[i]));
        button.querySelector('.contract-state').textContent = documents[i] ? contractMap.dataset.present : contractMap.dataset.missing;
      }
      const record = documents[activeContract];
      const fields = document.getElementById('contract-fields');
      fields.replaceChildren();
      document.getElementById('contract-empty').hidden = Boolean(record);
      document.getElementById('contract-actor').textContent = record ? `${record.payload.issuer} / ${record.protected.alg}` : '—';
      for (const summary of document.querySelectorAll('[data-contract-summary]')) summary.hidden = Number(summary.dataset.contractSummary) !== activeContract;
      if (!record) return;
      for (const name of fieldNames[activeContract]) {
        const row = document.createElement('div');
        const key = document.createElement('dt');
        const value = document.createElement('dd');
        key.textContent = name;
        value.textContent = record.payload[name] === null ? 'null' : String(record.payload[name]);
        row.append(key, value); fields.append(row);
      }
    }
    for (const button of contractButtons) {
      button.disabled = false;
      button.addEventListener('click', () => { activeContract = Number(button.dataset.contract); showContract(); });
    }
    function select(index) {
      activeCase = index;
      const selected = cases[index];
      caseButtons.forEach(button => button.setAttribute('aria-pressed', String(Number(button.dataset.case) === index)));
      for (const description of document.querySelectorAll('[data-description]')) description.hidden = Number(description.dataset.description) !== index;
      for (const field of ['gateway', 'destination', 'observer']) document.getElementById(`${field}-value`).textContent = selected[field];
      document.getElementById('reason').textContent = selected.reason;
      document.getElementById('method-trace').textContent = selected.trace.join('\n');
      document.getElementById('once').hidden = index === 0;
      document.getElementById('raw-fixture').href = `${demo.dataset.fixtures}/${selected.file}.json`;
      showContract();
    }
    for (const button of caseButtons) {
      button.disabled = false;
      button.addEventListener('click', () => select(Number(button.dataset.case)));
    }
    select(0);
  } catch {
    document.getElementById('demo-error').hidden = false;
    document.querySelector('.scenario-controls').hidden = true;
  }
}
loadDemo();
