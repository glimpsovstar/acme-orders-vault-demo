// Acme Orders: poll the JSON endpoints every 5 seconds and redraw. No framework.
let pinned = null;
const $ = (id) => document.getElementById(id);
const el = (tag, props, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };
const when = (t) => t ? new Date(t).toLocaleString('en-AU', { weekday: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) : 'Not known';
const ago = (t) => { const s = Math.round((Date.now() - Date.parse(t)) / 1000);
  return !t ? 'Not known' : s < 90 ? `${s} seconds ago` : s < 5400 ? `${Math.round(s / 60)} minutes ago` : when(t); };
// Colour the words accepted and refused; everything else is plain text.
const said = (node, text) => node.replaceChildren(...text.split(/\b(accepted|refused)\b/).map((s, i) =>
  i % 2 ? el('span', { className: s === 'accepted' ? 'ok' : 'bad', textContent: s }) : s));
const bad = (d) => ['refused', 'login_failed', 'unreachable'].includes(d.state);
const get = (url) => fetch(url).then((r) => r.json());

function vault(d) {
  if (pinned && (d.state === 'gone' || pinned === d.latest)) pinned = null;
  const tabs = (d.versions || []).map((v) => {
    // A deleted or destroyed version says so on its tab, the latest one too.
    const state = v.state[0].toUpperCase() + v.state.slice(1);
    const label = v.version === d.latest ? (v.state === 'live' ? 'Latest' : state) : v.version === pinned ? 'Pinned' : v.state !== 'live' ? state : when(v.created);
    const b = el('button', { className: 'v' + (v.state !== 'live' ? ' gone' : ''), type: 'button', textContent: `v${v.version}`, onclick: () => { pinned = v.version === d.latest ? null : v.version; tick(); } }, el('span', { textContent: label }));
    b.setAttribute('aria-pressed', String(v.version === d.version));
    if (v.version === pinned && bad(d)) b.classList.add('pinned');
    return b;
  });
  $('versions').replaceChildren(...tabs);
  $('vault').classList.toggle('pinned', !!pinned && bad(d));
  $('v-pw').textContent = d.masked || 'none';
  $('v-changed').textContent = d.changed ? when(d.changed) : 'Not known';
  $('v-result').className = 'result' + (bad(d) ? ' refused' : '');
  said($('v-result'), d.message);
}

// Continue a sentence with the note: lower-case its first word, unless that word is an acronym such as AWS.
const cont = (note) => /^[A-Z][A-Z]/.test(note) ? note : note[0].toLowerCase() + note.slice(1);

function aws(d) {
  const [note, login] = d.message.includes('. Database login') ? d.message.split('. ') : [null, d.message];
  $('a-pw').textContent = d.masked || 'none';
  $('a-changed').textContent = d.changed ? ago(d.changed) + (note ? ', ' + cont(note) : '') : 'Not known';
  $('a-result').className = 'result' + (bad(d) ? ' refused' : '');
  said($('a-result'), login);
}

function orders(d) {
  const rows = d.orders.map((o) => el('tr', {}, el('td', { className: 'id', textContent: o.order_id }), el('td', { textContent: o.items }), el('td', { textContent: o.courier }), el('td', {}, el('span', { className: 'st', textContent: o.status }))));
  $('orders').replaceChildren(...(rows.length ? rows : [el('tr', { className: 'empty' }, el('td', { colSpan: 4, textContent: d.message }))]));
  $('orders-who').textContent = d.password_version ? `Database login with password version ${d.password_version}` : 'No password to log in with';
  $('orders-state').className = d.db_login === 'accepted' ? 'ok' : 'bad';
  $('orders-state').textContent = d.db_login === 'accepted' ? 'Connected' : d.db_login === 'refused' ? 'Refused' : 'Not connected';
}

function tick() {
  const q = pinned ? `?version=${pinned}` : '';
  get('/api/secret' + q).then(vault).catch(() => said($('v-result'), 'Cannot reach the Acme Orders server'));
  get('/api/secret?source=aws').then(aws).catch(() => said($('a-result'), 'Cannot reach the Acme Orders server'));
  get('/api/orders' + q).then(orders).catch(() => { $('orders-state').textContent = 'Not connected'; });
}
tick();
setInterval(tick, 5000);
