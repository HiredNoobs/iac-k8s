// The ATT&CK matrix, drawn by the ATT&CK coverage dashboard's Business Text panel: its helpers
// code is this file with `const MATRIX = {...}` (attack-coverage.py's matrix()) in front of it.
// Registers {{attackMatrix}}, the panel's whole content: the techniques on the platforms the
// Platforms variable selects, coloured by their rules, marked when their alerts fired in the time
// range (the panel's query: alert instances per mitre_technique).

const esc = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const title = (lines) => lines.map(esc).join('&#10;');

// Alert instances per technique, revoked IDs (Falco's older tags) counted for their replacement.
const fired = {};
const add = (technique, count) => {
  if (!technique) {
    return;
  }
  const id = MATRIX.revoked[technique] || technique;
  fired[id] = (fired[id] || 0) + (Number(count) || 0);
};
for (const frame of context.panelData.series || []) {
  const techniques = frame.fields.find((f) => f.name === 'mitre_technique');
  const numbers = frame.fields.filter((f) => f.type === 'number');
  if (techniques && numbers.length) {
    const counts = Array.from(numbers[0].values);
    Array.from(techniques.values).forEach((t, i) => add(t, counts[i]));
  } else {
    // Time series rather than a table: the technique is a label of the value field.
    numbers.forEach((f) => add(f.labels && f.labels.mitre_technique, Array.from(f.values).pop()));
  }
}

// The selected platforms as bits (MATRIX.platforms' order); the defaults if the variable is
// missing or empty.
let selected;
try {
  selected = JSON.parse(context.grafana.replaceVariables('${platform:json}'));
} catch (e) {
  selected = null;
}
if (typeof selected === 'string') {
  selected = [selected];
}
if (!Array.isArray(selected) || !selected.length) {
  selected = MATRIX.defaultPlatforms;
}
const mask = MATRIX.platforms.reduce((bits, p, i) => (selected.includes(p) ? bits | (1 << i) : bits), 0);

const status = ['', 'untested', 'tested'];
const known = new Set();

const cell = (t, sub) => {
  const own = fired[t.id] || 0;
  const subs = sub ? [] : t.subs;
  const subFired = subs.reduce((n, s) => n + (fired[s.id] || 0), 0);
  const subStatus = subs.reduce((n, s) => Math.max(n, s.st), 0);
  const classes = [sub ? 'atk-s' : 'atk-t'];
  if (t.st) {
    classes.push(status[t.st]);
  } else if (subStatus) {
    classes.push('partial-' + status[subStatus]);
  }
  if (own + subFired) {
    classes.push('fired');
  }
  const lines = [t.id + ' ' + t.n];
  if (t.r) {
    lines.push(...t.r.split('\n'));
  }
  if (!t.st && subStatus) {
    lines.push('Covered through its sub-techniques');
  }
  if (own) {
    lines.push('Fired in range: ' + own);
  }
  if (subFired) {
    lines.push('Its sub-techniques fired in range: ' + subFired);
  }
  const badge = own + subFired ? '<span class="atk-fire">' + (own + subFired) + '</span>' : '';
  const href = 'https://attack.mitre.org/techniques/' + t.id.replace('.', '/') + '/';
  return (
    '<a class="' + classes.join(' ') + '" href="' + href + '" target="_blank" title="' + title(lines) + '">' +
    badge + '<span class="atk-id">' + esc(t.id) + '</span> ' + esc(t.n) + '</a>'
  );
};

const columns = MATRIX.tactics.map((tactic) => {
  let shown = 0;
  const cells = tactic.t
    .map((t) => {
      known.add(t.id);
      t.subs.forEach((s) => known.add(s.id));
      // Sub-techniques that are covered or fired, as Navigator's "annotated" expansion.
      const subs = t.subs.filter((s) => s.st || fired[s.id]);
      if (!(t.pf & mask) && !t.st && !fired[t.id] && !subs.length) {
        return '';
      }
      shown += 1;
      const subCells = subs.length ? '<div class="atk-subs">' + subs.map((s) => cell(s, true)).join('') + '</div>' : '';
      return cell(t, false) + subCells;
    })
    .join('');
  return (
    '<div class="atk-col"><div class="atk-tactic" title="' + esc(tactic.id) + '">' + esc(tactic.n) +
    '<span>' + shown + ' techniques</span></div>' + cells + '</div>'
  );
});

const firedIds = Object.keys(fired).filter((id) => fired[id]);
const outside = firedIds.filter((id) => !known.has(id)).sort();
const summary =
  '<div class="atk-summary"><b>' + MATRIX.covered + '</b> techniques covered by a rule, <b>' + MATRIX.tested +
  '</b> by a tested one; <b>' + firedIds.length + '</b> fired in the time range. Enterprise ATT&amp;CK ' +
  esc(MATRIX.version) + ', platforms: ' + esc(selected.join(', ')) + '.' +
  '<span class="atk-legend"><span class="tested">tested</span><span class="untested">untested</span>' +
  '<span class="partial-tested">a sub-technique</span><span class="fired">fired</span></span></div>';
const note = outside.length
  ? '<div class="atk-outside">Fired with techniques that aren\'t in ATT&amp;CK ' + esc(MATRIX.version) + ': ' +
    outside.map((id) => esc(id) + ' (' + fired[id] + ')').join(', ') + '</div>'
  : '';

const html = '<div class="atk">' + summary + note + '<div class="atk-grid">' + columns.join('') + '</div></div>';
context.handlebars.registerHelper('attackMatrix', () => new context.handlebars.SafeString(html));
