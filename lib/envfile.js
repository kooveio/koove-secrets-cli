'use strict';
/**
 * Minimal .env parser for `koove import`. Pure function, no I/O — the CLI
 * reads the file and passes the content here.
 *
 * Supported (the de-facto dotenv dialect):
 *   KEY=value            plain values, inner `=` preserved
 *   export KEY=value     shell-style export prefix
 *   KEY="v a l"          double quotes stripped, \n expanded
 *   KEY='v a l'          single quotes stripped literally
 *   # comment / blanks   ignored
 *   KEY=value # comment  trailing comment stripped on UNQUOTED values only
 *
 * Anything unparseable is reported in `skipped`, never silently dropped —
 * a secrets tool must not quietly lose lines.
 */

const LINE_RE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;

function parseValue(raw) {
  const trimmed = raw.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/\\n/g, '\n');
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  // Unquoted: strip a trailing comment, then trim.
  const hash = trimmed.indexOf(' #');
  return (hash === -1 ? trimmed : trimmed.slice(0, hash)).trim();
}

/**
 * @param {string} content
 * @returns {{ entries: {key: string, value: string}[], skipped: {line: number, text: string}[] }}
 */
function parseEnvFile(content) {
  const entries = [];
  const skipped = [];

  content.split(/\r?\n/).forEach((line, i) => {
    const t = line.trim();
    if (t === '' || t.startsWith('#')) return;

    const m = LINE_RE.exec(t);
    if (!m) {
      skipped.push({ line: i + 1, text: t.slice(0, 60) });
      return;
    }
    const value = parseValue(m[2]);
    if (value === '') {
      // An empty value is a decision, not a secret — surface it, don't upload.
      skipped.push({ line: i + 1, text: `${m[1]}= (valor vacío)` });
      return;
    }
    entries.push({ key: m[1], value });
  });

  return { entries, skipped };
}

module.exports = { parseEnvFile };
