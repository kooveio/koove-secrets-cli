'use strict';
/** Offline tests of the .env parser behind `koove import`. Run: node test/envfile.test.js */
const assert = require('node:assert');
const { parseEnvFile } = require('../lib/envfile');

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
  } catch (e) {
    failures += 1;
    console.error(`❌ ${name}\n   ${e.message}`);
  }
}

test('parses plain, export-prefixed and =-containing values', () => {
  const { entries, skipped } = parseEnvFile(
    'DB_URL=postgres://u:p@h/db?a=1\nexport API_KEY=abc123\nTOKEN=a=b=c\n',
  );
  assert.deepStrictEqual(entries, [
    { key: 'DB_URL', value: 'postgres://u:p@h/db?a=1' },
    { key: 'API_KEY', value: 'abc123' },
    { key: 'TOKEN', value: 'a=b=c' },
  ]);
  assert.strictEqual(skipped.length, 0);
});

test('ignores comments and blank lines; strips trailing comments on unquoted only', () => {
  const { entries } = parseEnvFile(
    '# header\n\nKEY=value # note\nQUOTED="value # not a comment"\n',
  );
  assert.deepStrictEqual(entries, [
    { key: 'KEY', value: 'value' },
    { key: 'QUOTED', value: 'value # not a comment' },
  ]);
});

test('strips double quotes (expanding \\n) and single quotes (literal)', () => {
  const { entries } = parseEnvFile('A="line1\\nline2"\nB=\'lit\\neral\'\n');
  assert.strictEqual(entries[0].value, 'line1\nline2');
  assert.strictEqual(entries[1].value, 'lit\\neral');
});

test('reports empty values and garbage lines as skipped, never silently', () => {
  const { entries, skipped } = parseEnvFile('EMPTY=\nnot a line\nGOOD=x\n');
  assert.deepStrictEqual(entries, [{ key: 'GOOD', value: 'x' }]);
  assert.strictEqual(skipped.length, 2);
  assert.strictEqual(skipped[0].line, 1);
  assert.strictEqual(skipped[1].line, 2);
});

test('accepts dotted/dashed key names, rejects invalid starts', () => {
  const { entries, skipped } = parseEnvFile('my.key-1=a\n1BAD=b\n_OK=c\n');
  assert.deepStrictEqual(
    entries.map((e) => e.key),
    ['my.key-1', '_OK'],
  );
  assert.strictEqual(skipped.length, 1);
});

process.exit(failures === 0 ? 0 : 1);
