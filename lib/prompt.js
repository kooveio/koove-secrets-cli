'use strict';
const readline = require('node:readline');

/** Ask a question on the TTY; input is echoed. */
function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Ask for a secret (passphrase / mnemonic) without echoing it. Falls back to
 * echoed input when not attached to a TTY (e.g. piped in CI).
 */
function askHidden(question) {
  if (!process.stdin.isTTY) return ask(question);
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const write = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (str) => {
      // Echo the prompt itself and newlines, mute the typed characters.
      if (str.includes(question) || str === '\r\n' || str === '\n') write(str);
    };
    rl.question(question, (answer) => {
      rl._writeToOutput = write;
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

/**
 * Resolve the controller keyfile passphrase: KOOVE_CONTROLLER_PASSPHRASE for
 * CI/automation, otherwise an interactive hidden prompt.
 */
async function askPassphrase(label, { confirm = false } = {}) {
  const fromEnv = process.env.KOOVE_CONTROLLER_PASSPHRASE;
  if (fromEnv) return fromEnv;
  const first = await askHidden(`${label}: `);
  if (!first) throw new Error('empty passphrase');
  if (confirm) {
    const second = await askHidden(`${label} (confirmar): `);
    if (first !== second) throw new Error('las passphrases no coinciden');
  }
  return first;
}

module.exports = { ask, askHidden, askPassphrase };
