/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) Protomated
 * Email: team@protomated.com
 * Website: protomated.com
 *
 * PJHB fork addition — F1 unit tests for tokenStorage encryption-at-rest.
 * Pass 5.5 W1.
 *
 * Covers:
 *   1. Round-trip save/load with a known SECRET_KEY.
 *   2. Refusal to start when SECRET_KEY is missing.
 *   3. Refusal to start when SECRET_KEY is too short.
 *   4. Refusal to start when SECRET_KEY is a known placeholder.
 *   5. Corruption detection — tampered ciphertext fails GCM auth-tag.
 *   6. Old plaintext format is treated as corrupted (re-auth path).
 *   7. Repeated saves use fresh salt + IV (basic envelope inspection).
 *
 * Cases 2–4 require fresh module loads with different env, so they are
 * implemented as subprocess spawns. The remaining cases run inline.
 *
 * Runnable via:  bun run src/tests/test-tokenStorage.ts
 *           or:  npx tsx src/tests/test-tokenStorage.ts
 */

import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { spawnSync } from 'child_process';

// Must be set BEFORE any import of tokenStorage / config / oauthClient.
// We control the LegalContext data dir via the LANCEDB_DB_PATH-adjacent
// convention upstream uses; for these tests we point the user data dir to
// a fresh tmpdir to avoid clobbering any developer's real tokens.
const TMP_DIR = mkdtempSync(join(tmpdir(), 'pjhb-tokenstore-'));
process.env.HOME = TMP_DIR;
process.env.USERPROFILE = TMP_DIR; // Windows
process.env.SECRET_KEY = 'pjhb-test-secret-key-v1-must-be-32-chars-min-aaaaaaaa';

// Required by upstream config.ts validation
process.env.CLIO_CLIENT_ID = 'test-client-id';
process.env.CLIO_CLIENT_SECRET = 'test-client-secret';

let pass = 0;
let fail = 0;

function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    pass++;
    console.log(`  [PASS] ${name}`);
  } else {
    fail++;
    console.error(`  [FAIL] ${name}  ${detail}`);
  }
}

async function main() {
  console.log('=== PJHB Pass 5.5 W1 — F1 token-storage unit tests ===');
  console.log('TMP_DIR:', TMP_DIR);

  // Lazy-import tokenStorage so process.env above takes effect first.
  const { secureTokenStorage } = await import('../clio/tokenStorage');

  // ---- Test 1: round-trip ----
  console.log('\nTest 1 — round-trip save/load');
  const tokens = {
    access_token: 'test-access-token-abc123',
    refresh_token: 'test-refresh-token-xyz789',
    token_type: 'Bearer',
    expires_in: 3600,
    created_at: Math.floor(Date.now() / 1000),
  };
  await secureTokenStorage.saveTokens(tokens);
  const loaded = await secureTokenStorage.loadTokens();
  check('round-trip preserves access_token', loaded?.access_token === tokens.access_token);
  check('round-trip preserves refresh_token', loaded?.refresh_token === tokens.refresh_token);
  check('round-trip preserves token_type', loaded?.token_type === tokens.token_type);
  check('round-trip preserves expires_in', loaded?.expires_in === tokens.expires_in);

  // ---- Test 2: on-disk file is NOT plaintext JSON of the tokens ----
  console.log('\nTest 2 — on-disk file is encrypted (no plaintext leakage)');
  // Find the actual token file path. Upstream uses ~/.legalcontext/clio_tokens
  const tokenFile = join(TMP_DIR, '.legalcontext', 'clio_tokens');
  check('token file exists', existsSync(tokenFile));
  const onDisk = readFileSync(tokenFile, 'utf8');
  check('on-disk content does not contain access_token plaintext',
    !onDisk.includes(tokens.access_token));
  check('on-disk content does not contain refresh_token plaintext',
    !onDisk.includes(tokens.refresh_token));
  let envelope: any;
  try {
    envelope = JSON.parse(onDisk);
    check('on-disk content is JSON envelope', true);
    check('envelope.v === 1', envelope.v === 1);
    check('envelope.kdf === argon2id', envelope.kdf === 'argon2id');
    check('envelope has salt', typeof envelope.salt === 'string' && envelope.salt.length > 0);
    check('envelope has iv', typeof envelope.iv === 'string' && envelope.iv.length > 0);
    check('envelope has tag', typeof envelope.tag === 'string' && envelope.tag.length > 0);
    check('envelope has ct', typeof envelope.ct === 'string' && envelope.ct.length > 0);
  } catch (e) {
    check('on-disk content is JSON envelope', false, String(e));
  }

  // ---- Test 3: re-save uses a fresh salt + IV (basic envelope check) ----
  console.log('\nTest 3 — re-save uses fresh salt + IV');
  const firstSalt = envelope?.salt;
  const firstIv = envelope?.iv;
  await secureTokenStorage.saveTokens(tokens);
  const onDisk2 = readFileSync(tokenFile, 'utf8');
  const envelope2 = JSON.parse(onDisk2);
  check('second save produces different salt', envelope2.salt !== firstSalt);
  check('second save produces different iv', envelope2.iv !== firstIv);

  // ---- Test 4: corruption detection ----
  console.log('\nTest 4 — corruption detection (tampered ciphertext)');
  const tampered = {
    ...envelope2,
    // Flip a byte in the ciphertext — base64 alteration
    ct: envelope2.ct.slice(0, -4) + 'AAAA',
  };
  writeFileSync(tokenFile, JSON.stringify(tampered));
  const loadedAfterTamper = await secureTokenStorage.loadTokens();
  check('tampered ciphertext loads as null', loadedAfterTamper === null);
  check('tampered file is quarantined to .bak',
    existsSync(`${tokenFile}.bak`));
  check('tampered file is removed from primary path',
    !existsSync(tokenFile) || readFileSync(tokenFile, 'utf8').trim() === '');

  // ---- Test 5: upstream plaintext-format file is rejected ----
  console.log('\nTest 5 — old plaintext format is rejected');
  // Cleanup quarantine + write an old-format plaintext file
  if (existsSync(`${tokenFile}.bak`)) rmSync(`${tokenFile}.bak`);
  writeFileSync(tokenFile, JSON.stringify({
    access_token: 'fake-leaked-token',
    refresh_token: 'fake-leaked-refresh',
    token_type: 'Bearer',
    expires_in: 3600,
    created_at: 1700000000,
  }));
  const loadedFromOld = await secureTokenStorage.loadTokens();
  check('old plaintext format loads as null', loadedFromOld === null);
  check('old plaintext format is quarantined',
    existsSync(`${tokenFile}.bak`));

  // ---- Tests 6/7/8: SECRET_KEY validation (subprocess via Bun) ----
  // The upstream module is .ts; Bun runs it natively. We write a tiny .mjs
  // driver inside the project root so its relative-import resolves to the
  // tokenStorage module, then `bun run` it from the project cwd.
  const projectRoot = process.cwd();
  const driverScript = join(projectRoot, '_subprocess_driver_pjhb_test.mjs');
  writeFileSync(driverScript,
    `try { await import('./src/clio/tokenStorage.ts'); console.log('UNEXPECTED_LOAD'); } ` +
    `catch (e) { console.log('REFUSED:' + (e instanceof Error ? e.message : String(e)).slice(0, 200)); }`);
  const runSubprocess = (envOverrides: Record<string, string | undefined>): string => {
    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
      HOME: TMP_DIR,
      USERPROFILE: TMP_DIR,
      CLIO_CLIENT_ID: 'x',
      CLIO_CLIENT_SECRET: 'x',
    };
    for (const [k, v] of Object.entries(envOverrides)) {
      if (v === undefined) delete env[k];
      else env[k] = v;
    }
    // Resolve bun via PATH lookup then spawn the absolute path. spawnSync
    // with PATH inheritance is fiddly on Windows; absolute path side-steps it.
    const which = spawnSync(process.platform === 'win32' ? 'where' : 'which',
      ['bun'], { encoding: 'utf8', env: process.env });
    const bunPath = (which.stdout || '').split(/\r?\n/)[0].trim();
    const r = spawnSync(
      bunPath || (process.platform === 'win32' ? 'bun.exe' : 'bun'),
      ['run', driverScript],
      { cwd: projectRoot, encoding: 'utf8', env, shell: false },
    );
    if (r.error) console.error('  subprocess spawn error:', r.error);
    return (r.stdout || '') + (r.stderr || '');
  };

  console.log('\nTest 6 — refuses to start without SECRET_KEY (subprocess)');
  const out6 = runSubprocess({ SECRET_KEY: undefined });
  check('missing SECRET_KEY produces refusal',
    out6.includes('REFUSED:') && out6.includes('SECRET_KEY'),
    out6.slice(0, 300));

  console.log('\nTest 7 — refuses to start with short SECRET_KEY (subprocess)');
  const out7 = runSubprocess({ SECRET_KEY: 'too-short' });
  check('short SECRET_KEY produces refusal',
    out7.includes('REFUSED:') && out7.includes('too short'),
    out7.slice(0, 300));

  console.log('\nTest 8 — refuses to start with placeholder SECRET_KEY (subprocess)');
  const out8 = runSubprocess({ SECRET_KEY: 'your_secure_secret_key_for_encrypting_tokens' });
  check('placeholder SECRET_KEY produces refusal',
    out8.includes('REFUSED:') && out8.includes('placeholder'),
    out8.slice(0, 300));

  // ---- Test 9: deleteTokens + tokensExist round-trip ----
  console.log('\nTest 9 — deleteTokens + tokensExist round-trip');
  await secureTokenStorage.saveTokens(tokens);
  check('tokensExist returns true after save', await secureTokenStorage.tokensExist());
  await secureTokenStorage.deleteTokens();
  check('tokensExist returns false after delete', !(await secureTokenStorage.tokensExist()));

  // Cleanup
  rmSync(TMP_DIR, { recursive: true, force: true });
  try { rmSync(driverScript, { force: true }); } catch {}

  console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
