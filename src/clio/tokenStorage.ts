/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) Protomated
 * Email: team@protomated.com
 * Website: protomated.com
 *
 * PJHB fork modification — F1 fix (Pass 5.5):
 * Replaces upstream plaintext-JSON storage with AES-256-GCM at rest,
 * Argon2id KDF from SECRET_KEY env var. Closes the documentation-vs-
 * implementation gap upstream advertised in env-config but never
 * delivered. See PJHB Pass 5 W2 §F1 + Pass 5.5 W1 decision log.
 */

import { config } from '../config';
import { logger } from '../logger';
import { ClioTokens } from './oauthClient';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'fs';
import { getLegalContextFilePath } from '../utils/paths';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { hashRaw, Algorithm } from '@node-rs/argon2';

// On-disk envelope format
const TOKEN_FORMAT_VERSION = 1;
const KDF_OUTPUT_LEN = 32; // AES-256 key length in bytes
const IV_LEN = 12;          // GCM IV
const SALT_LEN = 16;        // Argon2id salt
const SECRET_KEY_MIN_LENGTH = 32; // characters

// Argon2id parameters — OWASP-recommended defaults; env-tunable per-deployment
// without schema migration if posture tightens later.
const ARGON2_M = parseInt(process.env.PJHB_ARGON2_M ?? '19456', 10); // KiB (≥19 MiB)
const ARGON2_T = parseInt(process.env.PJHB_ARGON2_T ?? '2', 10);     // iterations
const ARGON2_P = parseInt(process.env.PJHB_ARGON2_P ?? '1', 10);     // parallelism

const TOKEN_FILE_PATH = getLegalContextFilePath('clio_tokens');
logger.info(`Using token storage file: ${TOKEN_FILE_PATH}`);

interface EncryptedEnvelope {
  v: number;
  kdf: 'argon2id';
  kdfParams: { m: number; t: number; p: number };
  salt: string;  // base64
  iv: string;    // base64
  tag: string;   // base64
  ct: string;    // base64
}

// Known placeholder values from upstream .env.example files — must not be used
// in production. Fail-fast prevents accidental deployment with a placeholder.
const PLACEHOLDER_SECRET_KEYS = new Set<string>([
  'default-secure-key-for-local-storage-only',
  'generate_a_strong_random_key',
  'your_secure_secret_key_for_encrypting_tokens',
]);

/**
 * Validate SECRET_KEY env var presence + minimum entropy. Throws on missing,
 * too short, or known placeholder values.
 */
function validateSecretKey(sk: string | undefined): asserts sk is string {
  if (!sk || typeof sk !== 'string') {
    throw new Error(
      'PJHB SecureTokenStorage refuses to initialize: SECRET_KEY env var is missing. ' +
      'Set SECRET_KEY to a high-entropy value of at least ' +
      `${SECRET_KEY_MIN_LENGTH} characters before starting. ` +
      'Generate one via: openssl rand -base64 48',
    );
  }
  if (sk.length < SECRET_KEY_MIN_LENGTH) {
    throw new Error(
      'PJHB SecureTokenStorage refuses to initialize: SECRET_KEY is too short ' +
      `(${sk.length} chars; minimum ${SECRET_KEY_MIN_LENGTH}). ` +
      'Generate one via: openssl rand -base64 48',
    );
  }
  if (PLACEHOLDER_SECRET_KEYS.has(sk)) {
    throw new Error(
      'PJHB SecureTokenStorage refuses to initialize: SECRET_KEY is a known ' +
      'placeholder value. Replace with a real high-entropy value.',
    );
  }
}

class SecureTokenStorage {
  private readonly secretKeyBuf: Buffer;

  constructor() {
    const sk = (config as any).secretKey ?? process.env.SECRET_KEY;
    validateSecretKey(sk);
    // Soft signal — log warning without refusing to start. Single-char keys
    // are pathological; flag them so operators can rotate.
    const uniqueChars = new Set(sk).size;
    if (uniqueChars < 8) {
      logger.warn(
        'SECRET_KEY has low character diversity. Consider regenerating ' +
        'with a stronger entropy source (e.g. openssl rand -base64 48).',
      );
    }
    this.secretKeyBuf = Buffer.from(sk, 'utf8');
    logger.debug('Token storage initialized');
  }

  private async deriveKey(salt: Buffer): Promise<Buffer> {
    return await hashRaw(this.secretKeyBuf, {
      algorithm: Algorithm.Argon2id,
      memoryCost: ARGON2_M,
      timeCost: ARGON2_T,
      parallelism: ARGON2_P,
      outputLen: KDF_OUTPUT_LEN,
      salt,
    });
  }

  /**
   * Save tokens to encrypted storage at rest.
   */
  async saveTokens(tokens: ClioTokens): Promise<void> {
    try {
      if (!tokens.access_token) {
        throw new Error('Cannot save invalid tokens: missing access_token');
      }
      const salt = randomBytes(SALT_LEN);
      const iv = randomBytes(IV_LEN);
      const key = await this.deriveKey(salt);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const plaintext = Buffer.from(JSON.stringify(tokens), 'utf8');
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      const envelope: EncryptedEnvelope = {
        v: TOKEN_FORMAT_VERSION,
        kdf: 'argon2id',
        kdfParams: { m: ARGON2_M, t: ARGON2_T, p: ARGON2_P },
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ct: ct.toString('base64'),
      };
      // mode 0o600 = owner-read/write only. Best-effort; some filesystems
      // (e.g. Windows NTFS without POSIX-compat layer) ignore mode bits.
      writeFileSync(TOKEN_FILE_PATH, JSON.stringify(envelope), { mode: 0o600 });
      // Defense-in-depth: log content does not narrate cryptographic choice
      // (no plaintext, no key material, no envelope params).
      logger.info('Tokens persisted');
    } catch (error) {
      logger.error('Failed to save tokens:', error);
      throw error;
    }
  }

  /**
   * Load tokens from encrypted storage. Returns null if file missing, empty,
   * uses an unsupported format version, or fails GCM authentication.
   * Corrupted files are quarantined to a `.bak` sibling and removed.
   */
  async loadTokens(): Promise<ClioTokens | null> {
    try {
      if (!existsSync(TOKEN_FILE_PATH)) {
        logger.info('Token file does not exist');
        return null;
      }
      const data = readFileSync(TOKEN_FILE_PATH, 'utf8');
      if (!data || data.trim() === '') {
        logger.info('Token file is empty');
        return null;
      }
      let envelope: EncryptedEnvelope;
      try {
        envelope = JSON.parse(data);
      } catch (parseError) {
        logger.error(`Error parsing token data envelope: ${parseError}`);
        await this.quarantineCorrupted(data);
        return null;
      }
      if (
        typeof envelope !== 'object' ||
        envelope === null ||
        envelope.v !== TOKEN_FORMAT_VERSION ||
        envelope.kdf !== 'argon2id' ||
        typeof envelope.salt !== 'string' ||
        typeof envelope.iv !== 'string' ||
        typeof envelope.tag !== 'string' ||
        typeof envelope.ct !== 'string'
      ) {
        logger.error(
          'Token file uses an unsupported format or is malformed; treating as corrupted. ' +
          'Re-authentication required.',
        );
        await this.quarantineCorrupted(data);
        return null;
      }
      try {
        const salt = Buffer.from(envelope.salt, 'base64');
        const iv = Buffer.from(envelope.iv, 'base64');
        const tag = Buffer.from(envelope.tag, 'base64');
        const ct = Buffer.from(envelope.ct, 'base64');
        const key = await this.deriveKey(salt);
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
        const tokens = JSON.parse(plaintext.toString('utf8')) as ClioTokens;
        if (!tokens.access_token) {
          logger.warn('Decrypted token data is missing access_token');
          return null;
        }
        logger.debug('Successfully loaded tokens');
        return tokens;
      } catch (decryptErr) {
        // GCM auth-tag mismatch lands here — wrong key, tampered file, or
        // wrong KDF salt/parameters. Quarantine and force re-auth.
        logger.error(
          `Token decryption failed: ${decryptErr instanceof Error ? decryptErr.message : decryptErr}. ` +
          'Re-authentication required.',
        );
        await this.quarantineCorrupted(data);
        return null;
      }
    } catch (error) {
      logger.error('Failed to load tokens:', error);
      return null;
    }
  }

  private async quarantineCorrupted(data: string): Promise<void> {
    try {
      const backupPath = `${TOKEN_FILE_PATH}.bak`;
      writeFileSync(backupPath, data, { mode: 0o600 });
      logger.info(`Backed up corrupted token file to ${backupPath}`);
    } catch (e) {
      logger.error(`Failed to backup corrupted token file: ${e}`);
    }
    try {
      unlinkSync(TOKEN_FILE_PATH);
      logger.info('Removed corrupted token file');
    } catch (e) {
      try {
        writeFileSync(TOKEN_FILE_PATH, '');
        logger.info('Overwrote corrupted token file');
      } catch (we) {
        logger.error(`Failed to clear corrupted token file: ${we}`);
      }
    }
  }

  /**
   * Delete saved tokens.
   */
  async deleteTokens(): Promise<void> {
    try {
      if (existsSync(TOKEN_FILE_PATH)) {
        unlinkSync(TOKEN_FILE_PATH);
        logger.info('Token file removed');
      } else {
        logger.info('No token file to delete');
      }
    } catch (error) {
      logger.error('Error deleting token file:', error);
      try {
        writeFileSync(TOKEN_FILE_PATH, '');
        logger.info('Token file overwritten');
      } catch (writeError) {
        logger.error('Failed to overwrite token file:', writeError);
        throw error;
      }
    }
  }

  async tokensExist(): Promise<boolean> {
    return existsSync(TOKEN_FILE_PATH);
  }
}

// Create and export a singleton instance. SECRET_KEY validation runs at import
// time — modules that import tokenStorage MUST have SECRET_KEY in env first
// (typically via dotenv.config() in src/config.ts which this file imports).
const secureTokenStorage = new SecureTokenStorage();
export { secureTokenStorage };
