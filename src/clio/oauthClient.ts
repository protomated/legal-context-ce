// Path: /Users/deletosh/projects/legal-context/src/clio/oauthClient.ts

/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) Protomated
 * Email: team@protomated.com
 * Website: protomated.com
 */
/**
 * Clio OAuth 2.0 Client
 *
 * This module implements the OAuth 2.0 client for authenticating with the Clio API.
 * It handles generating authorization URLs, exchanging authorization codes for tokens,
 * and refreshing expired tokens.
 */

import { config, validateClioConfig } from "../config";
import { logger } from "../logger";
import { randomBytes } from "crypto";

// Define token response interface
export interface ClioTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  created_at?: number; // We add this for tracking expiration
}

/**
 * Get the base URL for Clio API based on the configured region
 */
export function getClioBaseUrl(): string {
  // Check if all required Clio config is available
  const requiredClioVars = ['clioClientId', 'clioClientSecret', 'clioRedirectUri', 'clioApiRegion'];
  const missingClioVars = requiredClioVars.filter(varName => !config[varName as keyof typeof config]);

  if (missingClioVars.length > 0) {
    logger.warn(`Missing Clio configuration: ${missingClioVars.join(', ')}. Using default US region.`);
    return 'https://app.clio.com'; // Default to US region
  }

  validateClioConfig(); // Ensure Clio config is valid

  // Return region-specific URL
  switch (config.clioApiRegion) {
    case 'us':
      return 'https://app.clio.com';
    case 'ca':
      return 'https://ca.app.clio.com';
    case 'eu':
      return 'https://eu.app.clio.com';
    case 'au':
      return 'https://au.app.clio.com';
    default:
      return 'https://app.clio.com'; // Default to US region
  }
}

/**
 * Generate a cryptographically secure random state parameter for CSRF protection
 */
export function generateSecureState(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Generate the authorization URL for redirecting users to Clio's OAuth page
 */
export function generateAuthorizationUrl(state: string): string {
  validateClioConfig(); // Ensure Clio config is valid

  const baseUrl = getClioBaseUrl();
  const url = new URL('/oauth/authorize', baseUrl);

  // Use the configured client ID and redirect URI from the environment
  const clientId = config.clioClientId;
  if (!clientId) {
    throw new Error('CLIO_CLIENT_ID is not configured in environment variables');
  }

  const redirectUri = config.clioRedirectUri;
  if (!redirectUri) {
    throw new Error('CLIO_REDIRECT_URI is not configured in environment variables');
  }

  // Add required query parameters
  url.searchParams.append('response_type', 'code');
  url.searchParams.append('client_id', clientId);
  url.searchParams.append('redirect_uri', redirectUri);
  url.searchParams.append('state', state);

  return url.toString();
}

/**
 * Exchange an authorization code for access and refresh tokens
 */
export async function exchangeCodeForTokens(code: string): Promise<ClioTokens> {
  validateClioConfig(); // Ensure Clio config is valid

  const baseUrl = getClioBaseUrl();
  const url = new URL('/oauth/token', baseUrl);

  // Use the configured client ID, client secret, and redirect URI from the environment
  const clientId = config.clioClientId;
  if (!clientId) {
    throw new Error('CLIO_CLIENT_ID is not configured in environment variables');
  }

  const clientSecret = config.clioClientSecret;
  if (!clientSecret) {
    throw new Error('CLIO_CLIENT_SECRET is not configured in environment variables');
  }

  const redirectUri = config.clioRedirectUri;
  if (!redirectUri) {
    throw new Error('CLIO_REDIRECT_URI is not configured in environment variables');
  }

  // Create request body with all parameters
  const body = new URLSearchParams();
  body.append('grant_type', 'authorization_code');
  body.append('code', code);
  body.append('redirect_uri', redirectUri);
  body.append('client_id', clientId);
  body.append('client_secret', clientSecret);

  // Log request details for debugging (redact sensitive info)
  logger.debug(`Token exchange URL: ${url.toString()}`);
  logger.debug(`Request body: grant_type=authorization_code, code=REDACTED, redirect_uri=${redirectUri}, client_id=${clientId}, client_secret=REDACTED`);

  try {
    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: body.toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(`Token exchange failed: ${response.status} ${response.statusText}`, errorText);
      throw new Error(`Failed to exchange code for tokens: ${response.status} ${response.statusText}`);
    }

    const tokens = await response.json() as ClioTokens;

    // Add created_at timestamp if not provided by the API
    if (!tokens.created_at) {
      tokens.created_at = Math.floor(Date.now() / 1000);
    }

    // Clio returns refresh_token by default on code exchange.
    // Refresh tokens do not expire — store and reuse across refreshes.
    if (!tokens.refresh_token) {
      logger.warn('WARNING: No refresh_token received from Clio. Token will expire without ability to auto-refresh.');
    } else {
      logger.info('Refresh token received successfully');
    }

    return tokens;
  } catch (error) {
    logger.error("Error exchanging code for tokens:", error);
    throw error;
  }
}

/**
 * Refresh an expired access token using a refresh token
 */
export async function refreshAccessToken(refreshToken: string): Promise<ClioTokens> {
  validateClioConfig(); // Ensure Clio config is valid

  const baseUrl = getClioBaseUrl();
  const url = new URL('/oauth/token', baseUrl);

  // Use the configured client ID and client secret from the environment
  const clientId = config.clioClientId;
  if (!clientId) {
    throw new Error('CLIO_CLIENT_ID is not configured in environment variables');
  }

  const clientSecret = config.clioClientSecret;
  if (!clientSecret) {
    throw new Error('CLIO_CLIENT_SECRET is not configured in environment variables');
  }

  // Create request body with all parameters
  const body = new URLSearchParams();
  body.append('grant_type', 'refresh_token');
  body.append('refresh_token', refreshToken);
  body.append('client_id', clientId);
  body.append('client_secret', clientSecret);

  // Log request details for debugging (redact sensitive info)
  logger.debug(`Token refresh URL: ${url.toString()}`);
  logger.debug(`Request body: grant_type=refresh_token, refresh_token=REDACTED, client_id=${clientId}, client_secret=REDACTED`);

  try {
    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: body.toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(`Token refresh failed: ${response.status} ${response.statusText}`, errorText);
      throw new Error(`Failed to refresh token: ${response.status} ${response.statusText}`);
    }

    const tokens = await response.json() as ClioTokens;

    // Add created_at timestamp if not provided by the API
    if (!tokens.created_at) {
      tokens.created_at = Math.floor(Date.now() / 1000);
    }

    // Clio does not return a new refresh_token on refresh — preserve the original
    if (!tokens.refresh_token) {
      tokens.refresh_token = refreshToken;
    }

    return tokens;
  } catch (error) {
    logger.error("Error refreshing access token:", error);
    throw error;
  }
}

/**
 * Check if an access token is expired
 * Considers a token expired if it's within 60 seconds of actual expiration
 */
export function isTokenExpired(tokens: ClioTokens): boolean {
  if (!tokens.created_at || !tokens.expires_in) {
    // If we don't have created_at or expires_in, assume expired to be safe
    return true;
  }

  const expirationTime = tokens.created_at + tokens.expires_in;
  const currentTime = Math.floor(Date.now() / 1000);

  // Consider the token expired if it's within 60 seconds of expiration
  return currentTime >= (expirationTime - 60);
}
