/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) Protomated
 * Email: team@protomated.com
 * Website: protomated.com
 */

import { logger } from '../logger';
import { secureTokenStorage } from './tokenStorage';
import { ClioTokens, getClioBaseUrl, isTokenExpired, refreshAccessToken } from './oauthClient';
import { forceReauthentication } from './authStatus';

// API rate limit constants
const MAX_RATE_LIMIT_RETRIES = 3;
const RATE_LIMIT_RETRY_DELAY = 2000; // 2 seconds
const MAX_REQUESTS_PER_MINUTE = 48; // Clio's limit is 50, we use 48 to be safe
const MINUTE_IN_MS = 60 * 1000;

// Proactive refresh: refresh when 80% of token lifetime has elapsed
const TOKEN_REFRESH_THRESHOLD = 0.8;

// Clio API response interfaces
export interface ClioDocument {
  id: string;
  uuid: string;
  name: string;
  content_type?: string;
  date?: string;
  category?: string;
  size?: number;
  parent_folder?: {
    id: string;
    name: string;
  };
  created_at: string;
  updated_at: string;
  // Add other fields as needed
}

export interface ClioFolder {
  id: string;
  name: string;
  parent_folder?: {
    id: string;
    name: string;
  };
  created_at: string;
  updated_at: string;
  // Add other fields as needed
}

export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    paging: {
      page: number;
      per_page: number;
      total_entries: number;
      total_pages: number;
    }
  };
}

// Track authentication status to avoid repetitive failures
let isAuthenticated = false;
let authenticationFailed = false;

/**
 * Determines if a document is processable based on its content type
 */
export function isProcessableDocument(doc: ClioDocument): boolean {
  // Accept documents even if content_type is missing
  if (!doc.content_type) return true;

  // Convert to lowercase for case-insensitive matching
  const contentType = doc.content_type.toLowerCase();

  // List of content types to exclude (add problematic types here)
  const excludedTypes = [
    'image/', // Image files
    'video/', // Video files
    'audio/'  // Audio files
  ];

  // Check if the content type is in the excluded list
  for (const excludeType of excludedTypes) {
    if (contentType.includes(excludeType)) {
      return false;
    }
  }

  // Accept all other document types
  return true;
}

/**
 * Clio API Client class
 */
export class ClioApiClient {
  private tokens: ClioTokens | null = null;
  private baseUrl: string;
  private requestTimestamps: number[] = [];
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    try {
      this.baseUrl = getClioBaseUrl();
    } catch (error) {
      // Default to US region if Clio config validation fails
      this.baseUrl = 'https://app.clio.com';
      logger.warn('Using default Clio API base URL due to missing configuration');
    }
  }

  /**
   * Schedule a proactive token refresh before the token expires.
   * Refreshes at 80% of the token's lifetime to avoid expiration during use.
   */
  private scheduleTokenRefresh(): void {
    // Clear any existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    if (!this.tokens || !this.tokens.created_at || !this.tokens.expires_in) {
      return;
    }

    if (!this.tokens.refresh_token) {
      logger.warn('No refresh token available — cannot schedule automatic refresh');
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = this.tokens.created_at + this.tokens.expires_in;
    const lifetime = this.tokens.expires_in;
    const refreshAt = this.tokens.created_at + Math.floor(lifetime * TOKEN_REFRESH_THRESHOLD);
    const delaySeconds = Math.max(refreshAt - now, 60); // At least 60 seconds from now

    logger.info(`Token expires at ${new Date(expiresAt * 1000).toISOString()}`);
    logger.info(`Scheduling proactive refresh in ${Math.floor(delaySeconds / 3600)}h ${Math.floor((delaySeconds % 3600) / 60)}m`);

    this.refreshTimer = setTimeout(async () => {
      await this.proactiveRefresh();
    }, delaySeconds * 1000);
  }

  /**
   * Perform a proactive token refresh and reschedule the next one.
   */
  private async proactiveRefresh(): Promise<void> {
    if (!this.tokens?.refresh_token) {
      logger.warn('Proactive refresh skipped — no refresh token');
      return;
    }

    try {
      logger.info('Proactive token refresh starting...');
      this.tokens = await refreshAccessToken(this.tokens.refresh_token);
      await secureTokenStorage.saveTokens(this.tokens);
      logger.info('Proactive token refresh successful');

      // Schedule the next refresh
      this.scheduleTokenRefresh();
    } catch (error) {
      logger.error('Proactive token refresh failed:', error);
      // Retry in 5 minutes
      this.refreshTimer = setTimeout(async () => {
        await this.proactiveRefresh();
      }, 5 * 60 * 1000);
    }
  }

  /**
   * Initialize the client by loading tokens
   */
  async initialize(): Promise<boolean> {
    try {
      // If we already know authentication failed, don't try again
      if (authenticationFailed) {
        logger.warn('Authentication previously failed. Re-authentication required.');
        return false;
      }

      // If already authenticated, return success
      if (isAuthenticated && this.tokens) {
        logger.debug('Client already initialized and authenticated');
        return true;
      }

// Try to load existing tokens
      this.tokens = await secureTokenStorage.loadTokens();

      if (!this.tokens) {
        logger.warn('No Clio tokens found. Authentication required.');
        return false;
      }

// Log token information for debugging
      logger.debug(`Loaded tokens with access token: ${this.tokens.access_token ? '****' + this.tokens.access_token.substring(this.tokens.access_token.length - 4) : 'Missing'}`);
      logger.debug(`Token created at: ${this.tokens.created_at ? new Date(this.tokens.created_at * 1000).toISOString() : 'Unknown'}`);
      logger.debug(`Has refresh token: ${this.tokens.refresh_token ? 'Yes' : 'No'}`);

// Check if tokens need to be refreshed
      if (isTokenExpired(this.tokens)) {
        logger.info('Access token expired. Attempting to refresh...');

        try {
          // Check if we have a refresh token
          if (!this.tokens.refresh_token || this.tokens.refresh_token.trim() === '') {
            logger.warn('No refresh token available. Re-authentication required.');
            await forceReauthentication();
            authenticationFailed = true;
            return false;
          }

          this.tokens = await refreshAccessToken(this.tokens.refresh_token);
          await secureTokenStorage.saveTokens(this.tokens);
          logger.info('Token refreshed successfully');
        } catch (refreshError) {
          logger.error('Failed to refresh token. Re-authentication required.', refreshError);
          await forceReauthentication();
          authenticationFailed = true;
          return false;
        }
      }

// Validate token by making a simple API call
      try {
        // Make a simple API call to verify the token works
        await this.listDocuments(1, 1);
        logger.info('Clio API token validated successfully');
        isAuthenticated = true;
        authenticationFailed = false;

        // Schedule proactive token refresh
        this.scheduleTokenRefresh();

        return true;
      } catch (validationError) {
        if (validationError instanceof Error && validationError.message === 'Authentication failed') {
          logger.error('Token validation failed. Re-authentication required.', validationError);
          await forceReauthentication();
          authenticationFailed = true;
          return false;
        } else {
          // If it's not an authentication error, might be something else
          logger.warn('API call failed but not due to authentication. Will try again later.', validationError);
          // Don't mark authentication as failed if it's another type of error
          return false;
        }
      }
    } catch (error) {
      logger.error('Error initializing Clio API client:', error);
      return false;
    }
  }

  /**
   * Reset authentication status to force re-initialization
   */
  resetAuthenticationStatus() {
    isAuthenticated = false;
    authenticationFailed = false;
    this.tokens = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    logger.info('Clio API client authentication status reset');
  }

  /**
   * Check if we can make a new request based on rate limits
   * @returns boolean indicating if we can make a new request
   */
  private canMakeRequest(): boolean {
    const now = Date.now();
    // Remove timestamps older than 1 minute
    this.requestTimestamps = this.requestTimestamps.filter(
      timestamp => now - timestamp < MINUTE_IN_MS
    );
    // Check if we're under the limit
    return this.requestTimestamps.length < MAX_REQUESTS_PER_MINUTE;
  }

  /**
   * Wait until we can make a new request if needed
   */
  private async waitForRateLimit(): Promise<void> {
    if (this.canMakeRequest()) {
      return; // We can make a request now
    }

    const now = Date.now();
    // Get the oldest timestamp
    const oldestTimestamp = this.requestTimestamps[0];
    // Calculate how long to wait until we can make a new request
    const waitTime = MINUTE_IN_MS - (now - oldestTimestamp);

    if (waitTime > 0) {
      logger.info(`Rate limit reached. Waiting ${waitTime}ms before making next request...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      // Recursive call to check again after waiting
      await this.waitForRateLimit();
    }
  }

  /**
   * Record a new request timestamp
   */
  private recordRequest(): void {
    this.requestTimestamps.push(Date.now());
  }

  /**
   * Make an authenticated request to the Clio API
   */
  private async makeRequest<T>(
    endpoint: string,
    method: string = 'GET',
    data?: any,
    contentType: string = 'application/json',
  ): Promise<T> {
    // Ensure we have valid tokens
    if (!this.tokens) {
      throw new Error('Not authenticated. Initialize the client first.');
    }

    // Check if token needs refreshing
    if (isTokenExpired(this.tokens)) {
      logger.info('Access token expired. Refreshing...');

      // Check if we have a refresh token
      if (!this.tokens.refresh_token || this.tokens.refresh_token.trim() === '') {
        logger.warn('No refresh token available. Re-authentication required.');
        await forceReauthentication();
        throw new Error('Authentication failed');
      }

      try {
        this.tokens = await refreshAccessToken(this.tokens.refresh_token);
        await secureTokenStorage.saveTokens(this.tokens);
        this.scheduleTokenRefresh();
      } catch (refreshError) {
        logger.error('Failed to refresh token. Re-authentication required.', refreshError);
        await forceReauthentication();
        throw new Error('Authentication failed');
      }
    }

    // Prepare request headers
    const headers: HeadersInit = {
      'Authorization': `Bearer ${this.tokens.access_token}`,
      'Accept': 'application/json',
    };

    // Add content-type header for non-GET requests with body
    if (method !== 'GET' && data) {
      headers['Content-Type'] = contentType;
    }

    // Prepare request options
    const options: RequestInit = {
      method,
      headers,
      redirect: 'follow',
    };

    // Add body for non-GET requests with data
    if (method !== 'GET' && data) {
      if (contentType === 'application/json') {
        options.body = JSON.stringify(data);
      } else if (contentType === 'application/x-www-form-urlencoded') {
        options.body = data instanceof URLSearchParams ? data.toString() : new URLSearchParams(data).toString();
      } else {
        options.body = data;
      }
    }

    // Make the request with rate limit handling
    let retries = 0;
    let authRetry = false;

    while (true) {
      try {
        // Wait for rate limit before making request
        await this.waitForRateLimit();

        const url = new URL(`/api/v4/${endpoint}`, this.baseUrl);

        // For GET requests, add query parameters
        if (method === 'GET' && data) {
          Object.entries(data).forEach(([key, value]) => {
            if (value !== undefined) {
              url.searchParams.append(key, String(value));
            }
          });
        }

        // Record this request
        this.recordRequest();

        const response = await fetch(url.toString(), options);

        // Handle rate limiting
        if (response.status === 429) {
          if (retries < MAX_RATE_LIMIT_RETRIES) {
            retries++;
            const retryAfter = response.headers.get('Retry-After') || String(RATE_LIMIT_RETRY_DELAY / 1000);
            const delay = parseInt(retryAfter, 10) * 1000 || RATE_LIMIT_RETRY_DELAY;

            logger.warn(`Rate limit exceeded. Retrying in ${delay / 1000} seconds...`);
            await new Promise(resolve => setTimeout(resolve, delay));
            continue;
          } else {
            throw new Error(`Rate limit exceeded after ${MAX_RATE_LIMIT_RETRIES} retries`);
          }
        }

        // Handle authentication errors
        if (response.status === 401) {
          logger.warn('Authentication failed. Token might be invalid.');

          if (!authRetry) {
            // Try refreshing the token once
            if (this.tokens && this.tokens.refresh_token) {
              logger.info('Attempting to refresh token after 401 error');
              try {
                this.tokens = await refreshAccessToken(this.tokens.refresh_token);
                await secureTokenStorage.saveTokens(this.tokens);
                logger.info('Token refreshed after 401 error, retrying request');
                this.scheduleTokenRefresh();

                // Update the Authorization header with new token
                headers['Authorization'] = `Bearer ${this.tokens.access_token}`;
                options.headers = headers;

                authRetry = true;
                continue; // Retry the request with new token
              } catch (refreshError) {
                logger.error('Failed to refresh token after 401 error', refreshError);
              }
            }

            // If we couldn't refresh, or don't have a refresh token
            await forceReauthentication();
            isAuthenticated = false;
            authenticationFailed = true;
          }

          throw new Error('Authentication failed');
        }

        // Handle other errors
        if (!response.ok) {
          const errorText = await response.text();
          logger.error(`API request failed: ${response.status} ${response.statusText}`, errorText);
          throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }

        // Parse response
        try {
          const responseData = await response.json();
          // Authentication succeeded, update status
          isAuthenticated = true;
          authenticationFailed = false;
          return responseData as T;
        } catch (jsonError) {
          // Check content type to provide better error message
          const contentType = response.headers.get('Content-Type');

          // Get response text for logging
          let responseText;
          try {
            responseText = await response.text();
          } catch (textError) {
            responseText = `[Could not get response text: ${textError}]`;
          }

          logger.error(`Failed to parse response as JSON: ${jsonError}`, responseText);
          logger.debug(`Response content type: ${contentType}`);

          // If content type suggests this is not JSON, provide a more descriptive error
          if (contentType && !contentType.includes('application/json')) {
            throw new Error(`Received non-JSON response with content type: ${contentType}`);
          }

          throw new Error(`Failed to parse response as JSON: ${jsonError}`);
        }
      } catch (error) {
        // If it's an authentication error, mark status
        if (error instanceof Error && error.message === 'Authentication failed') {
          isAuthenticated = false;
          authenticationFailed = true;
        }

        logger.error(`Error making request to ${endpoint}:`, error);
        throw error;
      }
    }
  }

  /**
   * List documents from Clio
   */
  async listDocuments(
    page: number = 1,
    perPage: number = 10,
    query?: string,
  ): Promise<PaginatedResponse<ClioDocument>> {
    const params: any = {
      page,
      per_page: perPage,
    };

    if (query) {
      params.query = query;
    }

    return await this.makeRequest<PaginatedResponse<ClioDocument>>('documents', 'GET', params);
  }

  /**
   * Get a document's metadata by ID
   */
  async getDocument(documentId: string): Promise<{ data: ClioDocument }> {
    return await this.makeRequest<{ data: ClioDocument }>(`documents/${documentId}`);
  }

  /**
   * Download a document's content by ID
   */
  async downloadDocument(documentId: string): Promise<Buffer> {
    try {
      if (!this.tokens) {
        throw new Error('Not authenticated. Initialize the client first.');
      }

      // Wait for rate limit before making request
      await this.waitForRateLimit();

      const url = new URL(`/api/v4/documents/${documentId}/download`, this.baseUrl);

      // Record this request
      this.recordRequest();

      const response = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.tokens.access_token}`,
        },
        redirect: 'follow',
      });

      if (!response.ok) {
        throw new Error(`Failed to download document: ${response.status} ${response.statusText}`);
      }

      // Get the response as an ArrayBuffer
      const arrayBuffer = await response.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } catch (error) {
      logger.error(`Error downloading document ${documentId}:`, error);
      throw error;
    }
  }

  /**
   * List folders from Clio
   */
  async listFolders(
    page: number = 1,
    perPage: number = 10,
  ): Promise<PaginatedResponse<ClioFolder>> {
    const params = {
      page,
      per_page: perPage,
    };

    return await this.makeRequest<PaginatedResponse<ClioFolder>>('folders', 'GET', params);
  }

  /**
   * Get folder contents (documents and subfolders)
   */
  async getFolderContents(
    folderId: string,
  ): Promise<{
    documents: PaginatedResponse<ClioDocument>;
    folders: PaginatedResponse<ClioFolder>;
  }> {
    const documentsPromise = this.makeRequest<PaginatedResponse<ClioDocument>>(
      'documents',
      'GET',
      { folder_id: folderId },
    );

    const foldersPromise = this.makeRequest<PaginatedResponse<ClioFolder>>(
      'folders',
      'GET',
      { parent_id: folderId },
    );

    const [documents, folders] = await Promise.all([documentsPromise, foldersPromise]);

    return {
      documents,
      folders,
    };
  }
}

export const clioApiClient = new ClioApiClient();
