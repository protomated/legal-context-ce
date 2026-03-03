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
 * Simple Clio Authentication Test
 *
 * This script tests the Clio OAuth authentication flow.
 * It starts the HTTP server for authentication and guides the user through the auth process.
 */

import { logger } from '../logger';
import { startOAuthServer } from '../clio/httpServer';
import { clioApiClient } from '../clio/apiClient';
import { secureTokenStorage } from '../clio/tokenStorage';
import { config } from '../config';

// Set colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
};

/**
 * Main function to run the simple auth test
 */
async function runSimpleAuthTest() {
  console.log(`\n${colors.bright}${colors.cyan}=== Simple Clio Authentication Test ===${colors.reset}\n`);

  // Check for existing tokens
  const existingTokens = await secureTokenStorage.loadTokens();
  if (existingTokens) {
    console.log(`${colors.yellow}Existing Clio tokens found.${colors.reset}`);
    console.log(`  Refresh token: ${existingTokens.refresh_token ? colors.green + 'Present' + colors.reset : colors.red + 'MISSING' + colors.reset}`);
    if (existingTokens.created_at && existingTokens.expires_in) {
      const expiresAt = existingTokens.created_at + existingTokens.expires_in;
      const remainingSec = expiresAt - Math.floor(Date.now() / 1000);
      const remainingDays = Math.floor(remainingSec / 86400);
      console.log(`  Expires: ${new Date(expiresAt * 1000).toISOString()} (${remainingDays > 0 ? remainingDays + ' days' : 'EXPIRED'})`);
    }
    const answer = await question(`Do you want to test these existing tokens? (y/n): `);

    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      // Test existing tokens
      try {
        await clioApiClient.initialize();

        // Try a simple API call to validate the tokens
        try {
          const result = await clioApiClient.listDocuments(1, 1);

          console.log(`\n${colors.green}✓ Authentication successful! Tokens are valid.${colors.reset}`);

          // Properly handle and display the document count
          if (result && result.meta && result.meta.paging &&
            typeof result.meta.paging.total_entries !== 'undefined') {
            console.log(`Retrieved ${result.meta.paging.total_entries} documents from Clio.`);
          } else {
            console.log(`Retrieved documents from Clio, but couldn't determine total count.`);
            console.log(`Response structure: ${JSON.stringify(Object.keys(result || {}))}`);

            // If there's data in the response, show how many documents we got
            if (result && result.data && Array.isArray(result.data)) {
              console.log(`Response contains ${result.data.length} document(s) in the current page.`);
            }
          }
        } catch (apiCallError) {
          console.error(`\n${colors.red}✗ API call failed despite successful authentication: ${apiCallError instanceof Error ? apiCallError.message : String(apiCallError)}${colors.reset}`);
        }

        process.exit(0);
      } catch (error) {
        console.error(`\n${colors.red}✗ Authentication failed with existing tokens: ${error instanceof Error ? error.message : String(error)}${colors.reset}`);

        const retryAnswer = await question(`Do you want to re-authenticate with Clio? (y/n): `);
        if (retryAnswer.toLowerCase() !== 'y' && retryAnswer.toLowerCase() !== 'yes') {
          process.exit(1);
        }
      }
    } else {
      const deleteAnswer = await question(`Do you want to delete the existing tokens? (y/n): `);
      if (deleteAnswer.toLowerCase() === 'y' || deleteAnswer.toLowerCase() === 'yes') {
        await secureTokenStorage.deleteTokens();
        console.log(`${colors.green}✓ Existing tokens deleted.${colors.reset}`);
      }
    }
  }

  // Start OAuth server
  console.log(`\n${colors.yellow}Starting OAuth server...${colors.reset}`);

  const port = config.port || 3001;
  const oauthServer = startOAuthServer();

  console.log(`\n${colors.bright}${colors.cyan}OAuth server started on port ${port}${colors.reset}`);
  console.log(`\nPlease follow these steps to authenticate with Clio:`);
  console.log(`1. Visit ${colors.cyan}http://localhost:${port}/clio/auth${colors.reset} in your browser`);
  console.log(`2. Log in to your Clio account if prompted`);
  console.log(`3. Approve the authorization request`);
  console.log(`4. You should be redirected back to a success page`);

  console.log(`\n${colors.yellow}Waiting for authentication to complete...${colors.reset}`);
  console.log(`Press Ctrl+C to cancel at any time.\n`);

  // Check for tokens every 5 seconds
  let authenticated = false;
  const maxChecks = 60; // 5 minutes max
  let checks = 0;

  while (!authenticated && checks < maxChecks) {
    await new Promise(resolve => setTimeout(resolve, 5000));

    try {
      const tokens = await secureTokenStorage.loadTokens();
      if (tokens) {
        authenticated = true;
        console.log(`\n${colors.green}✓ Authentication successful! Tokens received and stored.${colors.reset}`);

        // Show refresh token status
        if (tokens.refresh_token) {
          console.log(`${colors.green}✓ Refresh token received — automatic token renewal is enabled.${colors.reset}`);
        } else {
          console.log(`${colors.red}✗ WARNING: No refresh token received. Token will expire in ${tokens.expires_in ? Math.floor(tokens.expires_in / 86400) : '?'} days without auto-renewal.${colors.reset}`);
          console.log(`${colors.yellow}  Re-run auth to retry. Clio should return a refresh token by default.${colors.reset}`);
        }

        // Test the tokens with a simple API call
        await clioApiClient.initialize();
        try {
          const result = await clioApiClient.listDocuments(1, 1);

          // Properly handle and display the document count
          if (result && result.meta && result.meta.paging &&
            typeof result.meta.paging.total_entries !== 'undefined') {
            console.log(`${colors.green}✓ API test successful! Retrieved ${result.meta.paging.total_entries} documents from Clio.${colors.reset}`);
          } else {
            console.log(`${colors.green}✓ API test successful!${colors.reset}`);
            console.log(`Response structure: ${JSON.stringify(Object.keys(result || {}))}`);

            // If there's data in the response, show how many documents we got
            if (result && result.data && Array.isArray(result.data)) {
              console.log(`Response contains ${result.data.length} document(s) in the current page.`);
            }
          }
        } catch (apiError) {
          console.error(`${colors.yellow}⚠ Warning: Received tokens but API test failed: ${apiError instanceof Error ? apiError.message : String(apiError)}${colors.reset}`);
        }

        break;
      }
    } catch (error) {
      // Ignore errors during polling
    }

    checks++;
  }

  if (!authenticated) {
    console.error(`\n${colors.red}✗ Authentication timed out after 5 minutes. Please try again.${colors.reset}`);
    process.exit(1);
  }

  // Shut down the server
  console.log(`\n${colors.yellow}Shutting down OAuth server...${colors.reset}`);
  oauthServer.stop();

  console.log(`\n${colors.bright}${colors.green}Authentication test complete!${colors.reset}`);
  console.log(`You can now start the LegalContext server with: ${colors.cyan}bun start${colors.reset}\n`);

  process.exit(0);
}

/**
 * Helper function to get user input
 */
async function question(query: string): Promise<string> {
  const readline = await import('readline');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise(resolve => {
    rl.question(query, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

// Run the auth test
runSimpleAuthTest().catch(error => {
  logger.error('Error during authentication test:', error);
  process.exit(1);
});
