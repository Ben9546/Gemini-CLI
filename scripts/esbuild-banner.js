/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// esbuild-banner.js
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
globalThis.__filename = require('node:url').fileURLToPath(import.meta.url);
globalThis.__dirname = require('node:path').dirname(globalThis.__filename);
