/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as path from 'path';
import * as fs from 'fs';

/**
 * Validates that a command is safe to execute by checking against an allowlist
 * of permitted executables and validating the command structure.
 */
export function validateToolCommand(command: string): string | null {
  if (!command || typeof command !== 'string') {
    return 'Command must be a non-empty string';
  }

  const trimmed = command.trim();
  if (!trimmed) {
    return 'Command cannot be empty or whitespace only';
  }

  // Split the command to get the executable and arguments
  const parts = trimmed.split(/\s+/);
  const executable = parts[0];

  // Check for obviously dangerous patterns
  if (containsDangerousPatterns(trimmed)) {
    return 'Command contains dangerous shell metacharacters or patterns';
  }

  // Check for dangerous file access patterns
  if (containsSensitiveFileAccess(trimmed)) {
    return 'Command attempts to access sensitive system files or directories';
  }

  // Validate the executable is in an allowlist of safe tools
  if (!isExecutableAllowed(executable)) {
    return `Executable '${executable}' is not in the allowlist of permitted tool discovery/call commands`;
  }

  return null;
}

/**
 * Checks if the command contains dangerous shell metacharacters or patterns
 */
function containsDangerousPatterns(command: string): boolean {
  // Dangerous patterns that could indicate shell injection
  const dangerousPatterns = [
    /[;&|`$(){}]/,           // Shell metacharacters
    /\|\||\&\&/,             // Logical operators
    /[<>]/,                  // Redirection
    /\\\\/,                  // Escaped characters (potential obfuscation)
    /\$\{/,                  // Parameter expansion
    /\n|\r/,                 // Newlines
    /^\s*sudo\s/i,           // Privilege escalation
    /^\s*rm\s/i,             // Dangerous file operations
    /^\s*curl\s.*\|\s*sh/i,  // Download and execute
    /^\s*wget\s.*\|\s*sh/i,  // Download and execute
  ];

  return dangerousPatterns.some(pattern => pattern.test(command));
}

/**
 * Checks if the command attempts to access sensitive system files or directories
 */
function containsSensitiveFileAccess(command: string): boolean {
  const sensitivePaths = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/hosts',
    '~/.ssh/',
    '~/.aws/',
    '~/.docker/',
    '/root/',
    '/proc/',
    '/sys/',
    '/dev/',
    'C:\\Windows\\System32',
    'C:\\Users\\',
    '%USERPROFILE%',
    '%APPDATA%',
    '%TEMP%'
  ];

  const lowerCommand = command.toLowerCase();
  return sensitivePaths.some(path => lowerCommand.includes(path.toLowerCase()));
}

/**
 * Checks if the executable is in the allowlist of permitted tools
 */
function isExecutableAllowed(executable: string): boolean {
  // Remove any path separators to get just the executable name
  const baseName = path.basename(executable);
  
  // Allowlist of safe executables for tool discovery and calling
  const allowedExecutables = new Set([
    // Package managers
    'npm', 'npx', 'yarn', 'pnpm',
    
    // Version control
    'git',
    
    // Build tools
    'make', 'cmake', 'gradle', 'mvn', 'ant',
    'cargo', 'go', 'rustc',
    
    // Node.js/JavaScript tools  
    'node', 'deno', 'bun',
    'tsc', 'eslint', 'prettier',
    
    // Python tools
    'python', 'python3', 'pip', 'pip3', 'poetry',
    
    // Safe POSIX utilities (limited set)
    'echo', 'cat', 'head', 'tail', 'grep', 'find', 'ls', 'pwd',
    
    // Docker (common in development)
    'docker', 'docker-compose',
    
    // Development servers
    'serve', 'http-server',
  ]);

  return allowedExecutables.has(baseName.toLowerCase());
}

/**
 * Creates a secure environment for tool execution by removing dangerous
 * environment variables and limiting PATH to safe directories
 */
export function createSecureExecutionEnvironment(): Record<string, string> {
  const env: Record<string, string> = {};
  
  // Copy safe environment variables
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) {
      env[key] = value;
    }
  }
  
  // Remove potentially dangerous environment variables
  const dangerousEnvVars = [
    'LD_PRELOAD',     // Linux dynamic library injection
    'DYLD_INSERT_LIBRARIES', // macOS dynamic library injection
    'NODE_OPTIONS',   // Node.js options that could be dangerous
    'ELECTRON_RUN_AS_NODE', // Electron bypass
  ];
  
  for (const varName of dangerousEnvVars) {
    delete env[varName];
  }
  
  // Limit PATH to common safe directories
  const safePaths = [
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
    '/usr/local/sbin',
    '/usr/sbin',
    '/sbin',
  ];
  
  // On Windows, include common safe paths
  if (process.platform === 'win32') {
    safePaths.push(
      'C:\\Windows\\System32',
      'C:\\Windows',
      'C:\\Program Files\\nodejs',
      'C:\\Program Files\\Git\\cmd',
    );
  }
  
  // Keep existing PATH but filter to safe directories only
  if (env.PATH) {
    const currentPaths = env.PATH.split(path.delimiter);
    const filteredPaths = currentPaths.filter(p => {
      const normalized = path.normalize(p).toLowerCase();
      return safePaths.some(safePath => 
        normalized.startsWith(safePath.toLowerCase()) ||
        normalized.includes('node_modules/.bin') || // npm/yarn binaries
        normalized.includes('.cargo/bin') ||        // Rust binaries
        normalized.includes('go/bin')               // Go binaries
      );
    });
    env.PATH = filteredPaths.join(path.delimiter);
  }
  
  return env;
}

/**
 * Validates that tool names are safe and don't contain injection attempts
 */
export function validateToolName(toolName: string): string | null {
  if (!toolName || typeof toolName !== 'string') {
    return 'Tool name must be a non-empty string';
  }

  const trimmed = toolName.trim();
  if (!trimmed) {
    return 'Tool name cannot be empty or whitespace only';
  }

  // Tool names should be simple identifiers
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return 'Tool name must contain only alphanumeric characters, underscores, and hyphens';
  }

  // Prevent excessively long names (potential buffer overflow)
  if (trimmed.length > 64) {
    return 'Tool name is too long (maximum 64 characters)';
  }

  // Prevent names that could be confused with system commands
  const reservedNames = new Set([
    'rm', 'del', 'format', 'fdisk', 'sudo', 'su', 'exec', 'eval',
    'bash', 'sh', 'cmd', 'powershell', 'python', 'node', 'ruby'
  ]);

  if (reservedNames.has(trimmed.toLowerCase())) {
    return `Tool name '${trimmed}' is reserved and not allowed`;
  }

  return null;
}