/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as os from 'os';

/**
 * Validates a command string for potentially dangerous patterns that could
 * lead to command injection or unintended execution.
 * 
 * @param command - The command string to validate
 * @returns An error message if the command is unsafe, null if it's safe
 */
export function validateCommandSafety(command: string): string | null {
  // Trim the command for analysis
  const trimmedCommand = command.trim();
  
  // Check for empty command
  if (!trimmedCommand) {
    return 'Command cannot be empty';
  }
  
  // Define dangerous patterns that could lead to command injection
  const dangerousPatterns = [
    {
      pattern: /&&|\|\|/g,
      description: 'Logical operators (&&, ||) that could conditionally execute commands',
      allowInQuotes: true
    },
    {
      pattern: /[;&|](?![&|])/g,
      description: 'Command chaining characters (;, &, |) that could execute multiple commands',
      allowInQuotes: true
    },
    {
      pattern: /[<>]/g,
      description: 'Redirection operators (<, >) that could access unauthorized files',
      allowInQuotes: true
    },
    {
      pattern: /\$\(/,
      description: 'Command substitution $() that could execute nested commands',
      allowInQuotes: false
    },
    {
      pattern: /`/g,
      description: 'Backticks (`) that could execute nested commands',
      allowInQuotes: false
    },
    {
      pattern: /\$\{[^}]*[:|?+-]/,
      description: 'Shell parameter expansion with operations that could execute code',
      allowInQuotes: false
    },
    {
      pattern: /\n|\r/g,
      description: 'Newline characters that could inject new commands',
      allowInQuotes: false
    }
  ];
  
  // Remove quoted sections for patterns that are allowed in quotes
  let unquotedCommand = trimmedCommand;
  const quotedSections: Array<{start: number, end: number, content: string}> = [];
  
  // Extract quoted sections
  const quoteRegex = /(["'])(?:(?=(\\?))\2.)*?\1/g;
  let match;
  while ((match = quoteRegex.exec(trimmedCommand)) !== null) {
    quotedSections.push({
      start: match.index,
      end: match.index + match[0].length,
      content: match[0]
    });
  }
  
  // Check each pattern
  for (const {pattern, description, allowInQuotes} of dangerousPatterns) {
    const checkCommand = allowInQuotes ? unquotedCommand : trimmedCommand;
    
    if (allowInQuotes) {
      // Create a version of the command with quoted sections replaced
      let tempCommand = trimmedCommand;
      for (let i = quotedSections.length - 1; i >= 0; i--) {
        const section = quotedSections[i];
        tempCommand = tempCommand.substring(0, section.start) + 
                     'Q'.repeat(section.end - section.start) + 
                     tempCommand.substring(section.end);
      }
      
      if (pattern.test(tempCommand)) {
        return `Potentially dangerous command: ${description}`;
      }
    } else {
      if (pattern.test(checkCommand)) {
        return `Potentially dangerous command: ${description}`;
      }
    }
  }
  
  // Additional checks for specific dangerous commands
  const commandParts = trimmedCommand.split(/\s+/);
  const baseCommand = commandParts[0]?.toLowerCase();
  
  // Check for obviously dangerous base commands
  const dangerousCommands = ['eval', 'exec', 'source', '.'];
  if (dangerousCommands.includes(baseCommand)) {
    return `Potentially dangerous command: ${baseCommand} can execute arbitrary code`;
  }
  
  return null;
}

/**
 * Escapes a command argument for safe use in shell execution.
 * This prevents injection of shell metacharacters.
 * 
 * @param arg - The argument to escape
 * @returns The escaped argument
 */
export function escapeShellArgument(arg: string): string {
  // Use the existing shell escape functionality
  if (os.platform() === 'win32') {
    return escapeShellArgumentWindows(arg);
  } else {
    return escapeShellArgumentPosix(arg);
  }
}

/**
 * Escapes an argument for POSIX shells (Linux/macOS)
 */
function escapeShellArgumentPosix(arg: string): string {
  // Empty strings need quotes
  if (arg === '') {
    return "''";
  }
  
  // Check if escaping is needed
  if (!/[^A-Za-z0-9_\-.,:\/@]/.test(arg)) {
    return arg;
  }
  
  // Use single quotes and escape embedded single quotes
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

/**
 * Escapes an argument for Windows cmd.exe
 * Follows Microsoft's documented command-line parsing rules
 */
function escapeShellArgumentWindows(arg: string): string {
  // Empty strings need quotes
  if (arg === '') {
    return '""';
  }
  
  // Check if escaping is needed - if no special characters, return as-is
  if (!/[ \t\n\v\f\r"\\]/.test(arg)) {
    return arg;
  }
  
  // For Windows cmd.exe, we need to follow these rules:
  // 1. Backslashes are literal unless they precede a quote
  // 2. A sequence of backslashes followed by a quote needs special handling
  // 3. Double quotes inside must be escaped as \"
  
  let escaped = '';
  let backslashCount = 0;
  
  for (let i = 0; i < arg.length; i++) {
    const char = arg[i];
    
    if (char === '\\') {
      backslashCount++;
    } else if (char === '"') {
      // Escape preceding backslashes (double them) and the quote
      escaped += '\\'.repeat(backslashCount * 2) + '\\"';
      backslashCount = 0;
    } else {
      // Regular character, add any pending backslashes
      escaped += '\\'.repeat(backslashCount) + char;
      backslashCount = 0;
    }
  }
  
  // Handle trailing backslashes - they need to be doubled when followed by closing quote
  escaped += '\\'.repeat(backslashCount * 2);
  
  return '"' + escaped + '"';
}

/**
 * Splits a command string into safe arguments while preserving quotes.
 * This is a safer alternative to letting the shell parse the command.
 * 
 * @param command - The command string to split
 * @returns An array of arguments, or null if the command can't be safely split
 */
export function splitCommandSafely(command: string): string[] | null {
  const args: string[] = [];
  let current = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escaped = false;
  
  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    const nextChar = command[i + 1];
    
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    
    if (char === '\\' && !inSingleQuote) {
      if (nextChar === '"' || nextChar === '\\' || nextChar === ' ') {
        escaped = true;
        continue;
      }
      current += char;
      continue;
    }
    
    if (char === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      continue;
    }
    
    if (char === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }
    
    if (char === ' ' && !inSingleQuote && !inDoubleQuote) {
      if (current) {
        args.push(current);
        current = '';
      }
      continue;
    }
    
    current += char;
  }
  
  // Check for unclosed quotes
  if (inSingleQuote || inDoubleQuote) {
    return null; // Unclosed quotes
  }
  
  if (current) {
    args.push(current);
  }
  
  return args;
}