/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  validateCommandSafety,
  escapeShellArgument,
  splitCommandSafely
} from './commandSecurity.js';

describe('commandSecurity', () => {
  describe('validateCommandSafety', () => {
    it('should allow safe commands', () => {
      expect(validateCommandSafety('ls -la')).toBeNull();
      expect(validateCommandSafety('git status')).toBeNull();
      expect(validateCommandSafety('npm install')).toBeNull();
      expect(validateCommandSafety('echo "hello world"')).toBeNull();
      expect(validateCommandSafety('grep -r "pattern" .')).toBeNull();
    });
    
    it('should reject empty commands', () => {
      expect(validateCommandSafety('')).toBe('Command cannot be empty');
      expect(validateCommandSafety('   ')).toBe('Command cannot be empty');
    });
    
    it('should reject command chaining with semicolon', () => {
      const result = validateCommandSafety('ls; rm -rf /');
      expect(result).toContain('Command chaining characters');
    });
    
    it('should reject command chaining with &&', () => {
      const result = validateCommandSafety('test -f file && rm file');
      expect(result).toContain('Logical operators');
    });
    
    it('should reject command chaining with ||', () => {
      const result = validateCommandSafety('test -f file || touch file');
      expect(result).toContain('Logical operators');
    });
    
    it('should reject background processes with &', () => {
      const result = validateCommandSafety('sleep 100 &');
      expect(result).toContain('Command chaining characters');
    });
    
    it('should reject command substitution with $()', () => {
      const result = validateCommandSafety('echo $(whoami)');
      expect(result).toContain('Command substitution');
    });
    
    it('should reject command substitution with backticks', () => {
      const result = validateCommandSafety('echo `whoami`');
      expect(result).toContain('Backticks');
    });
    
    it('should reject file redirection', () => {
      expect(validateCommandSafety('cat < /etc/passwd')).toContain('Redirection operators');
      expect(validateCommandSafety('echo secret > /tmp/file')).toContain('Redirection operators');
    });
    
    it('should reject shell parameter expansion with operations', () => {
      expect(validateCommandSafety('echo ${PATH:=malicious}')).toContain('Shell parameter expansion');
      expect(validateCommandSafety('echo ${var:-default}')).toContain('Shell parameter expansion');
    });
    
    it('should reject newline injection', () => {
      expect(validateCommandSafety('echo hello\nrm -rf /')).toContain('Newline characters');
      expect(validateCommandSafety('echo hello\r\nmalicious')).toContain('Newline characters');
    });
    
    it('should reject dangerous base commands', () => {
      expect(validateCommandSafety('eval "rm -rf /"')).toContain('eval can execute arbitrary code');
      expect(validateCommandSafety('exec malicious')).toContain('exec can execute arbitrary code');
      expect(validateCommandSafety('source /tmp/script')).toContain('source can execute arbitrary code');
      expect(validateCommandSafety('. /tmp/script')).toContain('. can execute arbitrary code');
    });
    
    it('should allow special characters in quotes', () => {
      expect(validateCommandSafety('echo "hello; world"')).toBeNull();
      expect(validateCommandSafety("echo 'test && test'")).toBeNull();
      expect(validateCommandSafety('grep "pattern|other" file')).toBeNull();
    });
    
    it('should still reject command substitution in quotes', () => {
      expect(validateCommandSafety('echo "$(whoami)"')).toContain('Command substitution');
      expect(validateCommandSafety('echo "`date`"')).toContain('Backticks');
    });
  });
  
  describe('escapeShellArgument', () => {
    it('should handle safe arguments (platform-agnostic)', () => {
      // These should work on any platform
      const safeArg = 'hello';
      const result = escapeShellArgument(safeArg);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });
    
    it('should handle arguments with spaces', () => {
      const result = escapeShellArgument('hello world');
      // Should be quoted somehow
      expect(result).toMatch(/^["'].*["']$/);
    });
    
    it('should handle empty strings', () => {
      const result = escapeShellArgument('');
      // Should be quoted
      expect(result).toMatch(/^["']["']$/);
    });
    
    it('should handle special characters safely', () => {
      const dangerousArg = 'test;rm -rf *';
      const result = escapeShellArgument(dangerousArg);
      // Should be quoted to prevent execution
      expect(result).toMatch(/^["'].*["']$/);
    });
    
    it('should correctly escape single quotes in arguments', () => {
      // Test the specific bug fix for POSIX single quote escaping
      const result = escapeShellArgument("don't");
      // On POSIX systems, this should become 'don'\''t'
      // On Windows, this should be quoted with double quotes
      expect(result).toMatch(/^["'].*["']$/);
      // Make sure it doesn't contain the broken pattern
      expect(result).not.toContain('"\'"\'"');
    });
    
    it('should handle Windows path edge cases', () => {
      // Test Windows-specific edge cases that the bot identified
      const testCases = [
        'C:\\path\\with\\backslashes',
        'path with "quotes"',
        'C:\\path\\ending\\with\\backslash\\',
        'file with spaces.txt',
        'path\\with\\trailing\\"quote'
      ];
      
      for (const testCase of testCases) {
        const result = escapeShellArgument(testCase);
        expect(result).toMatch(/^["'].*["']$/);
        // Should not contain the old broken patterns
        expect(result).not.toContain('""""'); // Old double quote escaping
        expect(result).not.toContain('^&'); // Caret escaping inside quotes
      }
    });
  });
  
  describe('splitCommandSafely', () => {
    it('should split simple commands', () => {
      expect(splitCommandSafely('ls -la')).toEqual(['ls', '-la']);
      expect(splitCommandSafely('git commit -m message')).toEqual(['git', 'commit', '-m', 'message']);
    });
    
    it('should handle quoted arguments', () => {
      expect(splitCommandSafely('echo "hello world"')).toEqual(['echo', 'hello world']);
      expect(splitCommandSafely("echo 'single quotes'")).toEqual(['echo', 'single quotes']);
    });
    
    it('should handle mixed quotes', () => {
      expect(splitCommandSafely('echo "hello" \'world\'')).toEqual(['echo', 'hello', 'world']);
    });
    
    it('should handle escaped characters', () => {
      expect(splitCommandSafely('echo \\"test\\"')).toEqual(['echo', '"test"']);
      expect(splitCommandSafely('path\\ with\\ spaces')).toEqual(['path with spaces']);
    });
    
    it('should return null for unclosed quotes', () => {
      expect(splitCommandSafely('echo "unclosed')).toBeNull();
      expect(splitCommandSafely("echo 'unclosed")).toBeNull();
    });
    
    it('should handle empty strings', () => {
      expect(splitCommandSafely('')).toEqual([]);
      expect(splitCommandSafely('   ')).toEqual([]);
    });
  });
});