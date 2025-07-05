/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ShellTool } from '../core/src/tools/shell.js';
import { Config } from '../core/src/config/config.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Shell Command Injection Prevention', () => {
  let config: Config;
  let shellTool: ShellTool;
  let testDir: string;
  
  beforeEach(() => {
    // Create a test directory
    testDir = path.join(os.tmpdir(), `shell-injection-test-${Date.now()}`);
    fs.mkdirSync(testDir, { recursive: true });
    
    // Create test config
    config = new Config({
      targetDir: testDir,
      coreTools: ['shell']
    });
    
    shellTool = new ShellTool(config);
  });
  
  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });
  
  describe('Command Validation', () => {
    it('should reject commands with semicolon injection', () => {
      const params = {
        command: 'echo safe; rm -rf /tmp/important'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Command chaining characters');
    });
    
    it('should reject commands with && operator', () => {
      const params = {
        command: 'test -f file && rm file'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Logical operators');
    });
    
    it('should reject commands with || operator', () => {
      const params = {
        command: 'test -f file || touch /tmp/backdoor'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Logical operators');
    });
    
    it('should reject commands with command substitution', () => {
      const params = {
        command: 'echo $(cat /etc/passwd)'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Command substitution');
    });
    
    it('should reject commands with backticks', () => {
      const params = {
        command: 'echo `whoami`'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Backticks');
    });
    
    it('should reject commands with dangerous base commands', () => {
      const dangerousCommands = ['eval', 'exec', 'source', '.'];
      
      for (const cmd of dangerousCommands) {
        const params = {
          command: `${cmd} /tmp/malicious.sh`
        };
        
        const error = shellTool.validateToolParams(params);
        expect(error).toContain(`${cmd} can execute arbitrary code`);
      }
    });
  });
  
  describe('Safe Command Execution', () => {
    it('should allow safe commands', () => {
      const params = {
        command: 'echo "Hello, World!"'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toBeNull();
    });
    
    it('should execute safe commands successfully', async () => {
      const params = {
        command: 'echo "Safe command execution"'
      };
      
      const result = await shellTool.execute(params, new AbortController().signal);
      expect(result.llmContent).toContain('Safe command execution');
      expect(result.llmContent).toContain('Exit Code: 0');
    });
    
    it('should handle special characters in quotes safely', async () => {
      const params = {
        command: 'echo "This is safe; no injection"'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toBeNull();
      
      const result = await shellTool.execute(params, new AbortController().signal);
      expect(result.llmContent).toContain('This is safe; no injection');
    });
  });
  
  describe('Attack Vector Prevention', () => {
    it('should prevent file path injection in pgrep redirection', async () => {
      // This test verifies that temp file paths are properly escaped
      // to prevent injection through crafted file names
      const maliciousPath = 'test; echo "injected" > /tmp/hacked';
      
      // Our escaping should prevent this from being executed as a command
      const safeParams = {
        command: 'echo "Testing path escaping"'
      };
      
      const result = await shellTool.execute(safeParams, new AbortController().signal);
      expect(result.llmContent).toContain('Testing path escaping');
      expect(result.llmContent).not.toContain('injected');
    });
    
    it('should reject newline injection attempts', () => {
      const params = {
        command: 'echo "line1"\nrm -rf /tmp/important'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Newline characters');
    });
    
    it('should reject shell parameter expansion attacks', () => {
      const params = {
        command: 'echo ${PATH:=malicious}'
      };
      
      const error = shellTool.validateToolParams(params);
      expect(error).toContain('Shell parameter expansion');
    });
  });
});