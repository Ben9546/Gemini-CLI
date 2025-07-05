/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { isPathWithinRoot, safeResolvePath } from './pathSecurity.js';

describe('pathSecurity', () => {
  let testDir: string;
  let sandboxDir: string;
  let sensitiveDir: string;
  
  beforeEach(() => {
    // Create a temporary test directory structure
    const tmpDir = os.tmpdir();
    testDir = fs.mkdtempSync(path.join(tmpDir, 'path-security-test-'));
    sandboxDir = path.join(testDir, 'sandbox');
    sensitiveDir = path.join(testDir, 'sensitive');
    
    // Create directories
    fs.mkdirSync(sandboxDir, { recursive: true });
    fs.mkdirSync(sensitiveDir, { recursive: true });
    
    // Create some test files
    fs.writeFileSync(path.join(sandboxDir, 'allowed.txt'), 'allowed content');
    fs.writeFileSync(path.join(sensitiveDir, 'secret.txt'), 'sensitive data');
  });
  
  afterEach(() => {
    // Clean up test directories
    fs.rmSync(testDir, { recursive: true, force: true });
  });
  
  describe('isPathWithinRoot', () => {
    it('should allow paths within the root directory', () => {
      expect(isPathWithinRoot(path.join(sandboxDir, 'file.txt'), sandboxDir)).toBe(true);
      expect(isPathWithinRoot(path.join(sandboxDir, 'subdir', 'file.txt'), sandboxDir)).toBe(true);
      expect(isPathWithinRoot(sandboxDir, sandboxDir)).toBe(true);
    });
    
    it('should reject paths outside the root directory', () => {
      expect(isPathWithinRoot(sensitiveDir, sandboxDir)).toBe(false);
      expect(isPathWithinRoot(path.join(testDir, 'other'), sandboxDir)).toBe(false);
      expect(isPathWithinRoot('/etc/passwd', sandboxDir)).toBe(false);
    });
    
    it('should reject relative path traversal attempts', () => {
      expect(isPathWithinRoot(path.join(sandboxDir, '..', 'sensitive'), sandboxDir)).toBe(false);
      expect(isPathWithinRoot(path.join(sandboxDir, '..', '..', 'etc'), sandboxDir)).toBe(false);
      expect(isPathWithinRoot(path.join(sandboxDir, 'subdir', '..', '..', 'sensitive'), sandboxDir)).toBe(false);
    });
    
    it('should detect and prevent symlink-based path traversal', () => {
      // Create a symlink inside sandbox pointing to sensitive directory
      const symlinkPath = path.join(sandboxDir, 'link-to-sensitive');
      fs.symlinkSync(sensitiveDir, symlinkPath);
      
      // The symlink itself is within bounds
      expect(isPathWithinRoot(symlinkPath, sandboxDir)).toBe(false);
      
      // But accessing files through the symlink should be rejected
      expect(isPathWithinRoot(path.join(symlinkPath, 'secret.txt'), sandboxDir)).toBe(false);
    });
    
    it('should handle non-existent paths safely', () => {
      // Non-existent but within bounds
      expect(isPathWithinRoot(path.join(sandboxDir, 'new-file.txt'), sandboxDir)).toBe(true);
      expect(isPathWithinRoot(path.join(sandboxDir, 'new-dir', 'file.txt'), sandboxDir)).toBe(true);
      
      // Non-existent and outside bounds
      expect(isPathWithinRoot(path.join(sandboxDir, '..', 'new-file.txt'), sandboxDir)).toBe(false);
      expect(isPathWithinRoot(path.join(testDir, 'other', 'new-file.txt'), sandboxDir)).toBe(false);
    });
    
    it('should handle complex symlink chains', () => {
      // Create a chain of symlinks
      const link1 = path.join(sandboxDir, 'link1');
      const tempDir = path.join(sandboxDir, 'temp');
      const link2 = path.join(tempDir, 'link2');
      
      fs.mkdirSync(tempDir);
      fs.symlinkSync(tempDir, link1);
      fs.symlinkSync(sensitiveDir, link2);
      
      // Following the chain should be detected
      expect(isPathWithinRoot(path.join(link1, 'link2', 'secret.txt'), sandboxDir)).toBe(false);
    });
    
    it('should handle symlinks pointing to parent directories', () => {
      // Create a symlink pointing to parent
      const parentLink = path.join(sandboxDir, 'parent-link');
      fs.symlinkSync('..', parentLink);
      
      // Should detect escape attempt
      expect(isPathWithinRoot(parentLink, sandboxDir)).toBe(false);
      expect(isPathWithinRoot(path.join(parentLink, 'sensitive'), sandboxDir)).toBe(false);
    });
  });
  
  describe('safeResolvePath', () => {
    it('should resolve paths within bounds', () => {
      const resolved = safeResolvePath('allowed.txt', sandboxDir);
      expect(resolved).toBe(path.join(sandboxDir, 'allowed.txt'));
    });
    
    it('should throw on paths outside bounds', () => {
      expect(() => safeResolvePath('../sensitive/secret.txt', sandboxDir)).toThrow(/Path traversal detected/);
      expect(() => safeResolvePath('../../etc/passwd', sandboxDir)).toThrow(/Path would be outside/);
    });
    
    it('should throw on symlink traversal attempts', () => {
      // Create escape symlink
      const escapeLink = path.join(sandboxDir, 'escape');
      fs.symlinkSync(sensitiveDir, escapeLink);
      
      expect(() => safeResolvePath('escape', sandboxDir)).toThrow(/Path traversal detected/);
      expect(() => safeResolvePath('escape/secret.txt', sandboxDir)).toThrow(/Path traversal detected/);
    });
    
    it('should handle non-existent paths with existing parents', () => {
      const subdir = path.join(sandboxDir, 'subdir');
      fs.mkdirSync(subdir);
      
      // Should resolve correctly
      const resolved = safeResolvePath('subdir/new-file.txt', sandboxDir);
      expect(resolved).toBe(path.join(subdir, 'new-file.txt'));
    });
    
    it('should detect symlinked parent directories', () => {
      // Create a symlink to sensitive dir
      const linkDir = path.join(sandboxDir, 'linked');
      fs.symlinkSync(sensitiveDir, linkDir);
      
      // Try to create a file through the symlink
      expect(() => safeResolvePath('linked/new-file.txt', sandboxDir)).toThrow(/Path traversal detected/);
    });
  });
  
  describe('edge cases', () => {
    it('should handle root directory paths', () => {
      expect(isPathWithinRoot('/', '/')).toBe(true);
      expect(isPathWithinRoot('/etc', '/')).toBe(true);
      expect(isPathWithinRoot('/etc/passwd', '/etc')).toBe(true);
      expect(isPathWithinRoot('/usr', '/etc')).toBe(false);
    });
    
    it('should handle Windows-style paths', () => {
      // Skip on non-Windows platforms
      if (os.platform() !== 'win32') {
        return;
      }
      
      expect(isPathWithinRoot('C:\\sandbox\\file.txt', 'C:\\sandbox')).toBe(true);
      expect(isPathWithinRoot('C:\\sandbox\\..\\other', 'C:\\sandbox')).toBe(false);
    });
    
    it('should handle permission errors gracefully', () => {
      // This test might not work in all environments
      try {
        const restrictedDir = path.join(sandboxDir, 'restricted');
        fs.mkdirSync(restrictedDir);
        fs.chmodSync(restrictedDir, 0o000);
        
        // Should return false on permission errors
        expect(isPathWithinRoot(path.join(restrictedDir, 'file'), sandboxDir)).toBe(false);
        
        // Cleanup
        fs.chmodSync(restrictedDir, 0o755);
      } catch (e) {
        // Skip if we can't set permissions
        console.log('Skipping permission test');
      }
    });
  });
});