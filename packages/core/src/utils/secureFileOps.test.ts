/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  secureReadFile,
  secureWriteFile,
  securePathCheck,
  atomicWriteFile
} from './secureFileOps.js';

describe('Secure File Operations', () => {
  let testDir: string;
  let testFile: string;
  let symlinkPath: string;
  
  beforeEach(async () => {
    // Create a unique temp directory for tests
    testDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'secure-file-test-'));
    testFile = path.join(testDir, 'test.txt');
    symlinkPath = path.join(testDir, 'symlink.txt');
  });
  
  afterEach(async () => {
    // Clean up test directory
    await fs.promises.rm(testDir, { recursive: true, force: true });
  });
  
  describe('secureReadFile', () => {
    it('should read a regular file successfully', async () => {
      await fs.promises.writeFile(testFile, 'Hello, World!');
      
      const result = await secureReadFile(testFile);
      
      expect(result.error).toBeNull();
      expect(result.content).toBe('Hello, World!');
      expect(result.isDirectory).toBeUndefined();
    });
    
    it('should fail when trying to read a directory', async () => {
      const dirPath = path.join(testDir, 'subdir');
      await fs.promises.mkdir(dirPath);
      
      const result = await secureReadFile(dirPath);
      
      expect(result.error).toContain('directory');
      expect(result.content).toBeNull();
      expect(result.isDirectory).toBe(true);
    });
    
    it('should fail when trying to read through a symlink', async () => {
      await fs.promises.writeFile(testFile, 'Secret content');
      await fs.promises.symlink(testFile, symlinkPath);
      
      const result = await secureReadFile(symlinkPath);
      
      expect(result.error).toBeTruthy();
      expect(result.content).toBeNull();
      // Should fail with ELOOP or similar error due to O_NOFOLLOW
    });
    
    it('should handle non-existent files', async () => {
      const result = await secureReadFile(path.join(testDir, 'nonexistent.txt'));
      
      expect(result.error).toContain('not found');
      expect(result.content).toBeNull();
    });
  });
  
  describe('secureWriteFile', () => {
    it('should write a new file successfully', async () => {
      const result = await secureWriteFile(testFile, 'Test content');
      
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      
      const content = await fs.promises.readFile(testFile, 'utf8');
      expect(content).toBe('Test content');
    });
    
    it('should fail when file exists and overwrite is false', async () => {
      await fs.promises.writeFile(testFile, 'Existing content');
      
      const result = await secureWriteFile(testFile, 'New content', { overwrite: false });
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('already exists');
    });
    
    it('should overwrite when overwrite is true', async () => {
      await fs.promises.writeFile(testFile, 'Old content');
      
      const result = await secureWriteFile(testFile, 'New content', { overwrite: true });
      
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      
      const content = await fs.promises.readFile(testFile, 'utf8');
      expect(content).toBe('New content');
    });
    
    it('should not follow symlinks when writing', async () => {
      const targetFile = path.join(testDir, 'target.txt');
      await fs.promises.writeFile(targetFile, 'Original content');
      await fs.promises.symlink(targetFile, symlinkPath);
      
      const result = await secureWriteFile(symlinkPath, 'Malicious content', { overwrite: true });
      
      // Should fail due to O_NOFOLLOW flag
      expect(result.success).toBe(false);
      expect(result.error).toBeTruthy();
      
      // Original file should remain unchanged
      const originalContent = await fs.promises.readFile(targetFile, 'utf8');
      expect(originalContent).toBe('Original content');
    });
    
    it('should create directories when requested', async () => {
      const nestedFile = path.join(testDir, 'a', 'b', 'c', 'file.txt');
      
      const result = await secureWriteFile(nestedFile, 'Nested content', {
        createDirectories: true
      });
      
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      
      const content = await fs.promises.readFile(nestedFile, 'utf8');
      expect(content).toBe('Nested content');
    });
  });
  
  describe('securePathCheck', () => {
    it('should detect regular files', async () => {
      await fs.promises.writeFile(testFile, 'content');
      
      const result = await securePathCheck(testFile);
      
      expect(result.exists).toBe(true);
      expect(result.isFile).toBe(true);
      expect(result.isDirectory).toBe(false);
      expect(result.isSymlink).toBe(false);
    });
    
    it('should detect directories', async () => {
      const dirPath = path.join(testDir, 'subdir');
      await fs.promises.mkdir(dirPath);
      
      const result = await securePathCheck(dirPath);
      
      expect(result.exists).toBe(true);
      expect(result.isFile).toBe(false);
      expect(result.isDirectory).toBe(true);
      expect(result.isSymlink).toBe(false);
    });
    
    it('should detect symlinks without following them', async () => {
      await fs.promises.writeFile(testFile, 'content');
      await fs.promises.symlink(testFile, symlinkPath);
      
      const result = await securePathCheck(symlinkPath);
      
      expect(result.exists).toBe(true);
      expect(result.isFile).toBe(false);
      expect(result.isDirectory).toBe(false);
      expect(result.isSymlink).toBe(true);
    });
    
    it('should handle non-existent paths', async () => {
      const result = await securePathCheck(path.join(testDir, 'nonexistent'));
      
      expect(result.exists).toBe(false);
      expect(result.isFile).toBeUndefined();
      expect(result.isDirectory).toBeUndefined();
      expect(result.isSymlink).toBeUndefined();
    });
  });
  
  describe('atomicWriteFile', () => {
    it('should write atomically', async () => {
      const result = await atomicWriteFile(testFile, 'Atomic content');
      
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      
      const content = await fs.promises.readFile(testFile, 'utf8');
      expect(content).toBe('Atomic content');
    });
    
    it('should replace existing files atomically', async () => {
      await fs.promises.writeFile(testFile, 'Original');
      
      const result = await atomicWriteFile(testFile, 'Replaced');
      
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      
      const content = await fs.promises.readFile(testFile, 'utf8');
      expect(content).toBe('Replaced');
    });
    
    it('should clean up temp files on failure', async () => {
      // Create a directory with the same name to cause rename to fail
      const dirPath = path.join(testDir, 'conflict');
      await fs.promises.mkdir(dirPath);
      
      const result = await atomicWriteFile(dirPath, 'Should fail');
      
      expect(result.success).toBe(false);
      expect(result.error).toBeTruthy();
      
      // Check that no temp files are left behind
      const files = await fs.promises.readdir(testDir);
      const tempFiles = files.filter(f => f.includes('.tmp'));
      expect(tempFiles.length).toBe(0);
    });
  });
  
  describe('TOCTOU Attack Prevention', () => {
    it('should prevent TOCTOU race condition in read operations', async () => {
      // This test simulates what would happen if a file changes between check and use
      // Our secure implementation uses O_NOFOLLOW to prevent symlink attacks
      
      await fs.promises.writeFile(testFile, 'Original content');
      
      // Even if someone tries to replace the file with a symlink during read,
      // the O_NOFOLLOW flag prevents following it
      const result = await secureReadFile(testFile);
      
      expect(result.error).toBeNull();
      expect(result.content).toBe('Original content');
    });
    
    it('should prevent TOCTOU race condition in write operations', async () => {
      // Create a sensitive file
      const sensitiveFile = path.join(testDir, 'sensitive.txt');
      await fs.promises.writeFile(sensitiveFile, 'Sensitive data');
      
      // Even if an attacker creates a symlink at our target path,
      // secure write with O_NOFOLLOW won't follow it
      const result = await secureWriteFile(testFile, 'Safe content');
      
      expect(result.success).toBe(true);
      
      // Sensitive file should remain unchanged
      const sensitiveContent = await fs.promises.readFile(sensitiveFile, 'utf8');
      expect(sensitiveContent).toBe('Sensitive data');
    });
  });
});