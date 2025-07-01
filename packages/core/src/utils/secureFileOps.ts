/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';

const openAsync = promisify(fs.open);
const fstatAsync = promisify(fs.fstat);
const closeAsync = promisify(fs.close);

/**
 * Securely reads a file using file descriptors to prevent TOCTOU attacks.
 * Opens the file with O_NOFOLLOW to prevent symlink attacks.
 */
export async function secureReadFile(filePath: string): Promise<{
  content: string | null;
  error: string | null;
  isDirectory?: boolean;
}> {
  let fd: number | null = null;
  
  try {
    // Open with O_NOFOLLOW to prevent following symlinks
    // O_RDONLY = 0, O_NOFOLLOW = 0x20000 (on most Unix systems)
    const O_RDONLY = fs.constants.O_RDONLY || 0;
    const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0x20000;
    
    fd = await openAsync(filePath, O_RDONLY | O_NOFOLLOW);
    
    // Now check the opened file descriptor, not the path
    const stats = await fstatAsync(fd);
    
    if (stats.isDirectory()) {
      return {
        content: null,
        error: `Path is a directory, not a file: ${filePath}`,
        isDirectory: true
      };
    }
    
    if (!stats.isFile()) {
      return {
        content: null,
        error: `Path is not a regular file: ${filePath}`
      };
    }
    
    // Read using the file descriptor
    const buffer = Buffer.alloc(stats.size);
    let position = 0;
    let totalBytesRead = 0;
    
    // Read in chunks to handle large files
    while (totalBytesRead < stats.size) {
      const remainingBytes = stats.size - totalBytesRead;
      const chunkSize = Math.min(remainingBytes, 65536); // 64KB chunks
      
      const result = await new Promise<{ bytesRead: number }>((resolve, reject) => {
        fs.read(fd, buffer, totalBytesRead, chunkSize, position, (err, bytesRead) => {
          if (err) reject(err);
          else resolve({ bytesRead });
        });
      });
      
      if (result.bytesRead === 0) break; // EOF
      totalBytesRead += result.bytesRead;
      position += result.bytesRead;
    }
    
    const content = buffer.subarray(0, totalBytesRead).toString('utf8');
    
    return {
      content,
      error: null
    };
    
  } catch (err: any) {
    if (err.code === 'ENOENT') {
      return {
        content: null,
        error: `File not found: ${filePath}`
      };
    } else if (err.code === 'ELOOP') {
      return {
        content: null,
        error: `Too many symbolic links encountered: ${filePath}`
      };
    } else if (err.code === 'EISDIR') {
      return {
        content: null,
        error: `Path is a directory: ${filePath}`,
        isDirectory: true
      };
    } else if (err.code === 'EACCES') {
      return {
        content: null,
        error: `Permission denied: ${filePath}`
      };
    }
    
    return {
      content: null,
      error: `Error reading file: ${err.message}`
    };
    
  } finally {
    if (fd !== null) {
      try {
        await closeAsync(fd);
      } catch (closeErr) {
        // Log but don't throw - we already have our result
        console.error(`Failed to close file descriptor: ${closeErr}`);
      }
    }
  }
}

/**
 * Securely writes to a file using file descriptors to prevent TOCTOU attacks.
 * Uses exclusive creation flags to prevent overwriting sensitive files via symlinks.
 */
export async function secureWriteFile(
  filePath: string, 
  content: string,
  options?: {
    overwrite?: boolean;
    createDirectories?: boolean;
  }
): Promise<{
  success: boolean;
  error: string | null;
}> {
  let fd: number | null = null;
  const opts = { overwrite: false, createDirectories: true, ...options };
  
  try {
    // Create directory if needed
    if (opts.createDirectories) {
      const dirName = path.dirname(filePath);
      await fs.promises.mkdir(dirName, { recursive: true });
    }
    
    // Open with appropriate flags
    const O_WRONLY = fs.constants.O_WRONLY || 0x1;
    const O_CREAT = fs.constants.O_CREAT || 0x200;
    const O_EXCL = fs.constants.O_EXCL || 0x800;
    const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0x20000;
    const O_TRUNC = fs.constants.O_TRUNC || 0x400;
    
    let flags = O_WRONLY | O_CREAT | O_NOFOLLOW;
    
    if (!opts.overwrite) {
      // Exclusive creation - fails if file exists
      flags |= O_EXCL;
    } else {
      // Truncate existing file
      flags |= O_TRUNC;
    }
    
    // Mode 0o666 (readable/writable by all, subject to umask)
    fd = await openAsync(filePath, flags, 0o666);
    
    // Verify we opened a regular file (defense in depth)
    const stats = await fstatAsync(fd);
    if (!stats.isFile()) {
      return {
        success: false,
        error: `Opened descriptor is not a regular file: ${filePath}`
      };
    }
    
    // Write content using the file descriptor
    const buffer = Buffer.from(content, 'utf8');
    let written = 0;
    
    while (written < buffer.length) {
      const toWrite = buffer.length - written;
      
      const bytesWritten = await new Promise<number>((resolve, reject) => {
        fs.write(fd, buffer, written, toWrite, null, (err, bytesWritten) => {
          if (err) reject(err);
          else resolve(bytesWritten);
        });
      });
      
      written += bytesWritten;
    }
    
    // Ensure data is flushed to disk
    await new Promise<void>((resolve, reject) => {
      fs.fsync(fd, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    
    return {
      success: true,
      error: null
    };
    
  } catch (err: any) {
    if (err.code === 'EEXIST') {
      return {
        success: false,
        error: `File already exists: ${filePath}`
      };
    } else if (err.code === 'ELOOP') {
      return {
        success: false,
        error: `Too many symbolic links encountered: ${filePath}`
      };
    } else if (err.code === 'EISDIR') {
      return {
        success: false,
        error: `Path is a directory: ${filePath}`
      };
    } else if (err.code === 'EACCES') {
      return {
        success: false,
        error: `Permission denied: ${filePath}`
      };
    } else if (err.code === 'ENOSPC') {
      return {
        success: false,
        error: `No space left on device: ${filePath}`
      };
    }
    
    return {
      success: false,
      error: `Error writing file: ${err.message}`
    };
    
  } finally {
    if (fd !== null) {
      try {
        await closeAsync(fd);
      } catch (closeErr) {
        console.error(`Failed to close file descriptor: ${closeErr}`);
      }
    }
  }
}

/**
 * Securely checks if a path exists and returns its type without following symlinks.
 * This is safer than fs.existsSync for security-sensitive operations.
 */
export async function securePathCheck(filePath: string): Promise<{
  exists: boolean;
  isFile?: boolean;
  isDirectory?: boolean;
  isSymlink?: boolean;
  error?: string;
}> {
  try {
    // Use lstat to not follow symlinks
    const stats = await fs.promises.lstat(filePath);
    
    return {
      exists: true,
      isFile: stats.isFile(),
      isDirectory: stats.isDirectory(),
      isSymlink: stats.isSymbolicLink()
    };
    
  } catch (err: any) {
    if (err.code === 'ENOENT') {
      return { exists: false };
    }
    
    return {
      exists: false,
      error: `Error checking path: ${err.message}`
    };
  }
}

/**
 * Atomically replaces a file's content by writing to a temporary file
 * and renaming it. This prevents partial writes and TOCTOU attacks.
 */
export async function atomicWriteFile(
  filePath: string,
  content: string
): Promise<{
  success: boolean;
  error: string | null;
}> {
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  
  try {
    // Write to temporary file
    const writeResult = await secureWriteFile(tempPath, content, {
      overwrite: false,
      createDirectories: true
    });
    
    if (!writeResult.success) {
      return writeResult;
    }
    
    // Atomically rename temp file to target
    // This operation is atomic on POSIX systems
    await fs.promises.rename(tempPath, filePath);
    
    return {
      success: true,
      error: null
    };
    
  } catch (err: any) {
    // Clean up temp file if it exists
    try {
      await fs.promises.unlink(tempPath);
    } catch (unlinkErr) {
      // Ignore - temp file might not exist
    }
    
    return {
      success: false,
      error: `Atomic write failed: ${err.message}`
    };
  }
}