/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * Securely validates that a file path is within the allowed root directory.
 * This function prevents symlink-based path traversal attacks by resolving
 * the real path before validation.
 * 
 * @param filePath - The path to validate (may contain symlinks)
 * @param rootPath - The root directory that the path must be within
 * @returns true if the path is safely within the root, false otherwise
 */
export function isPathWithinRoot(filePath: string, rootPath: string): boolean {
  try {
    // Normalize the root path first
    const normalizedRoot = path.resolve(rootPath);
    
    // Resolve the file path to its absolute form
    const absolutePath = path.resolve(rootPath, filePath);
    
    // Check if the path exists
    if (!fs.existsSync(absolutePath)) {
      // For non-existent paths, we can't resolve symlinks, but we can still
      // check if the path would be within bounds when created
      return isNormalizedPathWithinRoot(absolutePath, normalizedRoot);
    }
    
    // For existing paths, resolve any symlinks to get the real path
    const realPath = fs.realpathSync(absolutePath);
    
    // Check if the real path is within the root
    return isNormalizedPathWithinRoot(realPath, normalizedRoot);
  } catch (error) {
    // If we can't resolve the path (e.g., permission denied), 
    // err on the side of caution and reject it
    return false;
  }
}

/**
 * Helper function to check if a normalized path is within a root directory.
 * Both paths should be absolute and normalized.
 */
function isNormalizedPathWithinRoot(normalizedPath: string, normalizedRoot: string): boolean {
  // Ensure both paths end with a separator for accurate comparison
  const pathWithSep = normalizedPath + path.sep;
  const rootWithSep = normalizedRoot + path.sep;
  
  // Check if the path starts with the root
  return pathWithSep.startsWith(rootWithSep) || normalizedPath === normalizedRoot;
}

/**
 * Safely resolves a path, handling both existing and non-existing paths.
 * For existing paths, follows symlinks. For non-existing paths, resolves
 * parent directories that exist and validates the remaining path.
 * 
 * @param filePath - The path to resolve
 * @param rootPath - The root directory for resolution
 * @returns The resolved real path
 * @throws Error if the path would escape the root directory
 */
export function safeResolvePath(filePath: string, rootPath: string): string {
  const normalizedRoot = path.resolve(rootPath);
  const absolutePath = path.resolve(rootPath, filePath);
  
  // If the path exists, resolve it fully
  if (fs.existsSync(absolutePath)) {
    const realPath = fs.realpathSync(absolutePath);
    if (!isNormalizedPathWithinRoot(realPath, normalizedRoot)) {
      throw new Error(`Path traversal detected: ${filePath} resolves outside of allowed directory`);
    }
    return realPath;
  }
  
  // For non-existent paths, validate that they would be within bounds
  if (!isNormalizedPathWithinRoot(absolutePath, normalizedRoot)) {
    throw new Error(`Path would be outside allowed directory: ${filePath}`);
  }
  
  // Find the deepest existing parent directory and resolve it
  let currentPath = absolutePath;
  let nonExistentParts: string[] = [];
  
  while (!fs.existsSync(currentPath) && currentPath !== path.dirname(currentPath)) {
    nonExistentParts.unshift(path.basename(currentPath));
    currentPath = path.dirname(currentPath);
  }
  
  // If we found an existing parent, resolve it
  if (fs.existsSync(currentPath)) {
    const realParentPath = fs.realpathSync(currentPath);
    
    // Reconstruct the full path with the real parent
    const realFullPath = path.join(realParentPath, ...nonExistentParts);
    
    // Validate the final path
    if (!isNormalizedPathWithinRoot(realFullPath, normalizedRoot)) {
      throw new Error(`Path traversal detected: ${filePath} would resolve outside of allowed directory`);
    }
    
    return realFullPath;
  }
  
  // If no part of the path exists, just validate the normalized path
  if (!isNormalizedPathWithinRoot(absolutePath, normalizedRoot)) {
    throw new Error(`Path would be outside allowed directory: ${filePath}`);
  }
  
  return absolutePath;
}