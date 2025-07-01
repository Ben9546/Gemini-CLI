# Symlink Path Traversal Prevention

## Overview

This document describes the security measures implemented to prevent symlink-based path traversal attacks in Gemini CLI's file system tools. The vulnerability allowed attackers to bypass directory restrictions using symbolic links.

## The Vulnerability (CVE-TBD)

### Description

A critical security vulnerability existed in Gemini CLI's file system tools where path validation was performed on the user-provided path rather than the actual canonical path. Since Node.js file system functions follow symlinks by default, this created a Time-of-check to Time-of-use (TOCTOU) vulnerability.

### Attack Scenario

An attacker could bypass workspace restrictions by creating a symbolic link inside an allowed directory that points to sensitive locations outside of it:

```bash
# Workspace restricted to /home/user/project
$ ln -s /etc /home/user/project/config
$ gemini read /home/user/project/config/passwd  # Would read /etc/passwd!
```

### Affected Components

- `read_file` - Could read files outside workspace
- `write_file` - Could write files outside workspace  
- `replace` (edit) - Could modify files outside workspace
- `list_directory` - Could list directories outside workspace
- `glob` - Could search patterns outside workspace

### Impact

- **Confidentiality**: Attackers could read sensitive files like `/etc/passwd`, SSH keys, or environment files
- **Integrity**: Attackers could modify system files or other projects' files
- **Availability**: Attackers could potentially corrupt critical system files

## The Solution

### 1. Secure Path Validation Utility

We've implemented a new `pathSecurity` module that provides secure path validation:

```typescript
// packages/core/src/utils/pathSecurity.ts

export function isPathWithinRoot(filePath: string, rootPath: string): boolean {
  try {
    // Resolve to absolute paths
    const normalizedRoot = path.resolve(rootPath);
    const absolutePath = path.resolve(rootPath, filePath);
    
    // For existing paths, resolve symlinks
    if (fs.existsSync(absolutePath)) {
      const realPath = fs.realpathSync(absolutePath);
      return isNormalizedPathWithinRoot(realPath, normalizedRoot);
    }
    
    // For non-existent paths, validate the normalized path
    return isNormalizedPathWithinRoot(absolutePath, normalizedRoot);
  } catch (error) {
    // Fail securely on any errors
    return false;
  }
}
```

### 2. Updated File System Tools

All file system tools now use the secure validation:

- `fileUtils.ts` - Updated central `isWithinRoot` function
- `write-file.ts` - Uses `isPathWithinRoot` 
- `edit.ts` - Uses `isPathWithinRoot`
- `ls.ts` - Uses `isPathWithinRoot`
- `glob.ts` - Uses `isPathWithinRoot`

### 3. Key Security Features

1. **Symlink Resolution**: Uses `fs.realpathSync()` to resolve symlinks before validation
2. **Fail-Safe Design**: Returns `false` on any errors (permission denied, etc.)
3. **Comprehensive Coverage**: Handles both existing and non-existing paths
4. **Path Normalization**: Properly normalizes paths for accurate comparison

## Testing

### Unit Tests

Comprehensive unit tests in `pathSecurity.test.ts` verify:
- Direct symlink attacks are blocked
- Relative path symlinks are blocked
- Symlink chains are properly resolved
- Parent directory symlinks are blocked
- Edge cases (permissions, root paths) are handled

### Integration Tests

The `symlink-path-traversal.test.js` integration test demonstrates:
- Various symlink attack vectors
- Proper blocking of escape attempts
- Continued functionality for legitimate access

## Migration Guide

For developers using Gemini CLI's file system tools:

1. **No API Changes**: The fix is transparent to users
2. **Behavior Change**: Symlinks pointing outside the workspace will now be blocked
3. **Legitimate Symlinks**: Symlinks within the workspace continue to work

## Best Practices

1. **Never Trust User Paths**: Always validate after resolving symlinks
2. **Use realpath**: Resolve symlinks before any security checks
3. **Fail Securely**: Block access if path resolution fails
4. **Test Symlink Scenarios**: Include symlink tests in security testing

## Performance Considerations

- **Minimal Impact**: `fs.realpathSync()` is fast for existing paths
- **Cached Results**: File system typically caches symlink resolutions
- **Non-Existing Paths**: No additional overhead for new files

## References

- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [Node.js fs.realpath documentation](https://nodejs.org/api/fs.html#fsrealpathpath-options-callback)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

## Acknowledgments

This vulnerability was reported in [Issue #1121](https://github.com/google-gemini/gemini-cli/issues/1121). We thank the security researcher for responsible disclosure.