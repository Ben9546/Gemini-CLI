# Shell Command Injection Security Fix

## Overview

This document describes a critical shell command injection vulnerability discovered in the Gemini CLI tool's shell execution functionality and the comprehensive security fix implemented to address it.

## Vulnerability Description

### CVE-like Details
- **Component**: Shell Tool (`packages/core/src/tools/shell.ts`)
- **Severity**: Critical
- **Impact**: Command Injection, Arbitrary Code Execution
- **Attack Vector**: User-controlled input passed to shell without validation

### Technical Details

The shell tool executes user-provided commands using `bash -c <command>` without proper validation or sanitization. This allows attackers to inject additional commands using shell metacharacters.

**Vulnerable code pattern:**
```typescript
// Before fix - no validation
spawn('bash', ['-c', params.command], {...})
```

### Attack Vectors

1. **Command Chaining**: Using `;`, `&&`, `||` to execute multiple commands
   ```bash
   safe_command; rm -rf /important/files
   ```

2. **Command Substitution**: Using `$()` or backticks to execute nested commands
   ```bash
   echo $(cat /etc/passwd)
   echo `whoami`
   ```

3. **Redirection Attacks**: Using `<`, `>` to access unauthorized files
   ```bash
   safe_command > /etc/passwd
   ```

4. **Background Process Injection**: Using `&` to start malicious background processes
   ```bash
   safe_command & malicious_daemon
   ```

5. **Newline Injection**: Using newlines to inject new command lines
   ```bash
   safe_command\nrm -rf /
   ```

## Security Fix Implementation

### 1. Command Validation (`commandSecurity.ts`)

Created a comprehensive command validation utility with the following features:

```typescript
export function validateCommandSafety(command: string): string | null {
  // Validates against dangerous patterns:
  // - Command chaining (;, &, |)
  // - Logical operators (&&, ||)
  // - Command substitution ($(), backticks)
  // - Redirection operators (<, >)
  // - Shell parameter expansion with operations
  // - Newline injection
  // - Dangerous base commands (eval, exec, source, .)
}
```

### 2. Cross-Platform Shell Escaping

Implemented proper shell argument escaping for both POSIX and Windows systems:

```typescript
export function escapeShellArgument(arg: string): string {
  if (os.platform() === 'win32') {
    return escapeShellArgumentWindows(arg);
  } else {
    return escapeShellArgumentPosix(arg);
  }
}
```

**POSIX Escaping**: Uses single quotes with proper handling of embedded quotes
**Windows Escaping**: Uses double quotes with caret escaping for cmd.exe metacharacters

### 3. Safe Command Splitting

Added a secure command parser that properly handles quoted arguments:

```typescript
export function splitCommandSafely(command: string): string[] | null {
  // Safely splits commands while preserving quoted sections
  // Returns null for malformed commands with unclosed quotes
}
```

### 4. Integration with Shell Tool

Updated the shell tool to use validation at multiple points:

1. **Parameter Validation**: All commands validated before execution
2. **Temp File Escaping**: Proper escaping of temporary file paths used in pgrep
3. **Error Prevention**: Commands rejected before reaching shell execution

```typescript
validateToolParams(params: ShellToolParams): string | null {
  // ... existing validation ...
  
  // Validate command safety before execution
  const safetyError = validateCommandSafety(params.command);
  if (safetyError) {
    return safetyError;
  }
  
  // ... rest of validation ...
}
```

## Testing Strategy

### Unit Tests (`commandSecurity.test.ts`)

Comprehensive test suite covering:
- All dangerous pattern detection
- Cross-platform escaping functionality
- Quote handling edge cases
- Command splitting edge cases

### Integration Tests (`shell-injection.test.ts`)

End-to-end tests demonstrating:
- Attack vector prevention
- Safe command execution
- Real-world injection scenarios
- Platform-specific behavior

## Security Considerations

### Defense in Depth

1. **Input Validation**: Commands validated before execution
2. **Shell Escaping**: Arguments properly escaped when needed
3. **Execution Control**: Using spawn with explicit argument arrays where possible
4. **Monitoring**: Security events can be logged for audit

### Limitations

- **Legitimate Use Cases**: Some advanced shell features may be blocked
- **Performance**: Validation adds minimal overhead to command execution
- **Compatibility**: May reject some complex but legitimate commands

### Bypass Prevention

The fix prevents common bypass techniques:
- **Quote Escaping**: Validation applies to full command including quotes
- **Encoding**: No encoding-based bypasses possible
- **Unicode**: Standard string validation prevents Unicode attacks

## Deployment Recommendations

1. **Immediate Deployment**: This is a critical security fix
2. **Testing**: Run integration tests in your environment
3. **Monitoring**: Monitor for rejected commands that may be false positives
4. **Documentation**: Update user documentation about command restrictions

## Future Enhancements

1. **Allow Lists**: Consider implementing configurable command allow lists
2. **Sandbox**: Additional process sandboxing for command execution
3. **Audit Logging**: Enhanced logging of security events
4. **Policy Engine**: More granular security policies

## References

- [OWASP Command Injection Prevention](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)