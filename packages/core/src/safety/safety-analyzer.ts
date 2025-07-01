import { commandSafety } from './command-safety-db.js';

export type SafetyLevel = 'safe' | 'requires-approval' | 'dangerous';

/**
 * Analyzes a command string and returns its safety level
 * @param command - The full command string to analyze
 * @returns SafetyLevel indicating how the command should be handled
 */
export function analyzeSafety(command: string): SafetyLevel {
  if (!command || command.trim().length === 0) {
    return 'requires-approval';
  }

  const trimmedCommand = command.trim();
  const parts = trimmedCommand.split(/\s+/);
  const mainCommand = parts[0];
  const subCommand = parts[1];
  const flags = parts.filter(part => part.startsWith('-'));
  const arguments_array = parts.slice(1);

  // Check if main command exists in database
  if (!commandSafety[mainCommand]) {
    // Unknown commands require approval by default
    return 'requires-approval';
  }

  const commandConfig = commandSafety[mainCommand];

  // If it's a simple string safety level, return it
  if (typeof commandConfig === 'string') {
    return commandConfig as SafetyLevel;
  }

  // Handle special cases for nested command analysis
  if (commandConfig['*'] === 'analyze-nested-command') {
    return analyzeNestedCommand(parts);
  }

  // Start with default safety level
  let safetyLevel: SafetyLevel = 'safe';

  // Check subcommand safety first
  if (subCommand && commandConfig[subCommand]) {
    const subConfig = commandConfig[subCommand];
    
    if (typeof subConfig === 'string') {
      safetyLevel = subConfig as SafetyLevel;
    } else if (typeof subConfig === 'object') {
      // Handle nested subcommand configuration
      safetyLevel = analyzeNestedSubcommand(subConfig, arguments_array.slice(1), flags);
    }
  } else if (commandConfig['*']) {
    // Use wildcard default if specific subcommand not found
    safetyLevel = commandConfig['*'] as SafetyLevel;
  } else {
    // No specific subcommand found, default to requires-approval
    safetyLevel = 'requires-approval';
  }

  // Check flags for safety overrides (flags can make commands more dangerous)
  safetyLevel = checkFlagsForSafetyOverride(commandConfig, flags, safetyLevel);

  // Additional safety checks
  safetyLevel = performAdditionalSafetyChecks(trimmedCommand, safetyLevel);

  return safetyLevel;
}

/**
 * Analyzes nested commands like 'timeout 30 ls' or 'xargs rm'
 */
function analyzeNestedCommand(parts: string[]): SafetyLevel {
  const mainCommand = parts[0];
  
  if (mainCommand === 'timeout') {
    // For timeout, analyze the actual command after the timeout value
    // Format: timeout [duration] [command...]
    if (parts.length >= 3) {
      const nestedCommand = parts.slice(2).join(' ');
      return analyzeSafety(nestedCommand);
    }
    return 'requires-approval';
  }
  
  if (mainCommand === 'xargs') {
    // For xargs, analyze the command being executed
    // Format: xargs [options] [command]
    const commandIndex = parts.findIndex(part => !part.startsWith('-') && part !== 'xargs');
    if (commandIndex > 0 && commandIndex < parts.length) {
      const nestedCommand = parts.slice(commandIndex).join(' ');
      // xargs makes any command potentially more dangerous due to batch execution
      const nestedSafety = analyzeSafety(nestedCommand);
      return escalateSafetyLevel(nestedSafety);
    }
    return 'requires-approval';
  }
  
  if (mainCommand === 'watch') {
    // For watch, analyze the command being watched
    // Format: watch [options] [command]
    const commandIndex = parts.findIndex(part => !part.startsWith('-') && part !== 'watch');
    if (commandIndex > 0 && commandIndex < parts.length) {
      const nestedCommand = parts.slice(commandIndex).join(' ');
      // watch is generally safe as it just repeats commands
      return analyzeSafety(nestedCommand);
    }
    return 'requires-approval';
  }
  
  return 'requires-approval';
}

/**
 * Analyzes nested subcommand configurations
 */
function analyzeNestedSubcommand(
  subConfig: Record<string, any>, 
  remainingArgs: string[], 
  flags: string[]
): SafetyLevel {
  // Check if any of the remaining arguments match specific configurations
  for (const arg of remainingArgs) {
    if (subConfig[arg]) {
      return subConfig[arg] as SafetyLevel;
    }
  }
  
  // Check flags within the subcommand
  for (const flag of flags) {
    if (subConfig[flag]) {
      return subConfig[flag] as SafetyLevel;
    }
  }
  
  // Use wildcard default
  return (subConfig['*'] || 'requires-approval') as SafetyLevel;
}

/**
 * Checks flags for safety overrides - dangerous flags make commands more dangerous
 */
function checkFlagsForSafetyOverride(
  commandConfig: Record<string, any>,
  flags: string[],
  currentSafety: SafetyLevel
): SafetyLevel {
  let safetyLevel = currentSafety;
  
  for (const flag of flags) {
    if (commandConfig[flag]) {
      const flagSafety = commandConfig[flag] as SafetyLevel;
      // Use the most restrictive safety level
      safetyLevel = getMostRestrictiveSafetyLevel(safetyLevel, flagSafety);
    }
  }
  
  return safetyLevel;
}

/**
 * Performs additional heuristic safety checks
 */
function performAdditionalSafetyChecks(command: string, currentSafety: SafetyLevel): SafetyLevel {
  // Check for dangerous patterns
  const dangerousPatterns = [
    /rm\s+.*-r.*\//,  // recursive delete with paths
    /rm\s+.*-f.*\*/,  // force delete with wildcards
    />\s*\/dev\/null/,  // redirecting to /dev/null might hide important output
    /sudo\s+.*rm/,    // sudo + rm combination
    /chmod\s+777/,    // overly permissive permissions
    /\|\s*sh/,        // piping to shell
    /curl.*\|\s*bash/,  // downloading and executing scripts
  ];
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(command)) {
      return 'dangerous';
    }
  }
  
  // Check for system directories
  const systemPaths = ['/', '/usr', '/etc', '/var', '/sys', '/proc', '/boot'];
  for (const path of systemPaths) {
    if (command.includes(path) && (command.includes('rm') || command.includes('del'))) {
      return 'dangerous';
    }
  }
  
  // Check for potential data loss commands
  if (command.includes('--force') && (command.includes('rm') || command.includes('delete'))) {
    return escalateSafetyLevel(currentSafety);
  }
  
  return currentSafety;
}

/**
 * Returns the most restrictive safety level between two levels
 */
function getMostRestrictiveSafetyLevel(level1: SafetyLevel, level2: SafetyLevel): SafetyLevel {
  const hierarchy = { 'safe': 0, 'requires-approval': 1, 'dangerous': 2 };
  
  if (hierarchy[level1] >= hierarchy[level2]) {
    return level1;
  }
  return level2;
}

/**
 * Escalates a safety level to the next more restrictive level
 */
function escalateSafetyLevel(currentLevel: SafetyLevel): SafetyLevel {
  switch (currentLevel) {
    case 'safe':
      return 'requires-approval';
    case 'requires-approval':
      return 'dangerous';
    case 'dangerous':
      return 'dangerous'; // Already at max restriction
    default:
      return 'requires-approval';
  }
}

/**
 * Helper function to get a human-readable description of the safety level
 */
export function getSafetyDescription(level: SafetyLevel): string {
  switch (level) {
    case 'safe':
      return 'Safe to execute automatically';
    case 'requires-approval':
      return 'Requires user approval before execution';
    case 'dangerous':
      return 'Dangerous operation - requires explicit confirmation';
    default:
      return 'Unknown safety level';
  }
}

/**
 * Validates if a command should be auto-approved based on configuration
 */
export function shouldAutoApprove(command: string, autoApproveEnabled: boolean = true): boolean {
  if (!autoApproveEnabled) {
    return false;
  }
  
  const safetyLevel = analyzeSafety(command);
  return safetyLevel === 'safe';
}