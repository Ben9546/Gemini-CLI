/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { PromptAssembler } from './PromptAssembler.js';
import type { TaskContext } from './interfaces/prompt-assembly.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function debugLiveTest() {
  console.log('🔧 Debug Live Test - Checking Module Loading\n');

  try {
    // Initialize assembler with explicit module directory
    const assembler = new PromptAssembler({
      moduleDirectory: __dirname,
      enableCaching: true,
      maxTokenBudget: 1500,
      validateDependencies: true,
      selectionStrategy: 'default',
    });

    console.log('✅ PromptAssembler initialized successfully');

    // Test basic context
    const basicContext: TaskContext = {
      taskType: 'general',
      environment: {},
      hasGitRepo: false,
      sandboxMode: 'none',
      userMemory: 'Test user memory content',
    };

    console.log('🧪 Testing basic prompt assembly...');
    const result = await assembler.assemblePrompt(basicContext);

    console.log('📊 Assembly Results:');
    console.log(`  - Success: ${result.prompt.length > 0}`);
    console.log(`  - Content Length: ${result.prompt.length}`);
    console.log(`  - Token Count: ${result.totalTokens}`);
    console.log(`  - Modules Loaded: ${result.includedModules.length || 0}`);
    console.log(
      `  - Modules: ${result.includedModules.map((m) => m.id).join(', ') || 'None'}`,
    );

    if (result.warnings && result.warnings.length > 0) {
      console.log('⚠️  Warnings:');
      result.warnings.forEach((warning) => console.log(`  - ${warning}`));
    }

    // Note: AssemblyResult interface only has warnings, not errors

    console.log('\n📄 Generated Content Preview:');
    console.log('---');
    console.log(result.prompt.substring(0, 500) + '...');
    console.log('---');

    return result.prompt.length > 0 && result.warnings.length === 0;
  } catch (error) {
    console.error(`❌ Test failed: ${error instanceof Error ? error.message : String(error)}`);
    if (error instanceof Error) {
      console.error(error.stack);
    }
    return false;
  }
}

// Run the debug test
debugLiveTest().then((success) => {
  console.log(
    `\n🎯 Debug Test Result: ${success ? '✅ SUCCESS' : '❌ FAILED'}`,
  );
  process.exit(success ? 0 : 1);
});
