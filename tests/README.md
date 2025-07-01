# Test Organization

This directory contains all tests for the Gemini CLI project, organized by type:

## Directory Structure

```
tests/
├── integration/     # End-to-end integration tests
├── unit/           # Unit tests (from packages/)
└── helpers/        # Test utilities and runners
```

## Test Types

### Integration Tests (`tests/integration/`)

End-to-end tests that validate the complete functionality of the Gemini CLI. These tests:

- Test real interactions with external services
- Validate the full workflow from input to output
- Run in isolated environments (sandboxed when possible)

**Running integration tests:**

```bash
# Run all integration tests
npm run test:integration:all

# Run specific integration test
npm run test:integration:sandbox:none -- file-system

# Run with verbose output
npm run test:e2e
```

### Unit Tests (`tests/unit/`)

Unit tests for individual components and functions. These are typically located within the respective packages:

- `packages/cli/src/**/*.test.{ts,tsx}`
- `packages/core/src/**/*.test.ts`

**Running unit tests:**

```bash
npm run test
```

### Test Helpers (`tests/helpers/`)

Utilities and runners for the test infrastructure:

- `run-tests.js` - Main integration test runner
- `test-helper.js` - Common test utilities

## Test Configuration

Integration tests can be run with different sandbox configurations:

- `test:integration:sandbox:none` - No sandboxing
- `test:integration:sandbox:docker` - Docker-based sandboxing
- `test:integration:sandbox:podman` - Podman-based sandboxing

## Adding New Tests

### Adding Integration Tests

1. Create a new `.test.js` file in `tests/integration/`
2. Follow the existing test patterns
3. Use the test helper utilities from `tests/helpers/test-helper.js`

### Adding Unit Tests

1. Create test files alongside the source code in the respective packages
2. Use the existing test framework (Vitest)
3. Follow the naming convention `*.test.{ts,tsx}`

## Migration Notes

This test organization was migrated from the previous structure where integration tests were in `integration-tests/`. The new structure provides:

- Better separation of concerns
- Clearer organization for different test types
- Easier navigation and maintenance
- Consistent with modern testing practices
