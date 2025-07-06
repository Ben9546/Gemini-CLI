/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

const { mockProcessExit } = vi.hoisted(() => ({
  mockProcessExit: vi.fn((_code?: number): never => undefined as never),
}));

vi.mock('node:process', () => ({
  default: {
    exit: mockProcessExit,
    cwd: vi.fn(() => '/mock/cwd'),
    get env() {
      return process.env;
    }, // Use a getter to ensure current process.env is used
    platform: 'test-platform',
    version: 'test-node-version',
    memoryUsage: vi.fn(() => ({
      rss: 12345678,
      heapTotal: 23456789,
      heapUsed: 10234567,
      external: 1234567,
      arrayBuffers: 123456,
    })),
  },
  // Provide top-level exports as well for compatibility
  exit: mockProcessExit,
  cwd: vi.fn(() => '/mock/cwd'),
  get env() {
    return process.env;
  }, // Use a getter here too
  platform: 'test-platform',
  version: 'test-node-version',
  memoryUsage: vi.fn(() => ({
    rss: 12345678,
    heapTotal: 23456789,
    heapUsed: 10234567,
    external: 1234567,
    arrayBuffers: 123456,
  })),
}));

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  mkdir: vi.fn(),
}));

const mockGetCliVersionFn = vi.fn(() => Promise.resolve('0.1.0'));
vi.mock('../../utils/version.js', () => ({
  getCliVersion: (...args: []) => mockGetCliVersionFn(...args),
}));

import { act, renderHook } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach, Mock } from 'vitest';
import open from 'open';
import {
  useSlashCommandProcessor,
  type SlashCommandActionReturn,
} from './slashCommandProcessor.js';
import { MessageType } from '../types.js';
import {
  Config,
  MCPDiscoveryState,
  MCPServerStatus,
  getMCPDiscoveryState,
  getMCPServerStatus,
  GeminiClient,
} from '@google/gemini-cli-core';
import { useSessionStats } from '../contexts/SessionContext.js';
import { LoadedSettings } from '../../config/settings.js';
import * as ShowMemoryCommandModule from './useShowMemoryCommand.js';
import { GIT_COMMIT_INFO } from '../../generated/git-commit.js';

vi.mock('../contexts/SessionContext.js', () => ({
  useSessionStats: vi.fn(),
}));

vi.mock('./useShowMemoryCommand.js', () => ({
  SHOW_MEMORY_COMMAND_NAME: '/memory show',
  createShowMemoryAction: vi.fn(() => vi.fn()),
}));

vi.mock('open', () => ({
  default: vi.fn(),
}));

describe('useSlashCommandProcessor', () => {
  let mockAddItem: ReturnType<typeof vi.fn>;
  let mockClearItems: ReturnType<typeof vi.fn>;
  let mockLoadHistory: ReturnType<typeof vi.fn>;
  let mockRefreshStatic: ReturnType<typeof vi.fn>;
  let mockSetShowHelp: ReturnType<typeof vi.fn>;
  let mockOnDebugMessage: ReturnType<typeof vi.fn>;
  let mockOpenThemeDialog: ReturnType<typeof vi.fn>;
  let mockOpenAuthDialog: ReturnType<typeof vi.fn>;
  let mockOpenEditorDialog: ReturnType<typeof vi.fn>;
  let mockPerformMemoryRefresh: ReturnType<typeof vi.fn>;
  let mockSetQuittingMessages: ReturnType<typeof vi.fn>;
  let mockTryCompressChat: ReturnType<typeof vi.fn>;
  let mockGeminiClient: GeminiClient;
  let mockConfig: Config;
  let mockCorgiMode: ReturnType<typeof vi.fn>;
  const mockUseSessionStats = useSessionStats as Mock;

  beforeEach(() => {
    mockAddItem = vi.fn();
    mockClearItems = vi.fn();
    mockLoadHistory = vi.fn();
    mockRefreshStatic = vi.fn();
    mockSetShowHelp = vi.fn();
    mockOnDebugMessage = vi.fn();
    mockOpenThemeDialog = vi.fn();
    mockOpenAuthDialog = vi.fn();
    mockOpenEditorDialog = vi.fn();
    mockPerformMemoryRefresh = vi.fn().mockResolvedValue(undefined);
    mockSetQuittingMessages = vi.fn();
    mockTryCompressChat = vi.fn();
    mockGeminiClient = {
      tryCompressChat: mockTryCompressChat,
    } as unknown as GeminiClient;
    mockConfig = {
      getDebugMode: vi.fn(() => false),
      getGeminiClient: () => mockGeminiClient,
      getSandbox: vi.fn(() => 'test-sandbox'),
      getModel: vi.fn(() => 'test-model'),
      getProjectRoot: vi.fn(() => '/test/dir'),
      getCheckpointingEnabled: vi.fn(() => true),
      getBugCommand: vi.fn(() => undefined),
    } as unknown as Config;
    mockCorgiMode = vi.fn();
    mockUseSessionStats.mockReturnValue({
      stats: {
        sessionStartTime: new Date('2025-01-01T00:00:00.000Z'),
        cumulative: {
          turnCount: 0,
          promptTokenCount: 0,
          candidatesTokenCount: 0,
          totalTokenCount: 0,
          cachedContentTokenCount: 0,
          toolUsePromptTokenCount: 0,
          thoughtsTokenCount: 0,
        },
      },
    });

    (open as Mock).mockClear();
    mockProcessExit.mockClear();
    (ShowMemoryCommandModule.createShowMemoryAction as Mock).mockClear();
    mockPerformMemoryRefresh.mockClear();
    process.env = { ...globalThis.process.env };
  });

  const getProcessorHook = (showToolDescriptions: boolean = false) => {
    const settings = {
      merged: {
        contextFileName: 'GEMINI.md',
      },
    } as LoadedSettings;
    return renderHook(() =>
      useSlashCommandProcessor(
        mockConfig,
        settings,
        [],
        mockAddItem,
        mockClearItems,
        mockLoadHistory,
        mockRefreshStatic,
        mockSetShowHelp,
        mockOnDebugMessage,
        mockOpenThemeDialog,
        mockOpenAuthDialog,
        mockOpenEditorDialog,
        mockPerformMemoryRefresh,
        mockCorgiMode,
        showToolDescriptions,
        mockSetQuittingMessages,
      ),
    );
  };

  const getProcessor = (showToolDescriptions: boolean = false) =>
    getProcessorHook(showToolDescriptions).result.current;

  describe('/memory add', () => {
    it('should return tool scheduling info on valid input', async () => {
      const { handleSlashCommand } = getProcessor();
      const fact = 'Remember this fact';
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand(`/memory add ${fact}`);
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        1, // User message
        expect.objectContaining({
          type: MessageType.USER,
          text: `/memory add ${fact}`,
        }),
        expect.any(Number),
      );
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Info message about attempting to save
        expect.objectContaining({
          type: MessageType.INFO,
          text: `Attempting to save to memory: "${fact}"`,
        }),
        expect.any(Number),
      );

      expect(commandResult).toEqual({
        shouldScheduleTool: true,
        toolName: 'save_memory',
        toolArgs: { fact },
      });

      // performMemoryRefresh is no longer called directly here
      expect(mockPerformMemoryRefresh).not.toHaveBeenCalled();
    });

    it('should show usage error and return true if no text is provided', async () => {
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/memory add ');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // After user message
        expect.objectContaining({
          type: MessageType.ERROR,
          text: 'Usage: /memory add <text to remember>',
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true); // Command was handled (by showing an error)
    });
  });

  describe('/memory show', () => {
    it('should call the showMemoryAction and return true', async () => {
      const mockReturnedShowAction = vi.fn();
      vi.mocked(ShowMemoryCommandModule.createShowMemoryAction).mockReturnValue(
        mockReturnedShowAction,
      );
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/memory show');
      });
      expect(
        ShowMemoryCommandModule.createShowMemoryAction,
      ).toHaveBeenCalledWith(
        mockConfig,
        expect.any(Object),
        expect.any(Function),
      );
      expect(mockReturnedShowAction).toHaveBeenCalled();
      expect(commandResult).toBe(true);
    });
  });

  describe('/memory refresh', () => {
    it('should call performMemoryRefresh and return true', async () => {
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/memory refresh');
      });
      expect(mockPerformMemoryRefresh).toHaveBeenCalled();
      expect(commandResult).toBe(true);
    });
  });

  describe('Unknown /memory subcommand', () => {
    it('should show an error for unknown /memory subcommand and return true', async () => {
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/memory foobar');
      });
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.ERROR,
          text: 'Unknown /memory command: foobar. Available: show, refresh, add',
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });
  });

  describe('/stats command', () => {
    it('should show detailed session statistics', async () => {
      // Arrange
      mockUseSessionStats.mockReturnValue({
        stats: {
          sessionStartTime: new Date('2025-01-01T00:00:00.000Z'),
        },
      });

      const { handleSlashCommand } = getProcessor();
      const mockDate = new Date('2025-01-01T01:02:03.000Z'); // 1h 2m 3s duration
      vi.setSystemTime(mockDate);

      // Act
      await act(async () => {
        handleSlashCommand('/stats');
      });

      // Assert
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Called after the user message
        expect.objectContaining({
          type: MessageType.STATS,
          duration: '1h 2m 3s',
        }),
        expect.any(Number),
      );

      vi.useRealTimers();
    });

    it('should show model-specific statistics when using /stats model', async () => {
      // Arrange
      const { handleSlashCommand } = getProcessor();

      // Act
      await act(async () => {
        handleSlashCommand('/stats model');
      });

      // Assert
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Called after the user message
        expect.objectContaining({
          type: MessageType.MODEL_STATS,
        }),
        expect.any(Number),
      );
    });

    it('should show tool-specific statistics when using /stats tools', async () => {
      // Arrange
      const { handleSlashCommand } = getProcessor();

      // Act
      await act(async () => {
        handleSlashCommand('/stats tools');
      });

      // Assert
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Called after the user message
        expect.objectContaining({
          type: MessageType.TOOL_STATS,
        }),
        expect.any(Number),
      );
    });
  });

  describe('/about command', () => {
    it('should show the about box with all details including auth and project', async () => {
      // Arrange
      mockGetCliVersionFn.mockResolvedValue('test-version');
      process.env.SANDBOX = 'gemini-sandbox';
      process.env.GOOGLE_CLOUD_PROJECT = 'test-gcp-project';
      vi.mocked(mockConfig.getModel).mockReturnValue('test-model-from-config');

      const settings = {
        merged: {
          selectedAuthType: 'test-auth-type',
          contextFileName: 'GEMINI.md',
        },
      } as LoadedSettings;

      const { result } = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          [],
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      // Act
      await act(async () => {
        await result.current.handleSlashCommand('/about');
      });

      // Assert
      expect(mockAddItem).toHaveBeenCalledTimes(2); // user message + about message
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: 'about',
          cliVersion: 'test-version',
          osVersion: 'test-platform',
          sandboxEnv: 'gemini-sandbox',
          modelVersion: 'test-model-from-config',
          selectedAuthType: 'test-auth-type',
          gcpProject: 'test-gcp-project',
        }),
        expect.any(Number),
      );
    });

    it('should show sandbox-exec profile when applicable', async () => {
      // Arrange
      mockGetCliVersionFn.mockResolvedValue('test-version');
      process.env.SANDBOX = 'sandbox-exec';
      process.env.SEATBELT_PROFILE = 'test-profile';
      vi.mocked(mockConfig.getModel).mockReturnValue('test-model-from-config');

      const { result } = getProcessorHook();

      // Act
      await act(async () => {
        await result.current.handleSlashCommand('/about');
      });

      // Assert
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          sandboxEnv: 'sandbox-exec (test-profile)',
        }),
        expect.any(Number),
      );
    });
  });

  describe('Other commands', () => {
    it('/help should open help and return true', async () => {
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/help');
      });
      expect(mockSetShowHelp).toHaveBeenCalledWith(true);
      expect(commandResult).toBe(true);
    });

    it('/clear should clear items, reset chat, and refresh static', async () => {
      const mockResetChat = vi.fn();
      mockConfig = {
        ...mockConfig,
        getGeminiClient: () => ({
          resetChat: mockResetChat,
        }),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/clear');
      });

      expect(mockClearItems).toHaveBeenCalled();
      expect(mockResetChat).toHaveBeenCalled();
      expect(mockRefreshStatic).toHaveBeenCalled();
      expect(commandResult).toBe(true);
    });

    it('/editor should open editor dialog and return true', async () => {
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/editor');
      });
      expect(mockOpenEditorDialog).toHaveBeenCalled();
      expect(commandResult).toBe(true);
    });
  });

  describe('/bug command', () => {
    const originalEnv = process.env;
    beforeEach(() => {
      vi.resetModules();
      mockGetCliVersionFn.mockResolvedValue('0.1.0');
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    const getExpectedUrl = (
      description?: string,
      sandboxEnvVar?: string,
      seatbeltProfileVar?: string,
      cliVersion?: string,
    ) => {
      const osVersion = 'test-platform test-node-version';
      let sandboxEnvStr = 'no sandbox';
      if (sandboxEnvVar && sandboxEnvVar !== 'sandbox-exec') {
        sandboxEnvStr = sandboxEnvVar.replace(/^gemini-(?:code-)?/, '');
      } else if (sandboxEnvVar === 'sandbox-exec') {
        sandboxEnvStr = `sandbox-exec (${seatbeltProfileVar || 'unknown'})`;
      }
      const modelVersion = 'test-model';
      // Use the mocked memoryUsage value
      const memoryUsage = '11.8 MB';

      const info = `
*   **CLI Version:** ${cliVersion}
*   **Git Commit:** ${GIT_COMMIT_INFO}
*   **Operating System:** ${osVersion}
*   **Sandbox Environment:** ${sandboxEnvStr}
*   **Model Version:** ${modelVersion}
*   **Memory Usage:** ${memoryUsage}
`;
      let url =
        'https://github.com/google-gemini/gemini-cli/issues/new?template=bug_report.yml';
      if (description) {
        url += `&title=${encodeURIComponent(description)}`;
      }
      url += `&info=${encodeURIComponent(info)}`;
      return url;
    };

    it('should call open with the correct GitHub issue URL and return true', async () => {
      mockGetCliVersionFn.mockResolvedValue('test-version');
      process.env.SANDBOX = 'gemini-sandbox';
      process.env.SEATBELT_PROFILE = 'test_profile';
      const { handleSlashCommand } = getProcessor();
      const bugDescription = 'This is a test bug';
      const expectedUrl = getExpectedUrl(
        bugDescription,
        process.env.SANDBOX,
        process.env.SEATBELT_PROFILE,
        'test-version',
      );
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand(`/bug ${bugDescription}`);
      });

      expect(mockAddItem).toHaveBeenCalledTimes(2);
      expect(open).toHaveBeenCalledWith(expectedUrl);
      expect(commandResult).toBe(true);
    });

    it('should use the custom bug command URL from config if available', async () => {
      process.env.CLI_VERSION = '0.1.0';
      process.env.SANDBOX = 'sandbox-exec';
      process.env.SEATBELT_PROFILE = 'permissive-open';
      const bugCommand = {
        urlTemplate:
          'https://custom-bug-tracker.com/new?title={title}&info={info}',
      };
      mockConfig = {
        ...mockConfig,
        getBugCommand: vi.fn(() => bugCommand),
      } as unknown as Config;
      process.env.CLI_VERSION = '0.1.0';

      const { handleSlashCommand } = getProcessor();
      const bugDescription = 'This is a custom bug';
      const info = `
*   **CLI Version:** 0.1.0
*   **Git Commit:** ${GIT_COMMIT_INFO}
*   **Operating System:** test-platform test-node-version
*   **Sandbox Environment:** sandbox-exec (permissive-open)
*   **Model Version:** test-model
*   **Memory Usage:** 11.8 MB
`;
      const expectedUrl = bugCommand.urlTemplate
        .replace('{title}', encodeURIComponent(bugDescription))
        .replace('{info}', encodeURIComponent(info));

      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand(`/bug ${bugDescription}`);
      });

      expect(mockAddItem).toHaveBeenCalledTimes(2);
      expect(open).toHaveBeenCalledWith(expectedUrl);
      expect(commandResult).toBe(true);
    });
  });

  describe('/quit and /exit commands', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it.each([['/quit'], ['/exit']])(
      'should handle %s, set quitting messages, and exit the process',
      async (command) => {
        const { handleSlashCommand } = getProcessor();
        const mockDate = new Date('2025-01-01T01:02:03.000Z');
        vi.setSystemTime(mockDate);

        await act(async () => {
          handleSlashCommand(command);
        });

        expect(mockAddItem).not.toHaveBeenCalled();
        expect(mockSetQuittingMessages).toHaveBeenCalledWith([
          {
            type: 'user',
            text: command,
            id: expect.any(Number),
          },
          {
            type: 'quit',
            duration: '1h 2m 3s',
            id: expect.any(Number),
          },
        ]);

        // Fast-forward timers to trigger process.exit
        await act(async () => {
          vi.advanceTimersByTime(100);
        });
        expect(mockProcessExit).toHaveBeenCalledWith(0);
      },
    );
  });

  describe('Unknown command', () => {
    it('should show an error and return true for a general unknown command', async () => {
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/unknowncommand');
      });
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.ERROR,
          text: 'Unknown command: /unknowncommand',
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });
  });

  describe('/tools command', () => {
    it('should show an error if tool registry is not available', async () => {
      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue(undefined),
      } as unknown as Config;
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/tools');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.ERROR,
          text: 'Could not retrieve tools.',
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });

    it('should show an error if getAllTools returns undefined', async () => {
      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getAllTools: vi.fn().mockReturnValue(undefined),
        }),
      } as unknown as Config;
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/tools');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.ERROR,
          text: 'Could not retrieve tools.',
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });

    it('should display only Gemini CLI tools (filtering out MCP tools)', async () => {
      // Create mock tools - some with serverName property (MCP tools) and some without (Gemini CLI tools)
      const mockTools = [
        { name: 'tool1', displayName: 'Tool1' },
        { name: 'tool2', displayName: 'Tool2' },
        { name: 'mcp_tool1', serverName: 'mcp-server1' },
        { name: 'mcp_tool2', serverName: 'mcp-server1' },
      ];

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getAllTools: vi.fn().mockReturnValue(mockTools),
        }),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/tools');
      });

      // Should only show tool1 and tool2, not the MCP tools
      const message = mockAddItem.mock.calls[1][0].text;
      expect(message).toContain('Tool1');
      expect(message).toContain('Tool2');
      expect(commandResult).toBe(true);
    });

    it('should display a message when no Gemini CLI tools are available', async () => {
      // Only MCP tools available
      const mockTools = [
        { name: 'mcp_tool1', serverName: 'mcp-server1' },
        { name: 'mcp_tool2', serverName: 'mcp-server1' },
      ];

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getAllTools: vi.fn().mockReturnValue(mockTools),
        }),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/tools');
      });

      const message = mockAddItem.mock.calls[1][0].text;
      expect(message).toContain('No tools available');
      expect(commandResult).toBe(true);
    });

    it('should display tool descriptions when /tools desc is used', async () => {
      const mockTools = [
        {
          name: 'tool1',
          displayName: 'Tool1',
          description: 'Description for Tool1',
        },
        {
          name: 'tool2',
          displayName: 'Tool2',
          description: 'Description for Tool2',
        },
      ];

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getAllTools: vi.fn().mockReturnValue(mockTools),
        }),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/tools desc');
      });

      const message = mockAddItem.mock.calls[1][0].text;
      expect(message).toContain('Tool1');
      expect(message).toContain('Description for Tool1');
      expect(message).toContain('Tool2');
      expect(message).toContain('Description for Tool2');
      expect(commandResult).toBe(true);
    });
  });

  describe('/mcp command', () => {
    beforeEach(() => {
      // Mock the core module with getMCPServerStatus and getMCPDiscoveryState
      vi.mock('@google/gemini-cli-core', async (importOriginal) => {
        const actual = await importOriginal();
        return {
          ...actual,
          MCPServerStatus: {
            CONNECTED: 'connected',
            CONNECTING: 'connecting',
            DISCONNECTED: 'disconnected',
          },
          MCPDiscoveryState: {
            NOT_STARTED: 'not_started',
            IN_PROGRESS: 'in_progress',
            COMPLETED: 'completed',
          },
          getMCPServerStatus: vi.fn(),
          getMCPDiscoveryState: vi.fn(),
        };
      });
    });

    it('should show an error if tool registry is not available', async () => {
      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue(undefined),
      } as unknown as Config;
      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.ERROR,
          text: 'Could not retrieve tool registry.',
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });

    it('should display a message with a URL when no MCP servers are configured in a sandbox', async () => {
      process.env.SANDBOX = 'sandbox';
      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: vi.fn().mockReturnValue([]),
        }),
        getMcpServers: vi.fn().mockReturnValue({}),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.INFO,
          text: `No MCP servers configured. Please open the following URL in your browser to view documentation:\nhttps://goo.gle/gemini-cli-docs-mcp`,
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
      delete process.env.SANDBOX;
    });

    it('should display a message and open a URL when no MCP servers are configured outside a sandbox', async () => {
      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: vi.fn().mockReturnValue([]),
        }),
        getMcpServers: vi.fn().mockReturnValue({}),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.INFO,
          text: 'No MCP servers configured. Opening documentation in your browser: https://goo.gle/gemini-cli-docs-mcp',
        }),
        expect.any(Number),
      );
      expect(open).toHaveBeenCalledWith('https://goo.gle/gemini-cli-docs-mcp');
      expect(commandResult).toBe(true);
    });

    it('should display configured MCP servers with status indicators and their tools', async () => {
      // Mock MCP servers configuration
      const mockMcpServers = {
        server1: { command: 'cmd1' },
        server2: { command: 'cmd2' },
        server3: { command: 'cmd3' },
      };

      // Setup getMCPServerStatus mock implementation - use all CONNECTED to avoid startup message in this test
      vi.mocked(getMCPServerStatus).mockImplementation((serverName) => {
        if (serverName === 'server1') return MCPServerStatus.CONNECTED;
        if (serverName === 'server2') return MCPServerStatus.CONNECTED;
        return MCPServerStatus.DISCONNECTED; // Default for server3 and others
      });

      // Setup getMCPDiscoveryState mock to return completed so no startup message is shown
      vi.mocked(getMCPDiscoveryState).mockReturnValue(
        MCPDiscoveryState.COMPLETED,
      );

      // Mock tools from each server
      const mockServer1Tools = [
        { name: 'server1_tool1' },
        { name: 'server1_tool2' },
      ];

      const mockServer2Tools = [{ name: 'server2_tool1' }];

      const mockServer3Tools = [{ name: 'server3_tool1' }];

      const mockGetToolsByServer = vi.fn().mockImplementation((serverName) => {
        if (serverName === 'server1') return mockServer1Tools;
        if (serverName === 'server2') return mockServer2Tools;
        if (serverName === 'server3') return mockServer3Tools;
        return [];
      });

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: mockGetToolsByServer,
        }),
        getMcpServers: vi.fn().mockReturnValue(mockMcpServers),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.INFO,
          text: expect.stringContaining('Configured MCP servers:'),
        }),
        expect.any(Number),
      );

      // Check that the message contains details about servers and their tools
      const message = mockAddItem.mock.calls[1][0].text;
      // Server 1 - Connected
      expect(message).toContain(
        '🟢 \u001b[1mserver1\u001b[0m - Ready (2 tools)',
      );
      expect(message).toContain('\u001b[36mserver1_tool1\u001b[0m');
      expect(message).toContain('\u001b[36mserver1_tool2\u001b[0m');

      // Server 2 - Connected
      expect(message).toContain(
        '🟢 \u001b[1mserver2\u001b[0m - Ready (1 tools)',
      );
      expect(message).toContain('\u001b[36mserver2_tool1\u001b[0m');

      // Server 3 - Disconnected
      expect(message).toContain(
        '🔴 \u001b[1mserver3\u001b[0m - Disconnected (1 tools cached)',
      );
      expect(message).toContain('\u001b[36mserver3_tool1\u001b[0m');

      expect(commandResult).toBe(true);
    });

    it('should display tool descriptions when showToolDescriptions is true', async () => {
      // Mock MCP servers configuration with server description
      const mockMcpServers = {
        server1: {
          command: 'cmd1',
          description: 'This is a server description',
        },
      };

      // Setup getMCPServerStatus mock implementation
      vi.mocked(getMCPServerStatus).mockImplementation((serverName) => {
        if (serverName === 'server1') return MCPServerStatus.CONNECTED;
        return MCPServerStatus.DISCONNECTED;
      });

      // Setup getMCPDiscoveryState mock to return completed
      vi.mocked(getMCPDiscoveryState).mockReturnValue(
        MCPDiscoveryState.COMPLETED,
      );

      // Mock tools from server with descriptions
      const mockServerTools = [
        { name: 'tool1', description: 'This is tool 1 description' },
        { name: 'tool2', description: 'This is tool 2 description' },
      ];

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: vi.fn().mockReturnValue(mockServerTools),
        }),
        getMcpServers: vi.fn().mockReturnValue(mockMcpServers),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor(true);
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.INFO,
          text: expect.stringContaining('Configured MCP servers:'),
        }),
        expect.any(Number),
      );

      const message = mockAddItem.mock.calls[1][0].text;

      // Check that server description is included (with ANSI color codes)
      expect(message).toContain('\u001b[1mserver1\u001b[0m - Ready (2 tools)');
      expect(message).toContain(
        '\u001b[32mThis is a server description\u001b[0m',
      );

      // Check that tool descriptions are included (with ANSI color codes)
      expect(message).toContain('\u001b[36mtool1\u001b[0m');
      expect(message).toContain(
        '\u001b[32mThis is tool 1 description\u001b[0m',
      );
      expect(message).toContain('\u001b[36mtool2\u001b[0m');
      expect(message).toContain(
        '\u001b[32mThis is tool 2 description\u001b[0m',
      );

      expect(commandResult).toBe(true);
    });

    it('should indicate when a server has no tools', async () => {
      // Mock MCP servers configuration
      const mockMcpServers = {
        server1: { command: 'cmd1' },
        server2: { command: 'cmd2' },
      };

      // Setup getMCPServerStatus mock implementation
      vi.mocked(getMCPServerStatus).mockImplementation((serverName) => {
        if (serverName === 'server1') return MCPServerStatus.CONNECTED;
        if (serverName === 'server2') return MCPServerStatus.DISCONNECTED;
        return MCPServerStatus.DISCONNECTED;
      });

      // Setup getMCPDiscoveryState mock to return completed
      vi.mocked(getMCPDiscoveryState).mockReturnValue(
        MCPDiscoveryState.COMPLETED,
      );

      // Mock tools from each server - server2 has no tools
      const mockServer1Tools = [{ name: 'server1_tool1' }];

      const mockServer2Tools = [];

      const mockGetToolsByServer = vi.fn().mockImplementation((serverName) => {
        if (serverName === 'server1') return mockServer1Tools;
        if (serverName === 'server2') return mockServer2Tools;
        return [];
      });

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: mockGetToolsByServer,
        }),
        getMcpServers: vi.fn().mockReturnValue(mockMcpServers),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.INFO,
          text: expect.stringContaining('Configured MCP servers:'),
        }),
        expect.any(Number),
      );

      // Check that the message contains details about both servers and their tools
      const message = mockAddItem.mock.calls[1][0].text;
      expect(message).toContain(
        '🟢 \u001b[1mserver1\u001b[0m - Ready (1 tools)',
      );
      expect(message).toContain('\u001b[36mserver1_tool1\u001b[0m');
      expect(message).toContain(
        '🔴 \u001b[1mserver2\u001b[0m - Disconnected (0 tools cached)',
      );
      expect(message).toContain('No tools available');

      expect(commandResult).toBe(true);
    });

    it('should show startup indicator when servers are connecting', async () => {
      // Mock MCP servers configuration
      const mockMcpServers = {
        server1: { command: 'cmd1' },
        server2: { command: 'cmd2' },
      };

      // Setup getMCPServerStatus mock implementation with one server connecting
      vi.mocked(getMCPServerStatus).mockImplementation((serverName) => {
        if (serverName === 'server1') return MCPServerStatus.CONNECTED;
        if (serverName === 'server2') return MCPServerStatus.CONNECTING;
        return MCPServerStatus.DISCONNECTED;
      });

      // Setup getMCPDiscoveryState mock to return in progress
      vi.mocked(getMCPDiscoveryState).mockReturnValue(
        MCPDiscoveryState.IN_PROGRESS,
      );

      // Mock tools from each server
      const mockServer1Tools = [{ name: 'server1_tool1' }];
      const mockServer2Tools = [{ name: 'server2_tool1' }];

      const mockGetToolsByServer = vi.fn().mockImplementation((serverName) => {
        if (serverName === 'server1') return mockServer1Tools;
        if (serverName === 'server2') return mockServer2Tools;
        return [];
      });

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: mockGetToolsByServer,
        }),
        getMcpServers: vi.fn().mockReturnValue(mockMcpServers),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor();
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp');
      });

      const message = mockAddItem.mock.calls[1][0].text;

      // Check that startup indicator is shown
      expect(message).toContain(
        '⏳ MCP servers are starting up (1 initializing)...',
      );
      expect(message).toContain(
        'Note: First startup may take longer. Tool availability will update automatically.',
      );

      // Check server statuses
      expect(message).toContain(
        '🟢 \u001b[1mserver1\u001b[0m - Ready (1 tools)',
      );
      expect(message).toContain(
        '🔄 \u001b[1mserver2\u001b[0m - Starting... (first startup may take longer) (tools will appear when ready)',
      );

      expect(commandResult).toBe(true);
    });
  });

  describe('/mcp schema', () => {
    it('should display tool schemas and descriptions', async () => {
      // Mock MCP servers configuration with server description
      const mockMcpServers = {
        server1: {
          command: 'cmd1',
          description: 'This is a server description',
        },
      };

      // Setup getMCPServerStatus mock implementation
      vi.mocked(getMCPServerStatus).mockImplementation((serverName) => {
        if (serverName === 'server1') return MCPServerStatus.CONNECTED;
        return MCPServerStatus.DISCONNECTED;
      });

      // Setup getMCPDiscoveryState mock to return completed
      vi.mocked(getMCPDiscoveryState).mockReturnValue(
        MCPDiscoveryState.COMPLETED,
      );

      // Mock tools from server with descriptions
      const mockServerTools = [
        {
          name: 'tool1',
          description: 'This is tool 1 description',
          schema: {
            parameters: [{ name: 'param1', type: 'string' }],
          },
        },
        {
          name: 'tool2',
          description: 'This is tool 2 description',
          schema: {
            parameters: [{ name: 'param2', type: 'number' }],
          },
        },
      ];

      mockConfig = {
        ...mockConfig,
        getToolRegistry: vi.fn().mockResolvedValue({
          getToolsByServer: vi.fn().mockReturnValue(mockServerTools),
        }),
        getMcpServers: vi.fn().mockReturnValue(mockMcpServers),
      } as unknown as Config;

      const { handleSlashCommand } = getProcessor(true);
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await handleSlashCommand('/mcp schema');
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.INFO,
          text: expect.stringContaining('Configured MCP servers:'),
        }),
        expect.any(Number),
      );

      const message = mockAddItem.mock.calls[1][0].text;

      // Check that server description is included
      expect(message).toContain('Ready (2 tools)');
      expect(message).toContain('This is a server description');

      // Check that tool schemas are included
      expect(message).toContain('tool 1 description');
      expect(message).toContain('param1');
      expect(message).toContain('string');
      expect(message).toContain('tool 2 description');
      expect(message).toContain('param2');
      expect(message).toContain('number');

      expect(commandResult).toBe(true);
    });
  });

  describe('/compress command', () => {
    it('should call tryCompressChat(true)', async () => {
      const hook = getProcessorHook();
      mockTryCompressChat.mockImplementationOnce(async (force?: boolean) => {
        expect(force).toBe(true);
        await act(async () => {
          hook.rerender();
        });
        expect(hook.result.current.pendingHistoryItems).toContainEqual({
          type: MessageType.COMPRESSION,
          compression: {
            isPending: true,
            originalTokenCount: null,
            newTokenCount: null,
          },
        });
        return {
          originalTokenCount: 100,
          newTokenCount: 50,
        };
      });

      await act(async () => {
        hook.result.current.handleSlashCommand('/compress');
      });
      await act(async () => {
        hook.rerender();
      });
      expect(hook.result.current.pendingHistoryItems).toEqual([]);
      expect(mockGeminiClient.tryCompressChat).toHaveBeenCalledWith(true);
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          type: MessageType.COMPRESSION,
          compression: {
            isPending: false,
            originalTokenCount: 100,
            newTokenCount: 50,
          },
        }),
        expect.any(Number),
      );
    });
  });

  describe('/export command', () => {
    let mockWriteFile: Mock;
    let mockMkdir: Mock;
    let mockReadFile: Mock;

    beforeEach(async () => {
      const fs = await import('node:fs/promises');
      mockWriteFile = fs.writeFile as Mock;
      mockMkdir = fs.mkdir as Mock;
      mockReadFile = fs.readFile as Mock;

      mockWriteFile.mockResolvedValue(undefined);
      mockMkdir.mockResolvedValue(undefined);
      mockReadFile.mockResolvedValue('test content');

      // Set up environment for sandbox detection
      delete process.env.SANDBOX;
      delete process.env.SEATBELT_PROFILE;
      delete process.env.GOOGLE_CLOUD_PROJECT;

      // Mock additional config methods needed for export
      mockConfig = {
        ...mockConfig,
        getSessionId: vi.fn(() => 'test-session-123'),
        getGeminiClient: vi.fn(() => ({
          getChat: vi.fn(() => ({
            getHistory: vi.fn().mockResolvedValue([
              { role: 'user', parts: [{ text: 'test user input' }] },
              { role: 'model', parts: [{ text: 'test ai response' }] },
            ]),
          })),
        })),
      } as unknown as Config;

      // Mock session stats with more comprehensive data
      mockUseSessionStats.mockReturnValue({
        stats: {
          sessionStartTime: new Date('2025-01-01T00:00:00.000Z'),
          cumulative: {
            turnCount: 5,
            promptTokenCount: 1000,
            candidatesTokenCount: 800,
            totalTokenCount: 1800,
            cachedContentTokenCount: 200,
            toolUsePromptTokenCount: 150,
            thoughtsTokenCount: 50,
            apiTimeMs: 5000,
          },
          currentTurn: {
            promptTokenCount: 100,
            candidatesTokenCount: 80,
          },
        },
      });
    });

    it('should export conversation with default filename when no args provided', async () => {
      const { handleSlashCommand: _handleSlashCommand } = getProcessor();
      const mockHistory = [
        { id: 1, type: 'user', text: 'Hello', timestamp: new Date() },
        { id: 2, type: 'gemini', text: 'Hi there!', timestamp: new Date() },
      ];

      // Create hook with mock history
      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'api_key',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await hook.result.current.handleSlashCommand('/export');
      });

      expect(mockWriteFile).toHaveBeenCalledWith(
        expect.stringMatching(
          /gemini-conversation-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.md$/,
        ),
        expect.stringContaining('# Gemini CLI Conversation Export'),
        'utf-8',
      );
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Second call should be the success message
        expect.objectContaining({
          type: MessageType.INFO,
          text: expect.stringContaining('Conversation exported successfully!'),
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });

    it('should export conversation with custom filename', async () => {
      const { handleSlashCommand: _handleSlashCommand } = getProcessor();
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test message', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'google_login',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await hook.result.current.handleSlashCommand(
          '/export my-conversation.md',
        );
      });

      expect(mockWriteFile).toHaveBeenCalledWith(
        expect.stringMatching(/my-conversation\.md$/),
        expect.stringContaining('# Gemini CLI Conversation Export'),
        'utf-8',
      );
      expect(commandResult).toBe(true);
    });

    it('should handle different sandbox environments correctly', async () => {
      // Test Docker sandbox
      process.env.SANDBOX = 'docker';
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'api_key',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      let _commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        _commandResult =
          await hook.result.current.handleSlashCommand('/export test.md');
      });

      expect(mockWriteFile).toHaveBeenCalledWith(
        expect.anything(),
        expect.stringContaining('| **Sandbox Environment** | docker |'),
        'utf-8',
      );

      // Test sandbox-exec
      process.env.SANDBOX = 'sandbox-exec';
      process.env.SEATBELT_PROFILE = 'restrictive';

      await act(async () => {
        _commandResult =
          await hook.result.current.handleSlashCommand('/export test2.md');
      });

      expect(mockWriteFile).toHaveBeenCalledWith(
        expect.anything(),
        expect.stringContaining(
          '| **Sandbox Environment** | sandbox-exec (restrictive) |',
        ),
        'utf-8',
      );
    });

    it('should include session statistics in export', async () => {
      const { handleSlashCommand: _handleSlashCommand } = getProcessor();
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'vertex_ai',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      await act(async () => {
        await hook.result.current.handleSlashCommand('/export stats-test.md');
      });

      const exportContent = mockWriteFile.mock.calls[0][1];
      expect(exportContent).toContain('## 📊 Session Statistics');
      expect(exportContent).toContain('| **Total Turns** | 5 |');
      expect(exportContent).toContain('| **Total Tokens** | 1,800 |');
      expect(exportContent).toContain('| **Prompt Tokens** | 1,000 |');
      expect(exportContent).toContain('| **Response Tokens** | 800 |');
      expect(exportContent).toContain('| **Total API Time** | 5,000 ms |');
    });

    it('should handle core history retrieval failure gracefully', async () => {
      // Mock getGeminiClient to throw an error
      mockConfig = {
        ...mockConfig,
        getGeminiClient: vi.fn(() => ({
          getChat: vi.fn(() => {
            throw new Error('Core history unavailable');
          }),
        })),
      } as unknown as Config;

      const { handleSlashCommand: _handleSlashCommand } = getProcessor();
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'api_key',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      // Should not throw error and still export successfully
      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await hook.result.current.handleSlashCommand(
          '/export error-test.md',
        );
      });

      expect(commandResult).toBe(true);
      expect(mockWriteFile).toHaveBeenCalled();
      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Second call should be the success message
        expect.objectContaining({
          type: MessageType.INFO,
          text: expect.stringContaining('Conversation exported successfully!'),
        }),
        expect.any(Number),
      );
    });

    it('should handle file write errors gracefully', async () => {
      mockWriteFile.mockRejectedValue(new Error('Permission denied'));

      const { handleSlashCommand: _handleSlashCommand } = getProcessor();
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'api_key',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      let commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        commandResult = await hook.result.current.handleSlashCommand(
          '/export fail-test.md',
        );
      });

      expect(mockAddItem).toHaveBeenNthCalledWith(
        2, // Second call should be the error message
        expect.objectContaining({
          type: MessageType.ERROR,
          text: expect.stringContaining(
            '❌ Failed to export conversation: Permission denied',
          ),
        }),
        expect.any(Number),
      );
      expect(commandResult).toBe(true);
    });

    it('should generate valid markdown export with correct filename', async () => {
      const { handleSlashCommand } = getProcessor();

      let _commandResult: SlashCommandActionReturn | boolean = false;
      await act(async () => {
        _commandResult = await handleSlashCommand('/export test-export.md');
      });

      // Verify file was written with correct filename
      expect(mockWriteFile).toHaveBeenCalledWith(
        expect.stringMatching(/test-export\.md$/),
        expect.any(String),
        'utf-8',
      );

      // Verify the exported content has required structural elements
      const exportContent = mockWriteFile.mock.calls[0][1];
      expect(exportContent).toContain('**Export Time**');
      expect(exportContent).toContain('# Gemini CLI Conversation Export');
      expect(exportContent).toContain('Generated by Gemini CLI');
    });

    it('should block path traversal attempts with clear error message', async () => {
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'api_key',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      // Test various path traversal attempts
      const pathTraversalAttempts = [
        '../../malicious.md',
        '../../../etc/passwd',
        '/tmp/malicious.md',
        '../outside.md',
      ];

      for (const maliciousPath of pathTraversalAttempts) {
        mockWriteFile.mockClear();
        mockAddItem.mockClear();

        let commandResult: SlashCommandActionReturn | boolean = false;
        await act(async () => {
          commandResult = await hook.result.current.handleSlashCommand(
            `/export ${maliciousPath}`,
          );
        });

        // Should not write file
        expect(mockWriteFile).not.toHaveBeenCalled();

        // Should show security error (look for the second call after user message)
        expect(mockAddItem).toHaveBeenNthCalledWith(
          2,
          expect.objectContaining({
            type: MessageType.ERROR,
            text: expect.stringContaining(
              'Security error: Cannot write outside current working directory',
            ),
          }),
          expect.any(Number),
        );

        expect(commandResult).toBe(true);
      }
    });

    it('should allow legitimate subdirectory exports', async () => {
      const { handleSlashCommand: _handleSlashCommand } = getProcessor();
      const mockHistory = [
        { id: 1, type: 'user', text: 'Test', timestamp: new Date() },
      ];

      const settings = {
        merged: {
          contextFileName: 'GEMINI.md',
          selectedAuthType: 'api_key',
        },
      } as LoadedSettings;

      const hook = renderHook(() =>
        useSlashCommandProcessor(
          mockConfig,
          settings,
          mockHistory,
          mockAddItem,
          mockClearItems,
          mockLoadHistory,
          mockRefreshStatic,
          mockSetShowHelp,
          mockOnDebugMessage,
          mockOpenThemeDialog,
          mockOpenAuthDialog,
          mockOpenEditorDialog,
          mockPerformMemoryRefresh,
          mockCorgiMode,
          false,
          mockSetQuittingMessages,
        ),
      );

      // Test legitimate subdirectory paths
      const legitimatePaths = [
        'exports/session.md',
        'logs/conversation.md',
        'data/export-2025.md',
        'local-export.md',
      ];

      for (const legitimatePath of legitimatePaths) {
        let commandResult: SlashCommandActionReturn | boolean = false;
        await act(async () => {
          commandResult = await hook.result.current.handleSlashCommand(
            `/export ${legitimatePath}`,
          );
        });

        // Should create directory and write file
        expect(mockMkdir).toHaveBeenCalledWith(expect.any(String), {
          recursive: true,
        });
        expect(mockWriteFile).toHaveBeenCalledWith(
          expect.stringContaining(legitimatePath),
          expect.stringContaining('# Gemini CLI Conversation Export'),
          'utf-8',
        );

        // Should show success message
        expect(mockAddItem).toHaveBeenNthCalledWith(
          2, // After user message
          expect.objectContaining({
            type: MessageType.INFO,
            text: expect.stringContaining(
              'Conversation exported successfully!',
            ),
          }),
          expect.any(Number),
        );

        expect(commandResult).toBe(true);

        // Clear mocks for next iteration
        mockWriteFile.mockClear();
        mockMkdir.mockClear();
        mockAddItem.mockClear();
      }
    });
  });
});
