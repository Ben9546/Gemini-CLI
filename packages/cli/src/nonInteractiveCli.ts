/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  Config,
  ToolCallRequestInfo,
  executeToolCall,
  ToolRegistry,
  shutdownTelemetry,
  isTelemetrySdkInitialized,
} from '@google/gemini-cli-core';
import {
  Content,
  Part,
  FunctionCall,
  GenerateContentResponse,
  PartListUnion,
} from '@google/genai';

import { parseAndFormatApiError } from './ui/utils/errorParsing.js';
// ===== NEW IMPORT =====
import { isAtCommand } from './ui/utils/commandUtils.js';
import { handleAtCommand } from './ui/hooks/atCommandProcessor.js';
// ======================

function getResponseText(response: GenerateContentResponse): string | null {
  if (response.candidates && response.candidates.length > 0) {
    const candidate = response.candidates[0];
    if (
      candidate.content &&
      candidate.content.parts &&
      candidate.content.parts.length > 0
    ) {
      // We are running in headless mode so we don't need to return thoughts to STDOUT.
      const thoughtPart = candidate.content.parts[0];
      if (thoughtPart?.thought) {
        return null;
      }
      return candidate.content.parts
        .filter((part) => part.text)
        .map((part) => part.text)
        .join('');
    }
  }
  return null;
}

export async function runNonInteractive(
  config: Config,
  input: string,
): Promise<void> {
  // Handle EPIPE errors when the output is piped to a command that closes early.
  process.stdout.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EPIPE') {
      // Exit gracefully if the pipe is closed.
      process.exit(0);
    }
  });

  const geminiClient = config.getGeminiClient();
  const toolRegistry: ToolRegistry = await config.getToolRegistry();

  const chat = await geminiClient.getChat();
  const abortController = new AbortController();

  // ===== NEW LOGIC TO HANDLE @ COMMANDS =====
  let queryToSend: PartListUnion | null = input;
  if (isAtCommand(input)) {
    console.log('[AGENT_LOOP] @-command detected. Processing file content...');
    const atResult = await handleAtCommand({
      query: input,
      config,
      // addItem and onDebugMessage are stubs for non-interactive mode
      addItem: () => 0, // FIX: Return a number to satisfy the type.
      onDebugMessage: (msg) => console.log(`[DEBUG] [AtCommand] ${msg}`),
      messageId: Date.now(),
      signal: abortController.signal,
    });
    if (!atResult.shouldProceed) {
      console.log('[AGENT_LOOP] @-command processing finished. Exiting.');
      return;
    }
    queryToSend = atResult.processedQuery;
  }

  if (!queryToSend) {
    console.error('[AGENT_LOOP] Error: Query became null after processing.');
    process.exit(1);
  }
  // ==========================================

  // FIX: Correctly handle all PartListUnion types to create a valid Part[]
  let parts: Part[];
  if (Array.isArray(queryToSend)) {
    // It's (string | Part)[]. We need to convert strings to TextParts.
    parts = queryToSend.map((p) => (typeof p === 'string' ? { text: p } : p));
  } else if (typeof queryToSend === 'string') {
    // It's a single string.
    parts = [{ text: queryToSend }];
  } else {
    // It's a single Part object.
    parts = [queryToSend];
  }
  let currentMessages: Content[] = [{ role: 'user', parts }];

  try {
    while (true) {
      const lastMessage = currentMessages?.[0]?.parts?.[0];
      if (lastMessage) {
        if ('text' in lastMessage && lastMessage.text) {
          console.log(
            `[AGENT_LOOP] Starting new turn. Last message was: TEXT - "${lastMessage.text.substring(0, 150)}..."`,
          );
        } else if (
          'functionResponse' in lastMessage &&
          lastMessage.functionResponse
        ) {
          console.log(
            `[AGENT_LOOP] Starting new turn. Last message was: TOOL_RESPONSE for ${lastMessage.functionResponse.name}`,
          );
        } else {
          console.log(
            `[AGENT_LOOP] Starting new turn. Last message was: ${JSON.stringify(lastMessage).substring(0, 150)}`,
          );
        }
      } else {
        console.log(
          `[AGENT_LOOP] Starting new turn. No previous message content to log.`,
        );
      }

      const functionCalls: FunctionCall[] = [];

      console.log('[AGENT_LOOP] Sending API request and awaiting stream...');

      const responseStream = await chat.sendMessageStream({
        message: currentMessages[0]?.parts || [], // Ensure parts are always provided
        config: {
          abortSignal: abortController.signal,
          tools: [
            { functionDeclarations: toolRegistry.getFunctionDeclarations() },
          ],
        },
      });

      let streamConnected = false;

      for await (const resp of responseStream) {
        if (!streamConnected) {
          console.log(
            '[AGENT_LOOP] Stream connected. Receiving response chunks.',
          );
          streamConnected = true;
        }

        const rawResponseChunk = JSON.stringify(resp);
        console.log(`[AGENT_LOOP_RAW_RESPONSE] Received chunk. Size: ${rawResponseChunk.length} chars.`);
        const maxLineLength = 500;
        for (let i = 0; i < rawResponseChunk.length; i += maxLineLength) {
            console.log(`[AGENT_LOOP_RAW_RESPONSE_CHUNK] ${rawResponseChunk.substring(i, i + maxLineLength)}`);
        }

        if (abortController.signal.aborted) {
          console.error('Operation cancelled.');
          return;
        }

        const textPartForLog = getResponseText(resp);
        const functionCallsForLog = resp.functionCalls;
        const thoughtPartForLog = resp.candidates?.[0]?.content?.parts?.[0];

        if (thoughtPartForLog?.thought) {
          console.log(
            `[AGENT_LOOP] Model Response: THOUGHT - "${thoughtPartForLog.text?.substring(0, 150)}..."`,
          );
        } else if (textPartForLog) {
          console.log(`[AGENT_LOOP] Model Response: TEXT - "${textPartForLog}"`);
        } else if (functionCallsForLog && functionCallsForLog.length > 0) {
          const callNames = functionCallsForLog.map((fc) => fc.name).join(', ');
          console.log(
            `[AGENT_LOOP] Model Response: TOOL_CALL(S) - ${callNames}`,
          );
        } else {
          console.log(
            `[AGENT_LOOP] Model Response: Received a chunk with no text or tool calls.`,
          );
        }

        const textPart = getResponseText(resp);
        if (textPart) {
          process.stdout.write(textPart);
        }
        if (resp.functionCalls) {
          functionCalls.push(...resp.functionCalls);
        }
      }

      if (functionCalls.length > 0) {
        const toolResponseParts: Part[] = [];

        for (const fc of functionCalls) {
          const callId = fc.id ?? `${fc.name}-${Date.now()}`;
          const requestInfo: ToolCallRequestInfo = {
            callId,
            name: fc.name as string,
            args: (fc.args ?? {}) as Record<string, unknown>,
            isClientInitiated: false,
          };

          const toolResponse = await executeToolCall(
            config,
            requestInfo,
            toolRegistry,
            abortController.signal,
          );

          if (toolResponse.error) {
            const isToolNotFound = toolResponse.error.message.includes(
              'not found in registry',
            );
            console.error(
              `Error executing tool ${fc.name}: ${toolResponse.resultDisplay || toolResponse.error.message}`,
            );
            if (!isToolNotFound) {
              process.exit(1);
            }
          }

          if (toolResponse.responseParts) {
            const parts = Array.isArray(toolResponse.responseParts)
              ? toolResponse.responseParts
              : [toolResponse.responseParts];
            for (const part of parts) {
              if (typeof part === 'string') {
                toolResponseParts.push({ text: part });
              } else if (part) {
                toolResponseParts.push(part);
              }
            }
          }
        }
        currentMessages = [{ role: 'user', parts: toolResponseParts }];
      } else {
        process.stdout.write('\n'); // Ensure a final newline
        return;
      }
    }
  } catch (error) {
    console.error(
      parseAndFormatApiError(
        error,
        config.getContentGeneratorConfig().authType,
      ),
    );
    process.exit(1);
  } finally {
    if (isTelemetrySdkInitialized()) {
      await shutdownTelemetry();
    }
  }
}
