/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  CountTokensResponse,
  GenerateContentResponse,
  GenerateContentParameters,
  CountTokensParameters,
  EmbedContentResponse,
  EmbedContentParameters,
} from '@google/genai';
import { ContentGenerator, ContentGeneratorConfig } from './contentGenerator.js';

export class PortkeyContentGenerator implements ContentGenerator {
  private readonly apiKey: string;
  private readonly model: string;
  private readonly vertexAccessToken?: string;
  private readonly vertexProjectId?: string;
  private readonly vertexRegion?: string;
  private readonly baseUrl: string;

  constructor(config: ContentGeneratorConfig) {
    if (!config.portkey?.apiKey) {
      throw new Error('Portkey API key is required');
    }
    
    this.apiKey = config.portkey.apiKey;
    this.model = config.model;
    this.vertexAccessToken = config.portkey.vertexAccessToken;
    this.vertexProjectId = config.portkey.vertexProjectId;
    this.vertexRegion = config.portkey.vertexRegion;
    this.baseUrl = config.portkey.baseUrl || 'https://api.portkey.ai/v1';
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'x-portkey-api-key': this.apiKey,
      'x-portkey-provider': 'vertex-ai',
    };

    // Your gateway uses x-portkey-virtual-key instead of Authorization
    if (this.vertexAccessToken) {
      headers['x-portkey-virtual-key'] = this.vertexAccessToken;
    }

    if (this.vertexProjectId) {
      headers['x-portkey-vertex-project-id'] = this.vertexProjectId;
    }

    if (this.vertexRegion) {
      headers['x-portkey-vertex-region'] = this.vertexRegion;
    }

    return headers;
  }

  private convertToPortkeyFormat(request: GenerateContentParameters): any {
    const messages = [];
    
    if (request.contents) {
      const contentsArray = this.normalizeContents(request.contents as any);
      for (const content of contentsArray) {
        if (typeof content === 'object' && 'parts' in content && content.parts) {
          for (const part of content.parts) {
            if ('text' in part && part.text) {
              messages.push({
                role: content.role === 'model' ? 'assistant' : 'user',
                content: part.text
              });
            }
          }
        } else if (typeof content === 'string') {
          messages.push({
            role: 'user',
            content: content
          });
        } else if (typeof content === 'object' && 'text' in content && content.text) {
          messages.push({
            role: 'user',
            content: content.text
          });
        }
      }
    }

    return {
      model: this.model,
      messages: messages,
      stream: false,
      ...request.config && {
        max_tokens: request.config.maxOutputTokens,
        temperature: request.config.temperature,
        top_p: request.config.topP,
      }
    };
  }

  private normalizeContents(contents: any): any[] {
    if (Array.isArray(contents)) {
      return contents;
    }
    return [contents];
  }

  private convertFromPortkeyFormat(response: any): GenerateContentResponse {
    const text = response.choices?.[0]?.message?.content || '';
    const result = {
      candidates: [
        {
          content: {
            parts: [{ text }],
            role: 'model'
          },
          finishReason: response.choices?.[0]?.finish_reason || 'STOP',
          index: 0
        }
      ],
      usageMetadata: {
        promptTokenCount: response.usage?.prompt_tokens || 0,
        candidatesTokenCount: response.usage?.completion_tokens || 0,
        totalTokenCount: response.usage?.total_tokens || 0
      }
    } as any;
    
    // Add getters to match GoogleGenAI response format
    Object.defineProperty(result, 'text', {
      get: () => text,
      enumerable: false
    });
    Object.defineProperty(result, 'data', {
      get: () => undefined,
      enumerable: false
    });
    Object.defineProperty(result, 'functionCalls', {
      get: () => undefined,
      enumerable: false
    });
    Object.defineProperty(result, 'executableCode', {
      get: () => undefined,
      enumerable: false
    });
    Object.defineProperty(result, 'codeExecutionResult', {
      get: () => undefined,
      enumerable: false
    });
    
    return result as GenerateContentResponse;
  }

  async generateContent(request: GenerateContentParameters): Promise<GenerateContentResponse> {
    const portkeyRequest = this.convertToPortkeyFormat(request);
    
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(portkeyRequest)
    });

    if (!response.ok) {
      throw new Error(`Portkey API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return this.convertFromPortkeyFormat(data);
  }

  async generateContentStream(request: GenerateContentParameters): Promise<AsyncGenerator<GenerateContentResponse>> {
    const portkeyRequest = {
      ...this.convertToPortkeyFormat(request),
      stream: true
    };
    
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(portkeyRequest)
    });

    if (!response.ok) {
      throw new Error(`Portkey API error: ${response.status} ${response.statusText}`);
    }

    const generator = async function* (this: PortkeyContentGenerator) {
      const reader = response.body?.getReader();
      if (!reader) {
        throw new Error('Failed to get response reader');
      }

      const decoder = new TextDecoder();
      let buffer = '';

      try {
        while (true) {
          const { done, value } = await reader.read();
          
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              if (data === '[DONE]') continue;
              
              try {
                const parsed = JSON.parse(data);
                if (parsed.choices?.[0]?.delta?.content) {
                  yield this.convertFromPortkeyFormat({
                    choices: [{
                      message: { content: parsed.choices[0].delta.content },
                      finish_reason: parsed.choices[0].finish_reason
                    }],
                    usage: parsed.usage
                  });
                }
              } catch (e) {
                // Skip malformed JSON
              }
            }
          }
        }
      } finally {
        reader.releaseLock();
      }
    }.bind(this);
    
    return generator();
  }

  async countTokens(request: CountTokensParameters): Promise<CountTokensResponse> {
    // Portkey doesn't have a direct token counting endpoint
    // We'll estimate based on the text length as a fallback
    let totalText = '';
    
    if (request.contents) {
      const contentsArray = this.normalizeContents(request.contents as any);
      for (const content of contentsArray) {
        if (typeof content === 'object' && 'parts' in content && content.parts) {
          for (const part of content.parts) {
            if ('text' in part && part.text) {
              totalText += part.text;
            }
          }
        } else if (typeof content === 'string') {
          totalText += content;
        } else if (typeof content === 'object' && 'text' in content && content.text) {
          totalText += content.text;
        }
      }
    }

    // Rough estimation: ~4 characters per token
    const estimatedTokens = Math.ceil(totalText.length / 4);

    return {
      totalTokens: estimatedTokens
    };
  }

  async embedContent(request: EmbedContentParameters): Promise<EmbedContentResponse> {
    let inputText = '';
    
    if (request.contents) {
      const contentsArray = this.normalizeContents(request.contents as any);
      for (const content of contentsArray) {
        if (typeof content === 'object' && 'parts' in content && content.parts) {
          for (const part of content.parts) {
            if ('text' in part && part.text) {
              inputText += part.text + ' ';
            }
          }
        } else if (typeof content === 'string') {
          inputText += content + ' ';
        } else if (typeof content === 'object' && 'text' in content && content.text) {
          inputText += content.text + ' ';
        }
      }
    }
    
    const embedRequest = {
      model: request.model || 'text-embedding-ada-002', // Default embedding model
      input: inputText.trim(),
    };

    const response = await fetch(`${this.baseUrl}/embeddings`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(embedRequest)
    });

    if (!response.ok) {
      throw new Error(`Portkey Embeddings API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    return {
      embeddings: [{
        values: data.data?.[0]?.embedding || []
      }]
    } as EmbedContentResponse;
  }
}
