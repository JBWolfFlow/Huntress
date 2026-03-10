/**
 * ModelProvider Abstraction Layer — Core Types
 *
 * Provider-agnostic interfaces for multi-model AI support.
 * All AI interactions in Huntress flow through these types.
 */

/** Role in a conversation */
export type MessageRole = 'user' | 'assistant' | 'system';

// ─── Native Tool Use Types ───────────────────────────────────────────────────

/** JSON Schema subset used for tool input definitions */
export interface JSONSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description?: string;
  enum?: string[];
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
}

/** Tool definition passed to the model for native tool use */
export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: {
    type: 'object';
    properties: Record<string, JSONSchemaProperty>;
    required?: string[];
  };
}

/** A tool call returned by the model */
export interface ToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, unknown>;
}

/** A tool result sent back to the model */
export interface ToolResultBlock {
  type: 'tool_result';
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

/** A text content block in a response */
export interface TextBlock {
  type: 'text';
  text: string;
}

/** Union of content block types returned by models */
export type ContentBlock = TextBlock | ToolUseBlock;

/** Tool choice configuration */
export type ToolChoice =
  | 'auto'
  | 'any'
  | 'none'
  | { type: 'tool'; name: string };

// ─── Message Types ───────────────────────────────────────────────────────────

/** Content within a message — text string or structured blocks */
export type MessageContent = string | ContentBlock[];

/** A single message in a conversation */
export interface ChatMessage {
  role: MessageRole;
  content: MessageContent;
  /** Tool results sent as user messages (Anthropic/OpenAI pattern) */
  toolResults?: ToolResultBlock[];
}

/** Options passed to sendMessage / streamMessage */
export interface SendMessageOptions {
  model: string;
  maxTokens?: number;
  temperature?: number;
  systemPrompt?: string;
  stopSequences?: string[];
  /** Tool definitions for native tool use */
  tools?: ToolDefinition[];
  /** How the model should choose tools */
  toolChoice?: ToolChoice;
}

/** Response from a non-streaming sendMessage call */
export interface ChatResponse {
  content: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  stopReason: 'end_turn' | 'max_tokens' | 'stop_sequence' | 'tool_use' | 'unknown';
  /** Structured tool calls from the model (native tool use) */
  toolCalls?: ToolUseBlock[];
  /** All content blocks returned by the model */
  contentBlocks?: ContentBlock[];
}

/** A single chunk from a streaming response */
export interface StreamChunk {
  type: 'content_delta' | 'tool_use_delta' | 'message_start' | 'message_stop' | 'error';
  content?: string;
  /** Partial tool use block (built incrementally during streaming) */
  toolUse?: Partial<ToolUseBlock>;
  /** Cumulative token counts, available on message_stop */
  inputTokens?: number;
  outputTokens?: number;
  error?: string;
}

/** Metadata about a model offered by a provider */
export interface ModelInfo {
  id: string;
  displayName: string;
  contextWindow: number;
  maxOutputTokens: number;
  supportsStreaming: boolean;
  supportsSystemPrompt: boolean;
  /** Cost per 1M input tokens in USD */
  inputCostPer1M: number;
  /** Cost per 1M output tokens in USD */
  outputCostPer1M: number;
}

/**
 * The core provider interface. Every AI backend implements this.
 */
export interface ModelProvider {
  readonly providerId: string;
  readonly displayName: string;

  /** Send a complete message and wait for the full response */
  sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse>;

  /** Stream a response token-by-token */
  streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk>;

  /** List models this provider offers */
  getAvailableModels(): ModelInfo[];

  /** Test whether an API key is valid */
  validateApiKey(key: string): Promise<boolean>;

  /** Estimate cost in USD for a given token count */
  estimateCost(inputTokens: number, outputTokens: number, model: string): number;

  /** Whether this provider supports native tool use */
  supportsToolUse?: boolean;
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/** Extract plain text from a ChatMessage's content */
export function getMessageText(content: MessageContent): string {
  if (typeof content === 'string') return content;
  return content
    .filter((b): b is TextBlock => b.type === 'text')
    .map(b => b.text)
    .join('');
}

/** Extract tool use blocks from a ChatMessage's content */
export function getToolUseBlocks(content: MessageContent): ToolUseBlock[] {
  if (typeof content === 'string') return [];
  return content.filter((b): b is ToolUseBlock => b.type === 'tool_use');
}

/** Configuration needed to instantiate a provider */
export interface ProviderConfig {
  apiKey?: string;
  baseUrl?: string;
  /** Extra provider-specific options */
  options?: Record<string, unknown>;
}

/** Entry in the provider registry */
export interface ProviderRegistryEntry {
  providerId: string;
  displayName: string;
  requiresApiKey: boolean;
  factory: (config: ProviderConfig) => ModelProvider;
  defaultModels: ModelInfo[];
}
