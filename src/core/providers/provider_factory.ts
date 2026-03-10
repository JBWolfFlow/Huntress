/**
 * ProviderFactory
 *
 * Central registry for all AI model providers.
 * Creates provider instances, lists available providers and models.
 */

import type {
  ModelProvider,
  ModelInfo,
  ProviderConfig,
  ProviderRegistryEntry,
} from './types';
import { AnthropicProvider } from './anthropic';
import { OpenAIProvider } from './openai';
import { GoogleProvider } from './google';
import { LocalProvider } from './local';
import { OpenRouterProvider } from './openrouter';

export class ProviderFactory {
  private registry: Map<string, ProviderRegistryEntry> = new Map();

  constructor() {
    this.registerDefaults();
  }

  /** Register a new provider type */
  register(entry: ProviderRegistryEntry): void {
    this.registry.set(entry.providerId, entry);
  }

  /** Create a provider instance */
  create(providerId: string, config: ProviderConfig): ModelProvider {
    const entry = this.registry.get(providerId);
    if (!entry) {
      throw new Error(`Unknown provider: ${providerId}. Available: ${this.listProviderIds().join(', ')}`);
    }
    if (entry.requiresApiKey && !config.apiKey) {
      throw new Error(`Provider "${entry.displayName}" requires an API key`);
    }
    return entry.factory(config);
  }

  /** List all registered provider IDs */
  listProviderIds(): string[] {
    return Array.from(this.registry.keys());
  }

  /** List all registered providers with metadata */
  listProviders(): Array<{
    providerId: string;
    displayName: string;
    requiresApiKey: boolean;
    models: ModelInfo[];
  }> {
    return Array.from(this.registry.values()).map(entry => ({
      providerId: entry.providerId,
      displayName: entry.displayName,
      requiresApiKey: entry.requiresApiKey,
      models: entry.defaultModels,
    }));
  }

  /** Get all models across all providers */
  listAllModels(): Array<ModelInfo & { providerId: string }> {
    const models: Array<ModelInfo & { providerId: string }> = [];
    for (const entry of this.registry.values()) {
      for (const model of entry.defaultModels) {
        models.push({ ...model, providerId: entry.providerId });
      }
    }
    return models;
  }

  /** Look up which provider owns a given model ID */
  findProviderForModel(modelId: string): string | undefined {
    for (const entry of this.registry.values()) {
      if (entry.defaultModels.some(m => m.id === modelId)) {
        return entry.providerId;
      }
    }
    return undefined;
  }

  /** Check if a provider is registered */
  has(providerId: string): boolean {
    return this.registry.has(providerId);
  }

  private registerDefaults(): void {
    this.register({
      providerId: 'anthropic',
      displayName: 'Anthropic',
      requiresApiKey: true,
      factory: (config) => new AnthropicProvider(config),
      defaultModels: new AnthropicProvider({ apiKey: 'placeholder' }).getAvailableModels(),
    });

    this.register({
      providerId: 'openai',
      displayName: 'OpenAI',
      requiresApiKey: true,
      factory: (config) => new OpenAIProvider(config),
      defaultModels: new OpenAIProvider({ apiKey: 'placeholder' }).getAvailableModels(),
    });

    this.register({
      providerId: 'google',
      displayName: 'Google AI',
      requiresApiKey: true,
      factory: (config) => new GoogleProvider(config),
      defaultModels: new GoogleProvider({ apiKey: 'placeholder' }).getAvailableModels(),
    });

    this.register({
      providerId: 'local',
      displayName: 'Local (Ollama)',
      requiresApiKey: false,
      factory: (config) => new LocalProvider(config),
      defaultModels: new LocalProvider({}).getAvailableModels(),
    });

    this.register({
      providerId: 'openrouter',
      displayName: 'OpenRouter',
      requiresApiKey: true,
      factory: (config) => new OpenRouterProvider(config),
      defaultModels: new OpenRouterProvider({ apiKey: 'placeholder' }).getAvailableModels(),
    });
  }
}

/** Singleton factory instance */
let factoryInstance: ProviderFactory | null = null;

export function getProviderFactory(): ProviderFactory {
  if (!factoryInstance) {
    factoryInstance = new ProviderFactory();
  }
  return factoryInstance;
}

export default ProviderFactory;
