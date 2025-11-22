# Plugins Directory

This directory is reserved for future mini-agent plugins that can be dynamically loaded into HUNTRESS.

## Plugin Structure

Each plugin should export:
- A class implementing the agent interface
- Configuration schema
- Test methods
- PoC generation

## Example Plugin

```typescript
export interface PluginConfig {
  name: string;
  version: string;
  description: string;
}

export class MyPlugin {
  constructor(config: PluginConfig) {
    // Initialize plugin
  }

  async test(target: string): Promise<any> {
    // Implement testing logic
  }

  generatePoC(result: any): string {
    // Generate proof of concept
  }
}
```

## Loading Plugins

Plugins will be dynamically loaded at runtime and registered with the supervisor.