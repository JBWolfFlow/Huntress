/**
 * LangChain Tool Registry
 * 
 * Registers custom tools for AI agents to use during testing
 */

export interface Tool {
  name: string;
  description: string;
  execute: (input: any) => Promise<any>;
}

export class ToolRegistry {
  private tools: Map<string, Tool> = new Map();

  /**
   * Register a new tool
   */
  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  /**
   * Get a tool by name
   */
  get(name: string): Tool | undefined {
    return this.tools.get(name);
  }

  /**
   * Execute a tool
   */
  async execute(name: string, input: any): Promise<any> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Tool ${name} not found`);
    }
    return tool.execute(input);
  }

  /**
   * List all registered tools
   */
  list(): Tool[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get tool descriptions for AI context
   */
  getDescriptions(): string {
    return this.list()
      .map(tool => `${tool.name}: ${tool.description}`)
      .join('\n');
  }
}

export default ToolRegistry;