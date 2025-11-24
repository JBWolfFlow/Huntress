/**
 * Tool Output Manager
 *
 * Manages persistence of tool outputs to temporary files for inter-tool data passing.
 * This enables tools like httpx to read targets from files created by subfinder/amass.
 *
 * Note: Uses Tauri commands for file operations since Node.js modules aren't available in browser context.
 */

import { invoke } from '@tauri-apps/api/core';

/**
 * Tool output metadata
 */
export interface ToolOutput {
  toolName: string;
  sessionId: string;
  timestamp: Date;
  outputFile: string;
  lineCount: number;
}

/**
 * Tool Output Manager
 * 
 * Handles saving and retrieving tool outputs for multi-phase hunts
 */
export class ToolOutputManager {
  private outputs: Map<string, ToolOutput> = new Map();
  private tempDir: string = '';

  constructor() {
    // Use a fixed path that works in Tauri context
    // Tauri runs from src-tauri directory, so use relative path from there
    this.tempDir = './huntress_tool_outputs';
    
    console.log('[ToolOutputManager] Temp directory:', this.tempDir);
    console.log('[ToolOutputManager] Note: Files will be created relative to Tauri backend (src-tauri/)');
    
    // Initialize directory via Tauri
    this.initDirectory();
  }
  
  /**
   * Initialize the output directory using Tauri commands
   */
  private async initDirectory(): Promise<void> {
    try {
      // Use Tauri to create directory if it doesn't exist
      await invoke('create_output_directory', { path: this.tempDir }).catch(() => {
        // Directory might already exist, that's fine
        console.log('[ToolOutputManager] Directory already exists or created');
      });
    } catch (error) {
      console.warn('[ToolOutputManager] Could not create directory via Tauri:', error);
    }
  }

  /**
   * Save tool output to a file
   * 
   * @param toolName - Name of the tool (e.g., 'subfinder', 'amass')
   * @param sessionId - Unique session ID
   * @param output - Tool output text
   * @param filename - Optional custom filename (defaults to toolName_sessionId.txt)
   * @returns Path to the saved file
   */
  async saveOutput(
    toolName: string,
    sessionId: string,
    output: string,
    filename?: string
  ): Promise<string> {
    try {
      // Generate filename
      const outputFilename = filename || `${toolName}_${sessionId}.txt`;
      const outputPath = `${this.tempDir}/${outputFilename}`;

      // Write file using Tauri command
      await invoke('write_tool_output', {
        path: outputPath,
        content: output
      });

      // Count lines
      const lines = output.split('\n').filter((line: string) => line.trim().length > 0);
      
      // Store metadata
      const metadata: ToolOutput = {
        toolName,
        sessionId,
        timestamp: new Date(),
        outputFile: outputPath,
        lineCount: lines.length,
      };
      
      this.outputs.set(sessionId, metadata);
      
      console.log('[ToolOutputManager] Saved output:', {
        toolName,
        sessionId,
        path: outputPath,
        lines: lines.length,
      });

      return outputPath;
    } catch (error) {
      console.error('[ToolOutputManager] Failed to save output:', error);
      throw new Error(`Failed to save tool output: ${error}`);
    }
  }

  /**
   * Create a consolidated file from multiple tool outputs
   * 
   * Useful for combining subfinder + amass results into a single targets.txt
   * 
   * @param sessionIds - Array of session IDs to combine
   * @param outputFilename - Name for the combined file
   * @returns Path to the combined file
   */
  async combineOutputs(
    sessionIds: string[],
    outputFilename: string
  ): Promise<string> {
    try {
      const combinedLines = new Set<string>();

      // Read all outputs and deduplicate
      for (const sessionId of sessionIds) {
        const metadata = this.outputs.get(sessionId);
        if (!metadata) {
          console.warn('[ToolOutputManager] Session not found:', sessionId);
          continue;
        }

        const content = await invoke<string>('read_tool_output', {
          path: metadata.outputFile
        });
        
        const lines = content.split('\n')
          .map((line: string) => line.trim())
          .filter((line: string) => line.length > 0);
        
        lines.forEach((line: string) => combinedLines.add(line));
      }

      // Write combined output
      const combinedPath = `${this.tempDir}/${outputFilename}`;
      const combinedContent = Array.from(combinedLines).join('\n');
      
      await invoke('write_tool_output', {
        path: combinedPath,
        content: combinedContent
      });

      console.log('[ToolOutputManager] Combined outputs:', {
        sessionCount: sessionIds.length,
        totalLines: combinedLines.size,
        outputPath: combinedPath,
      });

      return combinedPath;
    } catch (error) {
      console.error('[ToolOutputManager] Failed to combine outputs:', error);
      throw new Error(`Failed to combine tool outputs: ${error}`);
    }
  }

  /**
   * Get output metadata by session ID
   */
  getOutput(sessionId: string): ToolOutput | undefined {
    return this.outputs.get(sessionId);
  }

  /**
   * Get all outputs for a specific tool
   */
  getOutputsByTool(toolName: string): ToolOutput[] {
    return Array.from(this.outputs.values())
      .filter(output => output.toolName === toolName);
  }

  /**
   * Check if a file exists
   */
  async fileExists(filepath: string): Promise<boolean> {
    try {
      const exists = await invoke<boolean>('file_exists', { path: filepath });
      return exists;
    } catch {
      return false;
    }
  }

  /**
   * Clean up old output files
   */
  async cleanup(sessionIds?: string[]): Promise<void> {
    try {
      const toClean = sessionIds 
        ? sessionIds.map(id => this.outputs.get(id)).filter(Boolean) as ToolOutput[]
        : Array.from(this.outputs.values());

      for (const output of toClean) {
        try {
          if (await this.fileExists(output.outputFile)) {
            await invoke('delete_tool_output', { path: output.outputFile });
            console.log('[ToolOutputManager] Cleaned up:', output.outputFile);
          }
          this.outputs.delete(output.sessionId);
        } catch (error) {
          console.warn('[ToolOutputManager] Failed to clean up file:', error);
        }
      }
    } catch (error) {
      console.error('[ToolOutputManager] Cleanup failed:', error);
    }
  }

  /**
   * Get all session IDs
   */
  getAllSessionIds(): string[] {
    return Array.from(this.outputs.keys());
  }
}

// Global singleton instance
let globalInstance: ToolOutputManager | null = null;

/**
 * Get the global ToolOutputManager instance
 */
export function getToolOutputManager(): ToolOutputManager {
  if (!globalInstance) {
    globalInstance = new ToolOutputManager();
  }
  return globalInstance;
}

export default ToolOutputManager;