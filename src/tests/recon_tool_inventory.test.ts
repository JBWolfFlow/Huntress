/**
 * Recon-pipeline tool-inventory invariants (P1-2, 2026-04-24)
 *
 * These tests enforce the contract between three artifacts:
 *
 *   1. `ATTACK_MACHINE_TOOLS` in `src/core/orchestrator/recon_pipeline.ts`
 *      — single-source-of-truth list of binaries the attack-machine
 *      container provides.
 *   2. `buildStages()` in the same file — the actual recon DAG, whose
 *      `commands[*].tool` field names the binary each stage invokes.
 *   3. `docker/Dockerfile.attack-machine` — what the image installs.
 *
 * The Dockerfile ↔ image relationship is verified at runtime by
 * `scripts/verify_attack_tools.sh` (real `--version` smoke test inside
 * the built container). These unit tests handle the source-side
 * invariants that don't need Docker:
 *   - Every tool the pipeline invokes is in the canonical inventory.
 *   - The inventory contains no duplicates, no empty names.
 *   - Tools removed by design (getJS, gowitness, jsluice) are NOT present.
 */
import { describe, it, expect } from 'vitest';
import {
  buildStages,
  ATTACK_MACHINE_TOOLS,
  ATTACK_MACHINE_TOOL_NAMES,
  type PipelineConfig,
} from '../core/orchestrator/recon_pipeline';

const baseConfig: PipelineConfig = {
  target: 'example.com',
  // Default everything off so all stages are present in the DAG and we
  // exercise every tool reference.
  skipPortScan: false,
  skipContentDiscovery: false,
};

describe('ATTACK_MACHINE_TOOLS — inventory hygiene', () => {
  it('contains no duplicates', () => {
    const names = ATTACK_MACHINE_TOOLS.map(t => t.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('every entry has a non-empty name and at least one version-arg', () => {
    for (const tool of ATTACK_MACHINE_TOOLS) {
      expect(tool.name).toBeTruthy();
      expect(tool.name).toMatch(/^[a-z0-9.\-]+$/i);
      expect(tool.versionArgs.length).toBeGreaterThan(0);
    }
  });

  it('ATTACK_MACHINE_TOOL_NAMES matches ATTACK_MACHINE_TOOLS exactly', () => {
    const fromArray = new Set(ATTACK_MACHINE_TOOLS.map(t => t.name));
    expect(ATTACK_MACHINE_TOOL_NAMES.size).toBe(fromArray.size);
    for (const n of fromArray) expect(ATTACK_MACHINE_TOOL_NAMES.has(n)).toBe(true);
  });

  it('does NOT list intentionally-absent tools', () => {
    // These three are documented as removed by design — getJS/jsluice
    // covered by katana -jc, gowitness covered by Playwright. If anyone
    // re-adds them they need a Dockerfile change AND a recon-prompt
    // update, not a test bypass.
    for (const removed of ['getJS', 'gowitness', 'jsluice', 'findomain']) {
      expect(ATTACK_MACHINE_TOOL_NAMES.has(removed)).toBe(false);
    }
  });
});

describe('buildStages — every invoked tool is in the canonical inventory', () => {
  it('every command.tool field appears in ATTACK_MACHINE_TOOL_NAMES', () => {
    const stages = buildStages('example.com', baseConfig);
    const referenced = new Set<string>();
    for (const stage of stages) {
      for (const cmd of stage.commands) referenced.add(cmd.tool);
    }
    expect(referenced.size).toBeGreaterThan(0);
    const missing = [...referenced].filter(t => !ATTACK_MACHINE_TOOL_NAMES.has(t));
    // If this fails: either add the tool to ATTACK_MACHINE_TOOLS *and*
    // the Dockerfile, or remove the stage from buildStages. Don't widen
    // the test — it exists to catch that exact drift.
    expect(missing).toEqual([]);
  });

  it('every command.command starts with the declared tool name', () => {
    // Catches the foot-gun where someone copies a stage and forgets to
    // update the `tool` field — the smoke test would skip the *actual*
    // command and verify the wrong binary.
    const stages = buildStages('example.com', baseConfig);
    for (const stage of stages) {
      for (const cmd of stage.commands) {
        const firstWord = cmd.command.trim().split(/\s+/)[0];
        expect(firstWord).toBe(cmd.tool);
      }
    }
  });

  it('emits at least one stage per major recon category', () => {
    const stages = buildStages('example.com', baseConfig);
    const ids = new Set(stages.map(s => s.id));
    // These category IDs are load-bearing — `recon_pipeline.ts` consumers
    // (orchestrator, asset map builder) check for them by name.
    for (const required of [
      'subdomain_enum',
      'http_probe',
      'waf_detect',
      'tech_fingerprint',
      'param_mining',
      'final_scan',
    ]) {
      expect(ids.has(required)).toBe(true);
    }
  });

  it('skipPortScan / skipContentDiscovery flip stage status to "skipped"', () => {
    const stages = buildStages('example.com', {
      target: 'example.com', skipPortScan: true, skipContentDiscovery: true,
    });
    const port = stages.find(s => s.id === 'port_scan');
    const content = stages.find(s => s.id === 'content_discovery');
    expect(port?.status).toBe('skipped');
    expect(content?.status).toBe('skipped');
  });
});

describe('cross-check against the agent prompt', () => {
  // Lightweight string-level check that the agent's "installed in the
  // sandbox image" list still names every tool the pipeline invokes.
  // If the canonical inventory grows and the prompt isn't updated, the
  // agent will still call the tool (it's actually installed) but its
  // mental model of the available toolkit drifts. Keep them aligned.
  it('every pipeline-referenced tool is mentioned in the recon agent prompt', async () => {
    const promptModule = await import('../agents/recon_agent');
    void promptModule;
    // The prompt is a const string inside the module; we read the file
    // contents directly via fs to avoid exporting a private constant.
    const fs = await import('node:fs/promises');
    const promptText = await fs.readFile('src/agents/recon_agent.ts', 'utf8');

    const stages = buildStages('example.com', baseConfig);
    const referenced = new Set<string>();
    for (const stage of stages) {
      for (const cmd of stage.commands) referenced.add(cmd.tool);
    }

    const missing = [...referenced].filter(t => !promptText.includes(t));
    expect(missing).toEqual([]);
  });
});
