import { describe, expect, test } from 'vitest';
import { MCP_TOOL_CAPABILITIES, requiredCapabilityForMcpTool } from './mcp-tool-policy.ts';

const REGISTERED_MCP_TOOLS = [
  'exec',
  'search',
  'history',
  'links',
  'skills',
  'config',
  'palette',
  'preview_url',
  'share_link',
  'lint',
  'audit',
  'write',
  'edit',
  'delete',
  'move',
  'install',
  'import',
  'checkpoint',
  'restore_version',
  'conflicts',
  'resolve_conflict',
] as const;

describe('MCP tool capability policy', () => {
  test('classifies the entire registered tool surface exactly once', () => {
    expect(new Set(Object.keys(MCP_TOOL_CAPABILITIES))).toEqual(new Set(REGISTERED_MCP_TOOLS));
  });

  test('keeps reads, proposal mutations, and administrative code acquisition distinct', () => {
    expect(requiredCapabilityForMcpTool('search')).toBe('knowledge.read');
    expect(requiredCapabilityForMcpTool('write')).toBe('knowledge.propose');
    expect(requiredCapabilityForMcpTool('install')).toBe('knowledge.admin');
    expect(requiredCapabilityForMcpTool('lint')).toBe('knowledge.read');
    expect(requiredCapabilityForMcpTool('lint', { fix: true })).toBe('knowledge.propose');
    expect(requiredCapabilityForMcpTool('lint', [])).toBe('knowledge.read');
  });

  test('fails closed when a newly registered tool has no policy', () => {
    expect(() => requiredCapabilityForMcpTool('future_tool')).toThrow(
      'MCP tool "future_tool" has no authorization policy',
    );
  });
});
