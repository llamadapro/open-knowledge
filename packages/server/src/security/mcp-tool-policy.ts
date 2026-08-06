import type { KnowledgeCapability } from '@inkeep/open-knowledge-core';

export const MCP_TOOL_CAPABILITIES = {
  exec: 'knowledge.read',
  search: 'knowledge.read',
  history: 'knowledge.read',
  links: 'knowledge.read',
  skills: 'knowledge.read',
  config: 'knowledge.read',
  palette: 'knowledge.read',
  preview_url: 'knowledge.read',
  share_link: 'knowledge.read',
  conflicts: 'knowledge.read',
  audit: 'knowledge.read',
  write: 'knowledge.propose',
  edit: 'knowledge.propose',
  delete: 'knowledge.propose',
  move: 'knowledge.propose',
  lint: 'knowledge.read',
  checkpoint: 'knowledge.propose',
  restore_version: 'knowledge.propose',
  resolve_conflict: 'knowledge.propose',
  install: 'knowledge.admin',
  import: 'knowledge.admin',
} as const satisfies Record<string, KnowledgeCapability>;

export type KnownMcpTool = keyof typeof MCP_TOOL_CAPABILITIES;

export function requiredCapabilityForMcpTool(tool: string, args?: unknown): KnowledgeCapability {
  if (!(tool in MCP_TOOL_CAPABILITIES)) {
    throw new Error(`MCP tool "${tool}" has no authorization policy`);
  }
  if (
    tool === 'lint' &&
    typeof args === 'object' &&
    args !== null &&
    !Array.isArray(args) &&
    (args as Record<string, unknown>).fix === true
  ) {
    return 'knowledge.propose';
  }
  return MCP_TOOL_CAPABILITIES[tool as KnownMcpTool];
}
