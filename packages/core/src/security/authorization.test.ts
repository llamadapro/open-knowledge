import { describe, expect, test } from 'vitest';
import {
  capabilitiesForRole,
  hasKnowledgeCapability,
  KNOWLEDGE_CAPABILITIES,
  SecurityPrincipalSchema,
} from './authorization.ts';

const human = {
  id: 'human:auth0-123',
  kind: 'human' as const,
  issuer: 'https://identity.example/',
  subject: 'auth0|123',
  displayName: 'Ada Lovelace',
  capabilities: ['knowledge.read'] as const,
};

describe('SecurityPrincipalSchema', () => {
  test('accepts a bounded provider-neutral principal', () => {
    expect(SecurityPrincipalSchema.parse(human)).toEqual(human);
  });

  test('rejects an id whose namespace does not match its kind', () => {
    const result = SecurityPrincipalSchema.safeParse({ ...human, id: 'agent:comito:prod' });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({ message: 'principal id must start with "human:"' }),
      );
    }
  });

  test('rejects malformed and duplicate capabilities', () => {
    expect(() =>
      SecurityPrincipalSchema.parse({
        ...human,
        capabilities: ['knowledge.read', 'knowledge.read'],
      }),
    ).toThrow(/must not contain duplicates/);
    expect(() =>
      SecurityPrincipalSchema.parse({ ...human, capabilities: ['secrets.read'] }),
    ).toThrow();
  });
});

describe('knowledge roles', () => {
  test('expands every role explicitly', () => {
    expect(capabilitiesForRole('reader')).toEqual(['knowledge.read']);
    expect(capabilitiesForRole('contributor')).toEqual(['knowledge.read', 'knowledge.propose']);
    expect(capabilitiesForRole('curator')).toEqual([
      'knowledge.read',
      'knowledge.propose',
      'knowledge.review',
    ]);
    expect(capabilitiesForRole('agent')).toEqual(['knowledge.read', 'knowledge.propose']);
    expect(capabilitiesForRole('admin')).toEqual(KNOWLEDGE_CAPABILITIES);
  });

  test('checks exact expanded capabilities without hidden implication rules', () => {
    const principal = SecurityPrincipalSchema.parse(human);
    expect(hasKnowledgeCapability(principal, 'knowledge.read')).toBe(true);
    expect(hasKnowledgeCapability(principal, 'knowledge.propose')).toBe(false);
  });
});
