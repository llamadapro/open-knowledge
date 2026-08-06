import { z } from 'zod';

export const KNOWLEDGE_CAPABILITIES = [
  'knowledge.read',
  'knowledge.propose',
  'knowledge.review',
  'knowledge.publish',
  'knowledge.admin',
] as const;

export const KnowledgeCapabilitySchema = z.enum(KNOWLEDGE_CAPABILITIES);
export type KnowledgeCapability = z.infer<typeof KnowledgeCapabilitySchema>;

export const SECURITY_PRINCIPAL_KINDS = ['human', 'agent', 'service'] as const;
export const SecurityPrincipalKindSchema = z.enum(SECURITY_PRINCIPAL_KINDS);
export type SecurityPrincipalKind = z.infer<typeof SecurityPrincipalKindSchema>;

const SECURITY_PRINCIPAL_ID = /^(human|agent|service):[^\s:]+(?::[^\s:]+)*$/;

export const SecurityPrincipalIdSchema = z.string().min(1).max(512).regex(SECURITY_PRINCIPAL_ID);

/**
 * Authenticated identity propagated through shared-server transports.
 *
 * This is deliberately distinct from the local `/api/principal` record, which
 * identifies one desktop checkout for attribution but is not authentication.
 * Issuer-specific claims stay inside authentication adapters; the rest of the
 * server receives only this bounded, provider-neutral representation.
 */
export const SecurityPrincipalSchema = z
  .object({
    id: SecurityPrincipalIdSchema,
    kind: SecurityPrincipalKindSchema,
    issuer: z.string().min(1).max(2048),
    subject: z.string().min(1).max(512),
    displayName: z.string().min(1).max(256).optional(),
    capabilities: z.array(KnowledgeCapabilitySchema).max(KNOWLEDGE_CAPABILITIES.length),
  })
  .superRefine((principal, ctx) => {
    if (!principal.id.startsWith(`${principal.kind}:`)) {
      ctx.addIssue({
        code: 'custom',
        path: ['id'],
        message: `principal id must start with "${principal.kind}:"`,
      });
    }

    if (new Set(principal.capabilities).size !== principal.capabilities.length) {
      ctx.addIssue({
        code: 'custom',
        path: ['capabilities'],
        message: 'capabilities must not contain duplicates',
      });
    }
  });

export type SecurityPrincipal = z.infer<typeof SecurityPrincipalSchema>;

export const KNOWLEDGE_ROLES = ['reader', 'contributor', 'curator', 'agent', 'admin'] as const;
export type KnowledgeRole = (typeof KNOWLEDGE_ROLES)[number];

const ROLE_CAPABILITIES = {
  reader: ['knowledge.read'],
  contributor: ['knowledge.read', 'knowledge.propose'],
  curator: ['knowledge.read', 'knowledge.propose', 'knowledge.review'],
  agent: ['knowledge.read', 'knowledge.propose'],
  admin: [...KNOWLEDGE_CAPABILITIES],
} as const satisfies Record<KnowledgeRole, readonly KnowledgeCapability[]>;

export function capabilitiesForRole(role: KnowledgeRole): readonly KnowledgeCapability[] {
  return ROLE_CAPABILITIES[role];
}

export function hasKnowledgeCapability(
  principal: SecurityPrincipal,
  capability: KnowledgeCapability,
): boolean {
  return principal.capabilities.includes(capability);
}
