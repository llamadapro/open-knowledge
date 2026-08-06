import {
  type KnowledgeRuntimeScope,
  KnowledgeRuntimeScopeSchema,
} from '@inkeep/open-knowledge-core';

export class KnowledgeRuntimeScopeConfigurationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'KnowledgeRuntimeScopeConfigurationError';
  }
}

export interface ResolveKnowledgeRuntimeScopeOptions {
  authorizationConfigured: boolean;
  explicitScope?: KnowledgeRuntimeScope;
  publishedBranch?: string;
}

const DEFAULT_PUBLISHED_RUNTIME_SCOPE: KnowledgeRuntimeScope = {
  kind: 'published',
  branch: 'main',
};

/**
 * Lower-level shared transport factories use this fail-closed default when
 * authentication is configured but their caller omitted an explicit scope.
 * The normal boot path still resolves branch overrides and proposal scopes.
 */
export function defaultSharedKnowledgeRuntimeScope(
  scope: KnowledgeRuntimeScope | undefined,
): KnowledgeRuntimeScope {
  return scope ?? DEFAULT_PUBLISHED_RUNTIME_SCOPE;
}

/**
 * Resolve the hosted filesystem posture. Authentication implies a read-only
 * published runtime unless an orchestrator explicitly boots a validated
 * principal-owned proposal runtime. Local single-user mode remains unscoped.
 */
export function resolveKnowledgeRuntimeScope(
  options: ResolveKnowledgeRuntimeScopeOptions,
): KnowledgeRuntimeScope | undefined {
  if (!options.authorizationConfigured) {
    if (options.explicitScope !== undefined || options.publishedBranch !== undefined) {
      throw new KnowledgeRuntimeScopeConfigurationError(
        'Knowledge runtime scope requires shared-server authentication.',
      );
    }
    return undefined;
  }

  const candidate: unknown =
    options.explicitScope ??
    (options.publishedBranch === undefined
      ? DEFAULT_PUBLISHED_RUNTIME_SCOPE
      : {
          kind: 'published',
          branch: options.publishedBranch.trim() || 'main',
        });
  const parsed = KnowledgeRuntimeScopeSchema.safeParse(candidate);
  if (!parsed.success) {
    throw new KnowledgeRuntimeScopeConfigurationError('Knowledge runtime scope is invalid.', {
      cause: parsed.error,
    });
  }
  return parsed.data;
}
