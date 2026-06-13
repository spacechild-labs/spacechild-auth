/**
 * Agent Scope Catalog (WARRANT layer)
 *
 * Namespaced scopes describing what a delegated agent (an OAuth2 client owned by
 * a human) is permitted to do on that human's behalf. This is an ADDITIVE module:
 * it introduces no dependency on existing auth flows and is consumed only by the
 * new agent-delegation router / storage.
 *
 * A requested scope set for a grant must be a subset of BOTH:
 *   1. this catalog (the universe of known agent scopes), AND
 *   2. the owning OAuth2 client's `allowed_scopes` (what the client may ever request).
 *
 * Pure functions only — no DB, no I/O — so the warrant decision logic is unit
 * testable without a live database.
 */

// ============================================
// CATALOG
// ============================================

/**
 * The complete set of agent-delegation scopes recognised by the WARRANT layer.
 * Namespaced under `agent:` so they never collide with the OIDC core scopes
 * (`openid`, `profile`, `email`) that the existing OAuth2 server issues.
 */
export const AGENT_SCOPE_CATALOG = [
  "agent:govern:vote:bounded",
  "agent:market:trade:bounded",
  "agent:treasury:read",
  "agent:curate:publish",
] as const;

export type AgentScope = (typeof AGENT_SCOPE_CATALOG)[number];

/** Fast membership set for the catalog. */
const CATALOG_SET: ReadonlySet<string> = new Set(AGENT_SCOPE_CATALOG);

/**
 * True if `scope` is a known agent-delegation scope.
 */
export function isAgentScope(scope: string): scope is AgentScope {
  return CATALOG_SET.has(scope);
}

// ============================================
// VALIDATION
// ============================================

export interface ScopeValidationResult {
  /** Whether the requested scopes pass every check. */
  valid: boolean;
  /** The normalised (de-duplicated, trimmed) requested scopes. */
  normalized: string[];
  /** Requested scopes that are not in the agent catalog. */
  unknown: string[];
  /** Requested scopes not permitted by the owning client's allowed_scopes. */
  notAllowedByClient: string[];
  /** Human-readable reasons for any rejection (empty when valid). */
  reasons: string[];
}

/**
 * Normalise an arbitrary scope input into a clean, de-duplicated string array.
 * Accepts either a space-delimited string (OAuth2 convention) or an array.
 */
export function normalizeScopes(input: unknown): string[] {
  let parts: string[];
  if (Array.isArray(input)) {
    parts = input.map((s) => String(s));
  } else if (typeof input === "string") {
    parts = input.split(/\s+/);
  } else {
    return [];
  }

  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of parts) {
    const s = raw.trim();
    if (s.length === 0) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

/**
 * Validate that a requested set of agent scopes is:
 *   - non-empty,
 *   - a subset of the agent scope catalog, AND
 *   - a subset of the owning client's allowed_scopes.
 *
 * Pure function: no side effects. Conservative — any unknown or disallowed
 * scope fails the whole set.
 *
 * @param requested      requested scopes (string[] or space-delimited string)
 * @param clientAllowed  the owning OAuth2 client's `allowed_scopes`
 */
export function validateAgentScopes(
  requested: unknown,
  clientAllowed: unknown,
): ScopeValidationResult {
  const normalized = normalizeScopes(requested);
  const clientAllowedSet = new Set(normalizeScopes(clientAllowed));

  const unknown: string[] = [];
  const notAllowedByClient: string[] = [];

  for (const scope of normalized) {
    if (!CATALOG_SET.has(scope)) {
      unknown.push(scope);
    } else if (!clientAllowedSet.has(scope)) {
      // Only meaningful to flag client-disallowed if it is otherwise a real scope.
      notAllowedByClient.push(scope);
    }
  }

  const reasons: string[] = [];
  if (normalized.length === 0) {
    reasons.push("no scopes requested");
  }
  if (unknown.length > 0) {
    reasons.push(`unknown agent scope(s): ${unknown.join(", ")}`);
  }
  if (notAllowedByClient.length > 0) {
    reasons.push(
      `scope(s) not permitted by owning client: ${notAllowedByClient.join(", ")}`,
    );
  }

  return {
    valid: reasons.length === 0,
    normalized,
    unknown,
    notAllowedByClient,
    reasons,
  };
}
