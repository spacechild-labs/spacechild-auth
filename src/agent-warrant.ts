/**
 * Agent Warrant Decision Logic (WARRANT layer)
 *
 * Pure decision functions for the "warrant check" — given a delegation grant and
 * a requested (scope, action, impact), decide whether the agent is authorised to
 * act on behalf of its human owner, within bounds.
 *
 * ADDITIVE + PURE: no DB, no I/O, no dependency on existing auth flows. The HTTP
 * introspection endpoint (see agent-routes.ts) loads a grant from storage and
 * delegates the actual decision to `decideWarrant` here, so the core can be
 * exhaustively unit-tested without a live database.
 *
 * Design principle: CONSERVATIVE — deny on any doubt. A missing grant, an
 * unparseable constraint, an expired window, or an impact at/over the cap all
 * result in `authorized: false` with explicit reasons.
 */

import type { AgentGrant, AgentGrantConstraints } from "./types";

// ============================================
// INPUT / OUTPUT SHAPES
// ============================================

export interface WarrantQuery {
  /** The scope the surface intends to exercise (must be one of the grant's scopes). */
  scope: string;
  /** Optional action identifier (used for context / future per-action rules). */
  action?: string;
  /** Optional numeric impact to check against constraints.maxAutoImpact. */
  impact?: number;
}

export interface WarrantDecision {
  authorized: boolean;
  userId: string | null;
  agentClientId: string | null;
  scopes: string[];
  boundWallet?: string | null;
  reasons: string[];
}

// ============================================
// HELPERS
// ============================================

/**
 * Coerce a stored `status`/`expires_at` grant into a live status, treating an
 * elapsed `expiresAt` as expired even if the stored row still says 'active'
 * (the row may not have been swept yet). Pure; `now` is injectable for tests.
 */
export function isGrantLive(grant: AgentGrant, now: Date = new Date()): {
  live: boolean;
  reason?: string;
} {
  if (grant.status === "revoked") {
    return { live: false, reason: "grant revoked" };
  }
  if (grant.status === "expired") {
    return { live: false, reason: "grant expired" };
  }
  if (grant.expiresAt && now.getTime() >= new Date(grant.expiresAt).getTime()) {
    return { live: false, reason: "grant expired" };
  }
  if (grant.status !== "active") {
    return { live: false, reason: `grant not active (status=${grant.status})` };
  }
  return { live: true };
}

/**
 * Check a numeric impact against constraints.maxAutoImpact.
 * Conservative: impact must be strictly LESS THAN the cap to pass (an impact
 * equal to the cap is treated as over-bound and requires human review).
 * Returns ok=true when there is no cap or no impact supplied.
 */
export function checkImpact(
  constraints: AgentGrantConstraints | null | undefined,
  impact: number | undefined,
): { ok: boolean; reason?: string } {
  if (impact === undefined || impact === null) {
    return { ok: true };
  }
  if (typeof impact !== "number" || Number.isNaN(impact)) {
    return { ok: false, reason: "impact is not a valid number" };
  }
  if (impact < 0) {
    return { ok: false, reason: "impact must be non-negative" };
  }
  const cap = constraints?.maxAutoImpact;
  if (cap === undefined || cap === null) {
    // No cap configured: an explicit impact cannot be auto-bounded → deny.
    return {
      ok: false,
      reason: "impact supplied but no maxAutoImpact constraint is set on the grant",
    };
  }
  if (typeof cap !== "number" || Number.isNaN(cap)) {
    return { ok: false, reason: "grant maxAutoImpact is malformed" };
  }
  if (impact >= cap) {
    return {
      ok: false,
      reason: `impact ${impact} is at or over maxAutoImpact ${cap}`,
    };
  }
  return { ok: true };
}

// ============================================
// CORE DECISION
// ============================================

/**
 * The warrant core. Decide whether a delegation grant authorises a given
 * (scope, action, impact). Pure and conservative.
 *
 * @param grant  the delegation record (or null/undefined if none was found)
 * @param query  what the surface wants to do
 * @param now    injectable clock for deterministic tests
 */
export function decideWarrant(
  grant: AgentGrant | null | undefined,
  query: WarrantQuery,
  now: Date = new Date(),
): WarrantDecision {
  const reasons: string[] = [];

  // 1. Grant must exist.
  if (!grant) {
    return {
      authorized: false,
      userId: null,
      agentClientId: null,
      scopes: [],
      reasons: ["no matching grant"],
    };
  }

  const base = {
    userId: grant.userId ?? null,
    agentClientId: grant.clientId ?? null,
    scopes: Array.isArray(grant.scopes) ? grant.scopes : [],
    boundWallet: grant.boundWalletAddress ?? null,
  };

  // 2. A scope must be requested.
  const requestedScope = (query?.scope ?? "").trim();
  if (requestedScope.length === 0) {
    reasons.push("no scope requested");
  }

  // 3. Grant must be live (active + not expired + not revoked).
  const liveness = isGrantLive(grant, now);
  if (!liveness.live && liveness.reason) {
    reasons.push(liveness.reason);
  }

  // 4. Requested scope must be within the grant's scopes.
  if (requestedScope.length > 0 && !base.scopes.includes(requestedScope)) {
    reasons.push(`scope '${requestedScope}' not granted`);
  }

  // 5. Impact (if supplied) must be within constraints.
  const impactCheck = checkImpact(grant.constraints, query?.impact);
  if (!impactCheck.ok && impactCheck.reason) {
    reasons.push(impactCheck.reason);
  }

  return {
    authorized: reasons.length === 0,
    ...base,
    reasons,
  };
}
