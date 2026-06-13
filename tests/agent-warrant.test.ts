/**
 * Agent Warrant Tests (WARRANT layer)
 *
 * Pure-logic tests for the delegation warrant core — no database required.
 * Covers:
 *   - scope-subset validation (catalog ∩ client.allowed_scopes)
 *   - constraint / impact checks
 *   - grant liveness (active / expired / revoked)
 *   - the introspect decision function (the warrant core):
 *       active            → authorized
 *       expired           → denied
 *       revoked           → denied
 *       scope-not-granted → denied
 *       impact-over-cap   → denied
 */

import { describe, it, expect } from "vitest";
import {
  AGENT_SCOPE_CATALOG,
  isAgentScope,
  normalizeScopes,
  validateAgentScopes,
} from "../src/agent-scopes";
import {
  decideWarrant,
  isGrantLive,
  checkImpact,
} from "../src/agent-warrant";
import type { AgentGrant } from "../src/types";

// ============================================
// FIXTURES
// ============================================

const NOW = new Date("2026-06-13T12:00:00Z");
const FUTURE = new Date("2026-06-14T12:00:00Z");
const PAST = new Date("2026-06-12T12:00:00Z");

function makeGrant(overrides: Partial<AgentGrant> = {}): AgentGrant {
  return {
    id: "grant-1",
    clientId: "agent-client-1",
    userId: "user-1",
    scopes: ["agent:govern:vote:bounded", "agent:treasury:read"],
    boundWalletAddress: null,
    constraints: null,
    status: "active",
    createdAt: PAST,
    expiresAt: FUTURE,
    revokedAt: null,
    ...overrides,
  };
}

// ============================================
// SCOPE CATALOG + VALIDATION
// ============================================

describe("agent scope catalog", () => {
  it("recognises catalog scopes", () => {
    expect(isAgentScope("agent:govern:vote:bounded")).toBe(true);
    expect(isAgentScope("agent:market:trade:bounded")).toBe(true);
    expect(isAgentScope("agent:treasury:read")).toBe(true);
    expect(isAgentScope("agent:curate:publish")).toBe(true);
  });

  it("rejects non-catalog scopes", () => {
    expect(isAgentScope("openid")).toBe(false);
    expect(isAgentScope("agent:treasury:write")).toBe(false);
    expect(isAgentScope("")).toBe(false);
  });

  it("has exactly the documented catalog", () => {
    expect([...AGENT_SCOPE_CATALOG].sort()).toEqual(
      [
        "agent:curate:publish",
        "agent:govern:vote:bounded",
        "agent:market:trade:bounded",
        "agent:treasury:read",
      ].sort(),
    );
  });
});

describe("normalizeScopes", () => {
  it("parses space-delimited strings", () => {
    expect(normalizeScopes("a b  c")).toEqual(["a", "b", "c"]);
  });
  it("de-duplicates and trims arrays", () => {
    expect(normalizeScopes([" a ", "a", "b"])).toEqual(["a", "b"]);
  });
  it("returns [] for junk", () => {
    expect(normalizeScopes(null)).toEqual([]);
    expect(normalizeScopes(undefined)).toEqual([]);
    expect(normalizeScopes(42 as any)).toEqual([]);
  });
});

describe("validateAgentScopes (subset of catalog ∩ client.allowed_scopes)", () => {
  const clientAllowed = [
    "agent:govern:vote:bounded",
    "agent:treasury:read",
    "openid",
  ];

  it("accepts a valid subset", () => {
    const r = validateAgentScopes(
      ["agent:govern:vote:bounded", "agent:treasury:read"],
      clientAllowed,
    );
    expect(r.valid).toBe(true);
    expect(r.normalized).toEqual([
      "agent:govern:vote:bounded",
      "agent:treasury:read",
    ]);
    expect(r.reasons).toEqual([]);
  });

  it("rejects empty scope sets", () => {
    const r = validateAgentScopes([], clientAllowed);
    expect(r.valid).toBe(false);
    expect(r.reasons.join(" ")).toContain("no scopes");
  });

  it("rejects scopes not in the catalog", () => {
    const r = validateAgentScopes(["agent:treasury:write"], clientAllowed);
    expect(r.valid).toBe(false);
    expect(r.unknown).toContain("agent:treasury:write");
    expect(r.reasons.join(" ")).toContain("unknown agent scope");
  });

  it("rejects catalog scopes the client is not allowed to request", () => {
    // agent:curate:publish is a real catalog scope but NOT in clientAllowed.
    const r = validateAgentScopes(["agent:curate:publish"], clientAllowed);
    expect(r.valid).toBe(false);
    expect(r.notAllowedByClient).toContain("agent:curate:publish");
    expect(r.reasons.join(" ")).toContain("not permitted by owning client");
  });

  it("treats non-catalog tokens as unknown even if the client lists them", () => {
    // 'openid' is in clientAllowed but is NOT an agent scope.
    const r = validateAgentScopes(["openid"], clientAllowed);
    expect(r.valid).toBe(false);
    expect(r.unknown).toContain("openid");
  });
});

// ============================================
// LIVENESS
// ============================================

describe("isGrantLive", () => {
  it("active + not expired → live", () => {
    expect(isGrantLive(makeGrant(), NOW).live).toBe(true);
  });
  it("revoked → not live", () => {
    expect(isGrantLive(makeGrant({ status: "revoked" }), NOW).live).toBe(false);
  });
  it("status expired → not live", () => {
    expect(isGrantLive(makeGrant({ status: "expired" }), NOW).live).toBe(false);
  });
  it("elapsed expiresAt → not live even if status still active", () => {
    const r = isGrantLive(makeGrant({ expiresAt: PAST }), NOW);
    expect(r.live).toBe(false);
    expect(r.reason).toContain("expired");
  });
  it("null expiresAt + active → live", () => {
    expect(isGrantLive(makeGrant({ expiresAt: null }), NOW).live).toBe(true);
  });
});

// ============================================
// IMPACT / CONSTRAINTS
// ============================================

describe("checkImpact", () => {
  it("no impact supplied → ok", () => {
    expect(checkImpact({ maxAutoImpact: 100 }, undefined).ok).toBe(true);
  });
  it("impact below cap → ok", () => {
    expect(checkImpact({ maxAutoImpact: 100 }, 50).ok).toBe(true);
  });
  it("impact equal to cap → denied (conservative)", () => {
    expect(checkImpact({ maxAutoImpact: 100 }, 100).ok).toBe(false);
  });
  it("impact over cap → denied", () => {
    const r = checkImpact({ maxAutoImpact: 100 }, 150);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("over maxAutoImpact");
  });
  it("impact supplied but no cap configured → denied", () => {
    expect(checkImpact(null, 10).ok).toBe(false);
    expect(checkImpact({}, 10).ok).toBe(false);
  });
  it("negative or NaN impact → denied", () => {
    expect(checkImpact({ maxAutoImpact: 100 }, -1).ok).toBe(false);
    expect(checkImpact({ maxAutoImpact: 100 }, NaN).ok).toBe(false);
  });
});

// ============================================
// WARRANT DECISION (the core)
// ============================================

describe("decideWarrant (introspect core)", () => {
  it("active grant, granted scope → authorized", () => {
    const d = decideWarrant(makeGrant(), { scope: "agent:treasury:read" }, NOW);
    expect(d.authorized).toBe(true);
    expect(d.userId).toBe("user-1");
    expect(d.agentClientId).toBe("agent-client-1");
    expect(d.reasons).toEqual([]);
  });

  it("no grant → denied", () => {
    const d = decideWarrant(null, { scope: "agent:treasury:read" }, NOW);
    expect(d.authorized).toBe(false);
    expect(d.reasons).toContain("no matching grant");
  });

  it("expired grant → denied", () => {
    const d = decideWarrant(
      makeGrant({ expiresAt: PAST }),
      { scope: "agent:treasury:read" },
      NOW,
    );
    expect(d.authorized).toBe(false);
    expect(d.reasons.join(" ")).toContain("expired");
  });

  it("revoked grant → denied", () => {
    const d = decideWarrant(
      makeGrant({ status: "revoked" }),
      { scope: "agent:treasury:read" },
      NOW,
    );
    expect(d.authorized).toBe(false);
    expect(d.reasons.join(" ")).toContain("revoked");
  });

  it("scope not in grant → denied", () => {
    const d = decideWarrant(
      makeGrant(),
      { scope: "agent:curate:publish" },
      NOW,
    );
    expect(d.authorized).toBe(false);
    expect(d.reasons.join(" ")).toContain("not granted");
  });

  it("missing scope → denied", () => {
    const d = decideWarrant(makeGrant(), { scope: "" }, NOW);
    expect(d.authorized).toBe(false);
    expect(d.reasons.join(" ")).toContain("no scope");
  });

  it("impact within constraint → authorized", () => {
    const d = decideWarrant(
      makeGrant({ constraints: { maxAutoImpact: 100 } }),
      { scope: "agent:treasury:read", impact: 50 },
      NOW,
    );
    expect(d.authorized).toBe(true);
  });

  it("impact over constraint → denied", () => {
    const d = decideWarrant(
      makeGrant({ constraints: { maxAutoImpact: 100 } }),
      { scope: "agent:treasury:read", impact: 250 },
      NOW,
    );
    expect(d.authorized).toBe(false);
    expect(d.reasons.join(" ")).toContain("maxAutoImpact");
  });

  it("surfaces the bound wallet when present", () => {
    const wallet = "0x" + "a".repeat(40);
    const d = decideWarrant(
      makeGrant({ boundWalletAddress: wallet }),
      { scope: "agent:treasury:read" },
      NOW,
    );
    expect(d.authorized).toBe(true);
    expect(d.boundWallet).toBe(wallet);
  });

  it("accumulates multiple reasons (expired AND scope-not-granted)", () => {
    const d = decideWarrant(
      makeGrant({ status: "revoked" }),
      { scope: "agent:curate:publish" },
      NOW,
    );
    expect(d.authorized).toBe(false);
    expect(d.reasons.length).toBeGreaterThanOrEqual(2);
  });
});
