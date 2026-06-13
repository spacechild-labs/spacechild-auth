/**
 * Agent Delegation Routes (WARRANT layer — ADDITIVE)
 *
 * A new router, mounted under /auth/agents, implementing the "proof-of-delegation"
 * surface that the constellation (Steward / AMOR / ghostsignals) needs:
 *
 *   POST   /auth/agents/grants              create a delegation (auth required, owner-only)
 *   GET    /auth/agents/grants              list the caller's own grants
 *   POST   /auth/agents/grants/:id/revoke   revoke one of the caller's grants
 *   POST   /auth/agents/introspect          the WARRANT CHECK a surface calls
 *   POST   /auth/agents/token               mint a scoped agent token (additive, optional)
 *
 * This file is ENTIRELY ADDITIVE: it imports existing middleware/services and
 * registers as a sub-router. It does not modify any existing route handler.
 *
 * An "agent" is an OAuth2 client (oauth2_clients) OWNED BY a human (owner_id).
 * A grant is a scoped, time-boxed, revocable delegation for that client. Token
 * issuance reuses the existing JWT signing; agent_grants is the delegation record
 * + constraints + revocation that introspection consults.
 */

import { Router } from "express";
import { z } from "zod";
import { authService } from "./auth-service";
import { isAuthenticated } from "./middleware";
import { storage } from "./storage";
import { validateAgentScopes } from "./agent-scopes";
import { decideWarrant } from "./agent-warrant";
import type { AgentGrant, AgentGrantConstraints } from "./types";

const router = Router();

// ============================================
// VALIDATION SCHEMAS
// ============================================

const perWindowSchema = z.object({
  action: z.string().min(1),
  count: z.number().int().nonnegative(),
  windowSec: z.number().int().positive(),
});

const constraintsSchema = z
  .object({
    maxAutoImpact: z.number().nonnegative().optional(),
    perWindow: perWindowSchema.optional(),
  })
  .passthrough();

// Ethereum-style 0x + 40 hex chars (optional on-chain binding / KAX wallet).
const walletSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, "bound_wallet_address must be a 0x-prefixed 40-hex address");

const createGrantSchema = z.object({
  clientId: z.string().min(1, "clientId (agent OAuth2 client) is required"),
  scopes: z.array(z.string().min(1)).min(1, "at least one scope is required"),
  // ttl in seconds → expires_at. Capped at 1 year to keep delegations time-boxed.
  ttlSec: z.number().int().positive().max(365 * 24 * 60 * 60),
  boundWalletAddress: walletSchema.optional().nullable(),
  constraints: constraintsSchema.optional().nullable(),
});

const introspectSchema = z
  .object({
    token: z.string().min(1).optional(),
    grantId: z.string().min(1).optional(),
    scope: z.string().min(1),
    action: z.string().min(1).optional(),
    impact: z.number().optional(),
  })
  .refine((d) => !!d.token || !!d.grantId, {
    message: "either token or grantId is required",
  });

const tokenSchema = z.object({
  grantId: z.string().min(1, "grantId is required"),
  // Optional explicit TTL for the minted token; defaults applied below, capped to grant expiry.
  ttlSec: z.number().int().positive().max(24 * 60 * 60).optional(),
});

// Default agent-token lifetime when not specified (15 minutes, mirrors access token).
const DEFAULT_AGENT_TOKEN_TTL_SEC = 15 * 60;

// ============================================
// SERIALIZATION (never leak secrets)
// ============================================

function serializeGrant(grant: AgentGrant) {
  return {
    id: grant.id,
    clientId: grant.clientId,
    userId: grant.userId,
    scopes: grant.scopes,
    boundWalletAddress: grant.boundWalletAddress,
    constraints: grant.constraints,
    status: grant.status,
    createdAt: grant.createdAt,
    expiresAt: grant.expiresAt,
    revokedAt: grant.revokedAt,
  };
}

// ============================================
// POST /auth/agents/grants — create a delegation
// ============================================

router.post("/grants", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims?.sub) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const parsed = createGrantSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0].message });
    }

    const { clientId, scopes, ttlSec, boundWalletAddress, constraints } = parsed.data;

    // Validate the agent OAuth2 client exists.
    const client = await storage.getOAuth2ClientByClientId(clientId);
    if (!client) {
      return res.status(404).json({ error: "Agent client not found" });
    }

    // Ownership: the authenticated human must own the client.
    if (client.ownerId !== claims.sub) {
      return res
        .status(403)
        .json({ error: "Forbidden - you do not own this agent client" });
    }

    if (!client.isActive) {
      return res.status(400).json({ error: "Agent client is not active" });
    }

    // Scope validation: requested ⊆ catalog ∩ client.allowed_scopes.
    const scopeCheck = validateAgentScopes(scopes, client.allowedScopes);
    if (!scopeCheck.valid) {
      return res.status(400).json({
        error: "Invalid scopes",
        reasons: scopeCheck.reasons,
      });
    }

    const expiresAt = new Date(Date.now() + ttlSec * 1000);

    const grant = await storage.createAgentGrant({
      clientId,
      userId: claims.sub,
      scopes: scopeCheck.normalized,
      boundWalletAddress: boundWalletAddress ?? null,
      constraints: (constraints as AgentGrantConstraints | null) ?? null,
      status: "active",
      expiresAt,
    });

    return res.status(201).json({ success: true, grant: serializeGrant(grant) });
  } catch (error: any) {
    console.error("Create agent grant error:", error);
    return res.status(500).json({ error: "Failed to create agent grant" });
  }
});

// ============================================
// GET /auth/agents/grants — list caller's grants
// ============================================

router.get("/grants", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims?.sub) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const grants = await storage.getAgentGrantsByUser(claims.sub);
    return res.json({ grants: grants.map(serializeGrant) });
  } catch (error: any) {
    console.error("List agent grants error:", error);
    return res.status(500).json({ error: "Failed to list agent grants" });
  }
});

// ============================================
// POST /auth/agents/grants/:id/revoke — revoke (owner only)
// ============================================

router.post("/grants/:id/revoke", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims?.sub) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { id } = req.params;
    const grant = await storage.getAgentGrant(id);
    if (!grant) {
      return res.status(404).json({ error: "Grant not found" });
    }

    // Ownership enforcement: only the owner may revoke.
    if (grant.userId !== claims.sub) {
      return res.status(403).json({ error: "Forbidden - not your grant" });
    }

    if (grant.status !== "active") {
      // Idempotent-ish: report current state without flipping a revoked/expired one.
      return res.json({
        success: true,
        grant: serializeGrant(grant),
        message: `Grant already ${grant.status}`,
      });
    }

    await storage.revokeAgentGrant(id);
    const updated = await storage.getAgentGrant(id);
    return res.json({
      success: true,
      grant: updated ? serializeGrant(updated) : undefined,
    });
  } catch (error: any) {
    console.error("Revoke agent grant error:", error);
    return res.status(500).json({ error: "Failed to revoke agent grant" });
  }
});

// ============================================
// POST /auth/agents/introspect — the WARRANT CHECK
// ============================================
// Conservative by design: any doubt → authorized:false with reasons.
// No auth middleware: this is a service-to-service confirmation that a token /
// grant authorises an action; it reveals only delegation facts, never secrets.

router.post("/introspect", async (req, res) => {
  try {
    const parsed = introspectSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        authorized: false,
        reasons: [parsed.error.errors[0].message],
      });
    }

    const { token, grantId, scope, action, impact } = parsed.data;

    // Resolve the grant: prefer an explicit grantId; otherwise derive it from
    // the agent token's grant_id claim. Deny on any resolution failure.
    let resolvedGrant: AgentGrant | undefined;
    const reasons: string[] = [];

    if (token) {
      const claims = authService.verifyAgentToken(token);
      if (!claims) {
        return res.json({
          authorized: false,
          userId: null,
          agentClientId: null,
          scopes: [],
          reasons: ["invalid or expired agent token"],
        });
      }
      resolvedGrant = await storage.getAgentGrant(claims.grantId);

      // If a grantId was ALSO supplied, it must match the token's grant.
      if (grantId && grantId !== claims.grantId) {
        reasons.push("token/grantId mismatch");
      }
    } else if (grantId) {
      resolvedGrant = await storage.getAgentGrant(grantId);
    }

    // If the token said one thing but the grant resolution disagreed, deny.
    if (reasons.length > 0) {
      return res.json({
        authorized: false,
        userId: resolvedGrant?.userId ?? null,
        agentClientId: resolvedGrant?.clientId ?? null,
        scopes: resolvedGrant?.scopes ?? [],
        reasons,
      });
    }

    const decision = decideWarrant(resolvedGrant ?? null, { scope, action, impact });

    return res.json({
      authorized: decision.authorized,
      userId: decision.userId,
      agentClientId: decision.agentClientId,
      scopes: decision.scopes,
      boundWallet: decision.boundWallet ?? null,
      reasons: decision.reasons,
    });
  } catch (error: any) {
    console.error("Agent introspect error:", error);
    // Conservative: errors deny.
    return res.status(500).json({
      authorized: false,
      reasons: ["introspection error"],
    });
  }
});

// ============================================
// POST /auth/agents/token — mint a scoped agent token (owner only)
// ============================================
// Additive token issuance: mints a scoped JWT carrying the delegation, reusing
// the existing JWT signing util. Only the grant owner may mint.

router.post("/token", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims?.sub) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const parsed = tokenSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0].message });
    }

    const { grantId, ttlSec } = parsed.data;

    const grant = await storage.getAgentGrant(grantId);
    if (!grant) {
      return res.status(404).json({ error: "Grant not found" });
    }

    if (grant.userId !== claims.sub) {
      return res.status(403).json({ error: "Forbidden - not your grant" });
    }

    if (grant.status !== "active") {
      return res.status(400).json({ error: `Grant is ${grant.status}` });
    }

    // Token may not outlive the grant.
    const now = Date.now();
    const grantRemainingSec = grant.expiresAt
      ? Math.floor((new Date(grant.expiresAt).getTime() - now) / 1000)
      : DEFAULT_AGENT_TOKEN_TTL_SEC;

    if (grantRemainingSec <= 0) {
      return res.status(400).json({ error: "Grant has expired" });
    }

    const requestedTtl = ttlSec ?? DEFAULT_AGENT_TOKEN_TTL_SEC;
    const effectiveTtl = Math.min(requestedTtl, grantRemainingSec);

    const { token, expiresIn } = authService.mintAgentToken({
      userId: grant.userId,
      agentClientId: grant.clientId,
      grantId: grant.id,
      scopes: grant.scopes,
      expiresInSec: effectiveTtl,
    });

    return res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: grant.scopes.join(" "),
      grant_id: grant.id,
    });
  } catch (error: any) {
    console.error("Mint agent token error:", error);
    return res.status(500).json({ error: "Failed to mint agent token" });
  }
});

export default router;
