/**
 * Agent Grants Storage + Token Tests (WARRANT layer)
 *
 * Exercises the agent_grants storage CRUD and the additive agent-token
 * mint/verify round-trip WITHOUT a live database, using an in-memory fake of
 * the mysql2 pool that understands just enough SQL for these paths. This mirrors
 * the existing tests/storage.test.ts mock-pool approach but is self-contained.
 */

import { describe, it, expect, beforeEach, beforeAll } from "vitest";
import type { Pool } from "mysql2/promise";
import { Storage } from "../src/storage";
import { AuthService } from "../src/auth-service";

// ============================================
// In-memory fake pool (agent_grants + oauth2_clients only)
// ============================================

interface FakeRow {
  [k: string]: any;
}

function createFakePool(): { pool: Pool; tables: { agent_grants: FakeRow[]; oauth2_clients: FakeRow[] } } {
  const tables = {
    agent_grants: [] as FakeRow[],
    oauth2_clients: [] as FakeRow[],
  };

  const execute = async (sql: string, values: any[] = []): Promise<any> => {
    const s = sql.trim();

    // --- oauth2_clients SELECT by client_id ---
    if (/^SELECT \* FROM oauth2_clients WHERE client_id = \?/i.test(s)) {
      const row = tables.oauth2_clients.find((r) => r.client_id === values[0]);
      return [row ? [row] : [], []];
    }

    // --- agent_grants INSERT ---
    if (/^INSERT INTO agent_grants/i.test(s)) {
      const [id, client_id, user_id, scopes, bound_wallet_address, constraints, status, expires_at] =
        values;
      tables.agent_grants.push({
        id,
        client_id,
        user_id,
        scopes,
        bound_wallet_address,
        constraints,
        status,
        created_at: new Date(),
        expires_at,
        revoked_at: null,
      });
      return [{ insertId: 0, affectedRows: 1 }, []];
    }

    // --- agent_grants revoke ---
    if (/^UPDATE agent_grants\s+SET status = 'revoked'/i.test(s)) {
      const id = values[0];
      const row = tables.agent_grants.find((r) => r.id === id && r.status === "active");
      if (row) {
        row.status = "revoked";
        row.revoked_at = new Date();
        return [{ affectedRows: 1 }, []];
      }
      return [{ affectedRows: 0 }, []];
    }

    // --- agent_grants expire ---
    if (/^UPDATE agent_grants\s+SET status = 'expired'/i.test(s)) {
      const id = values[0];
      const row = tables.agent_grants.find((r) => r.id === id && r.status === "active");
      if (row) {
        row.status = "expired";
        return [{ affectedRows: 1 }, []];
      }
      return [{ affectedRows: 0 }, []];
    }

    // --- agent_grants SELECT by id ---
    if (/^SELECT \* FROM agent_grants WHERE id = \?/i.test(s)) {
      const row = tables.agent_grants.find((r) => r.id === values[0]);
      return [row ? [row] : [], []];
    }

    // --- agent_grants SELECT by user_id ---
    if (/^SELECT \* FROM agent_grants WHERE user_id = \?/i.test(s)) {
      const rows = tables.agent_grants.filter((r) => r.user_id === values[0]);
      return [rows, []];
    }

    return [[], []];
  };

  const pool = { execute } as unknown as Pool;
  return { pool, tables };
}

// ============================================
// STORAGE: agent_grants CRUD
// ============================================

describe("Storage: agent grants", () => {
  let storage: Storage;
  let fake: ReturnType<typeof createFakePool>;

  beforeEach(() => {
    fake = createFakePool();
    storage = new Storage(fake.pool);
    fake.tables.oauth2_clients.push({
      id: 1,
      client_id: "agent-client-1",
      name: "Test Agent",
      description: null,
      redirect_uris: JSON.stringify([]),
      allowed_scopes: JSON.stringify(["agent:treasury:read", "agent:govern:vote:bounded"]),
      allowed_grant_types: JSON.stringify(["client_credentials"]),
      is_confidential: 1,
      is_active: 1,
      owner_id: "user-1",
      created_at: new Date(),
      updated_at: new Date(),
    });
  });

  it("reads an oauth2 client and parses JSON columns", async () => {
    const client = await storage.getOAuth2ClientByClientId("agent-client-1");
    expect(client).toBeDefined();
    expect(client?.ownerId).toBe("user-1");
    expect(client?.allowedScopes).toEqual([
      "agent:treasury:read",
      "agent:govern:vote:bounded",
    ]);
    expect(client?.isActive).toBe(true);
  });

  it("creates, reads, and lists a grant", async () => {
    const grant = await storage.createAgentGrant({
      clientId: "agent-client-1",
      userId: "user-1",
      scopes: ["agent:treasury:read"],
      constraints: { maxAutoImpact: 100 },
      expiresAt: new Date(Date.now() + 3600_000),
    });

    expect(grant.id).toBeTruthy();
    expect(grant.scopes).toEqual(["agent:treasury:read"]);
    expect(grant.constraints).toEqual({ maxAutoImpact: 100 });
    expect(grant.status).toBe("active");

    const fetched = await storage.getAgentGrant(grant.id);
    expect(fetched?.id).toBe(grant.id);

    const list = await storage.getAgentGrantsByUser("user-1");
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(grant.id);
  });

  it("revokes a grant (status → revoked, revoked_at set)", async () => {
    const grant = await storage.createAgentGrant({
      clientId: "agent-client-1",
      userId: "user-1",
      scopes: ["agent:treasury:read"],
      expiresAt: new Date(Date.now() + 3600_000),
    });

    await storage.revokeAgentGrant(grant.id);
    const after = await storage.getAgentGrant(grant.id);
    expect(after?.status).toBe("revoked");
    expect(after?.revokedAt).toBeTruthy();
  });

  it("does not list another user's grants", async () => {
    await storage.createAgentGrant({
      clientId: "agent-client-1",
      userId: "user-1",
      scopes: ["agent:treasury:read"],
      expiresAt: new Date(Date.now() + 3600_000),
    });
    const others = await storage.getAgentGrantsByUser("user-2");
    expect(others).toEqual([]);
  });
});

// ============================================
// AUTH SERVICE: agent token mint/verify
// ============================================

describe("AuthService: agent tokens", () => {
  let authService: AuthService;

  beforeAll(() => {
    process.env.SESSION_SECRET =
      process.env.SESSION_SECRET || "test-secret-key-minimum-32-characters-long";
    authService = AuthService.getInstance();
  });

  it("mints and verifies an agent token round-trip", () => {
    const { token, expiresIn } = authService.mintAgentToken({
      userId: "user-1",
      agentClientId: "agent-client-1",
      grantId: "grant-1",
      scopes: ["agent:treasury:read"],
      expiresInSec: 600,
    });

    expect(typeof token).toBe("string");
    expect(expiresIn).toBe(600);

    const claims = authService.verifyAgentToken(token);
    expect(claims).not.toBeNull();
    expect(claims?.userId).toBe("user-1");
    expect(claims?.agentClientId).toBe("agent-client-1");
    expect(claims?.grantId).toBe("grant-1");
    expect(claims?.scopes).toEqual(["agent:treasury:read"]);
  });

  it("rejects a garbage token", () => {
    expect(authService.verifyAgentToken("not-a-jwt")).toBeNull();
  });

  it("does not treat a non-agent JWT as an agent token", () => {
    // A JWT signed with the same secret/issuer but WITHOUT token_use:"agent"
    // (mirrors a user access token) must not validate as an agent token.
    const jwt = require("jsonwebtoken");
    const userish = jwt.sign(
      { userId: "user-1", type: "access" },
      process.env.SESSION_SECRET,
      { issuer: "spacechild-auth", expiresIn: 600 },
    );
    expect(authService.verifyAgentToken(userish)).toBeNull();
  });
});
