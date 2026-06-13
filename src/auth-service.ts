/**
 * SpaceChild Auth Service
 *
 * Core authentication logic ported from space-child-dream auth module.
 * Provides clean interface for authentication operations with ZKP support.
 */

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { storage } from "./storage";
import { sendVerificationEmail, sendPasswordResetEmail, sendWelcomeEmail } from "./email";
import { authEvents } from "./events";
import type {
  UserPublic,
  SpaceChildTokenPayload,
  AuthResult,
  RegisterResult,
  LoginResult,
  TokenPair,
  ZKProofRequest,
  ZKProofResponse,
} from "./types";

// ============================================
// CONSTANTS
// ============================================

const JWT_ISSUER = "spacechild-auth";
const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";
const EMAIL_VERIFICATION_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours
const PASSWORD_RESET_EXPIRY = 15 * 60 * 1000; // 15 minutes

// ============================================
// PRIVATE STATE
// ============================================

const envSecret: string = process.env.SESSION_SECRET || "";
if (!envSecret) {
  console.error("FATAL: SESSION_SECRET environment variable is required. Exiting.");
  console.error("Please set SESSION_SECRET to a secure random string (min 32 characters).");
  process.exit(1);
}

let poseidonHash: any = null;

// ============================================
// PRIVATE HELPERS
// ============================================

function getJwtSecret(): string {
  return envSecret;
}

async function getPoseidon() {
  if (!poseidonHash) {
    try {
      const { buildPoseidon } = await import("circomlibjs");
      poseidonHash = await buildPoseidon();
    } catch (error) {
      console.warn("⚠️ circomlibjs not available - ZKP features disabled. This may happen on ARM systems.");
      console.warn("ZK proof operations will return errors.");
      poseidonHash = null;
    }
  }
  return poseidonHash;
}

// ============================================
// AUTH SERVICE CLASS
// ============================================

class AuthService {
  private static instance: AuthService;
  private authorizationCodes: Map<string, { userId: string; subdomain: string; expiresAt: number }> = new Map();

  private constructor() {}

  static getInstance(): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService();
    }
    return AuthService.instance;
  }

  // ============================================
  // PASSWORD OPERATIONS
  // ============================================

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  // ============================================
  // ZK CREDENTIAL OPERATIONS
  // ============================================

  async generateZkCredential(userId: string, secretData: string): Promise<{ commitment: string; credentialHash: string }> {
    const poseidon = await getPoseidon();
    if (!poseidon) {
      throw new Error("ZK proof functionality is not available. circomlibjs may not be compatible with this system.");
    }

    const encoder = new TextEncoder();
    const secretBytes = encoder.encode(secretData);
    const secretBigInt = BigInt("0x" + Buffer.from(secretBytes).toString("hex").slice(0, 62));
    const saltBigInt = BigInt("0x" + Buffer.from(uuidv4().replace(/-/g, "")).toString("hex"));
    const commitment = poseidon.F.toString(poseidon([secretBigInt, saltBigInt]));
    const credentialHash = poseidon.F.toString(poseidon([BigInt(commitment), BigInt("0x" + userId.replace(/-/g, "").slice(0, 30))]));
    return { commitment, credentialHash };
  }

  // ============================================
  // REGISTRATION
  // ============================================

  async register(
    email: string,
    password: string,
    firstName?: string,
    lastName?: string
  ): Promise<RegisterResult> {
    try {
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return { success: false, error: "Email already registered" };
      }

      const passwordHash = await this.hashPassword(password);
      const userId = uuidv4();

      // Skip email verification when SMTP is not configured
      const skipVerification = !process.env.SMTP_HOST;

      // Insert user FIRST (ZK credentials have a FK to users)
      const user = await storage.upsertUser({
        id: userId,
        email,
        firstName: firstName || null,
        lastName: lastName || null,
        passwordHash,
        zkCredentialHash: null,
        isEmailVerified: skipVerification,
      });
      
      // Now create ZK credential (user exists, FK satisfied)
      try {
        const { commitment, credentialHash } = await this.generateZkCredential(userId, password + email);

        await storage.createZkCredential({
          userId: userId,
          credentialType: "space_child_identity",
          publicCommitment: commitment,
          credentialHash,
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        });

        // Update user with ZK hash
        await storage.updateUser(userId, { zkCredentialHash: credentialHash });
      } catch (zkError) {
        console.warn("ZK credential creation failed, continuing without ZKP support:", zkError);
      }

      if (!skipVerification) {
        // Generate verification token and send email
        const verificationToken = uuidv4();
        const tokenHash = await this.hashPassword(verificationToken);
        await storage.createEmailVerificationToken({
          userId: user.id,
          tokenHash,
          expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_EXPIRY),
        });

        await sendVerificationEmail(email, verificationToken, firstName);
      }

      // Emit registration event
      authEvents.userRegistered({
        userId: user.id,
        email,
        firstName: firstName || undefined,
        lastName: lastName || undefined,
      });

      // Auto-login if verification is skipped
      if (skipVerification) {
        const { accessToken, refreshToken } = await this.generateTokens(user);
        return {
          success: true,
          user: this.mapUser(user),
          accessToken,
          refreshToken,
        };
      }

      return {
        success: true,
        user: this.mapUser(user),
        requiresVerification: true,
      };
    } catch (error: any) {
      console.error("Registration error:", error);
      return { success: false, error: error.message || "Registration failed" };
    }
  }

  // ============================================
  // LOGIN
  // ============================================

  async login(email: string, password: string, ip?: string): Promise<LoginResult> {
    try {
      const user = await storage.getUserByEmail(email);
      if (!user) {
        return { success: false, error: "Invalid email or password" };
      }

      if (!user.passwordHash) {
        return { success: false, error: "Account requires password reset" };
      }

      const isValid = await this.verifyPassword(password, user.passwordHash);
      if (!isValid) {
        return { success: false, error: "Invalid email or password" };
      }

      // Block login for unverified users
      if (!user.isEmailVerified) {
        return {
          success: false,
          error: "Please verify your email before logging in. Check your inbox for the verification link.",
          requiresVerification: true,
          user: this.mapUser(user),
        };
      }

      // Check if user has MFA enabled
      try {
        const mfaModule = await import("./mfa");
        const { mfaService } = mfaModule;
        const requiresMfa = await mfaService.userRequiresMfa(user.id);

        if (requiresMfa) {
          // Create pending login and return partial token
          const pendingLogin = await mfaService.createPendingLogin(user);

          return {
            success: true,
            user: this.mapUser(user),
            requiresMfa: true,
            partialToken: pendingLogin.partialToken,
            availableMethods: pendingLogin.availableMethods,
            mfaExpiresAt: pendingLogin.expiresAt,
          };
        }
      } catch (mfaError) {
        console.warn("MFA check failed, continuing without MFA:", mfaError);
      }

      await storage.updateUser(user.id, { lastLoginAt: new Date() });
      const { accessToken, refreshToken } = await this.generateTokens(user);

      // Emit login event
      authEvents.userLogin({
        userId: user.id,
        email: user.email || "",
        method: "password",
        ip: ip || undefined,
      });

      return {
        success: true,
        user: this.mapUser(user),
        accessToken,
        refreshToken,
      };
    } catch (error: any) {
      console.error("Login error:", error);
      return { success: false, error: error.message || "Login failed" };
    }
  }

  // ============================================
  // TOKEN OPERATIONS
  // ============================================

  async generateTokens(user: any, subdomain?: string): Promise<TokenPair> {
    const accessPayload: SpaceChildTokenPayload = {
      userId: user.id,
      email: user.email || null,
      firstName: user.firstName || null,
      lastName: user.lastName || null,
      subdomain: subdomain || undefined,
      type: "access",
    };

    const refreshPayload: SpaceChildTokenPayload = {
      userId: user.id,
      email: user.email || null,
      firstName: user.firstName || null,
      lastName: user.lastName || null,
      subdomain: subdomain || undefined,
      type: "refresh",
    };

    const accessToken = jwt.sign(accessPayload, getJwtSecret(), {
      expiresIn: ACCESS_TOKEN_EXPIRY,
      issuer: JWT_ISSUER,
    });

    const refreshToken = jwt.sign(refreshPayload, getJwtSecret(), {
      expiresIn: REFRESH_TOKEN_EXPIRY,
      issuer: JWT_ISSUER,
    });

    const refreshTokenHash = await this.hashPassword(refreshToken);
    await storage.createRefreshToken({
      userId: user.id,
      tokenHash: refreshTokenHash,
      subdomain: subdomain || null,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return { accessToken, refreshToken };
  }

  async verifyAccessToken(token: string): Promise<SpaceChildTokenPayload | null> {
    try {
      const payload = jwt.verify(token, getJwtSecret(), {
        issuer: JWT_ISSUER,
      }) as SpaceChildTokenPayload;

      if (payload.type !== "access") {
        return null;
      }

      return payload;
    } catch {
      return null;
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<AuthResult> {
    try {
      if (!refreshToken) {
        return { success: false, error: "Refresh token required" };
      }

      const payload = jwt.verify(refreshToken, getJwtSecret(), {
        issuer: JWT_ISSUER,
      }) as SpaceChildTokenPayload;

      if (payload.type !== "refresh") {
        return { success: false, error: "Invalid token type" };
      }

      const user = await storage.getUser(payload.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      const storedTokens = await storage.getRefreshTokensByUser(payload.userId);
      let validToken = false;
      let matchedTokenId: number | undefined;

      for (const storedToken of storedTokens) {
        if (storedToken.isRevoked) continue;
        if (new Date() > storedToken.expiresAt) continue;

        const isMatch = await this.verifyPassword(refreshToken, storedToken.tokenHash);
        if (isMatch) {
          validToken = true;
          matchedTokenId = storedToken.id;
          break;
        }
      }

      if (!validToken) {
        return { success: false, error: "Refresh token revoked or invalid" };
      }

      if (matchedTokenId) {
        await storage.revokeRefreshToken(matchedTokenId);
      }

      const tokens = await this.generateTokens(user, payload.subdomain);

      // Emit token refresh event
      authEvents.tokenRefreshed({ userId: user.id });

      return {
        success: true,
        user: this.mapUser(user),
        ...tokens,
      };
    } catch {
      return { success: false, error: "Invalid or expired refresh token" };
    }
  }

  async revokeUserTokens(userId: string, revokedBy: "user" | "admin" | "system" = "system"): Promise<void> {
    await storage.revokeAllUserRefreshTokens(userId);
    authEvents.tokenRevoked({ userId, revokedBy });
  }

  // ============================================
  // ZK PROOF OPERATIONS
  // ============================================

  async createZkProofRequest(userId?: string): Promise<ZKProofRequest> {
    const sessionId = uuidv4();
    const challenge = uuidv4() + "-" + Date.now().toString(36);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await storage.createProofSession({
      sessionId,
      userId: userId || null,
      challenge,
      proofType: "auth",
      status: "pending",
      expiresAt,
    });

    return { sessionId, challenge, expiresAt };
  }

  async verifyZkProof(proofResponse: ZKProofResponse, ip?: string): Promise<AuthResult> {
    try {
      const poseidon = await getPoseidon();
      if (!poseidon) {
        return { success: false, error: "ZK proof functionality is not available" };
      }

      const session = await storage.getProofSession(proofResponse.sessionId);
      if (!session) {
        return { success: false, error: "Invalid proof session" };
      }

      if (session.status !== "pending") {
        return { success: false, error: "Proof session already used" };
      }

      if (new Date() > session.expiresAt) {
        return { success: false, error: "Proof session expired" };
      }

      const challengeHash = poseidon.F.toString(
        poseidon([BigInt("0x" + Buffer.from(session.challenge).toString("hex").slice(0, 62))])
      );

      const expectedResponse = poseidon.F.toString(
        poseidon([BigInt(proofResponse.proof.commitment), BigInt(challengeHash)])
      );

      const credential = await storage.getZkCredentialByCommitment(proofResponse.proof.commitment);
      if (!credential) {
        return { success: false, error: "Invalid proof - credential not found" };
      }

      if (credential.isRevoked) {
        return { success: false, error: "Credential has been revoked" };
      }

      if (credential.expiresAt && new Date() > credential.expiresAt) {
        return { success: false, error: "Credential has expired" };
      }

      if (proofResponse.proof.response !== expectedResponse) {
        return { success: false, error: "Proof verification failed" };
      }

      const user = await storage.getUser(credential.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      if (!user.isEmailVerified) {
        return { success: false, error: "Please verify your email before using ZKP authentication" };
      }

      await storage.updateProofSession(session.id, {
        status: "verified",
        userId: user.id,
        verifiedAt: new Date(),
      });

      const { accessToken, refreshToken } = await this.generateTokens(user);

      // Emit login event
      authEvents.userLogin({
        userId: user.id,
        email: user.email || "",
        method: "zkp",
        ip: ip || undefined,
      });

      return { success: true, user: this.mapUser(user), accessToken, refreshToken };
    } catch (error: any) {
      console.error("ZK proof verification error:", error);
      return { success: false, error: error.message || "Proof verification failed" };
    }
  }

  // ============================================
  // EMAIL VERIFICATION
  // ============================================

  async verifyEmail(token: string): Promise<AuthResult> {
    try {
      const result = await this.findUserByVerificationToken(token);
      if (!result) {
        return { success: false, error: "Invalid or expired verification link" };
      }

      const { user, tokenRecord } = result;

      await storage.updateUser(user.id, { isEmailVerified: true });
      await storage.consumeEmailVerificationToken(tokenRecord.id);

      await sendWelcomeEmail(user.email!, user.firstName || undefined);

      const { accessToken, refreshToken } = await this.generateTokens(user);

      // Emit verification event
      authEvents.userVerified({
        userId: user.id,
        email: user.email!,
      });

      return {
        success: true,
        user: { ...this.mapUser(user), isEmailVerified: true },
        accessToken,
        refreshToken,
      };
    } catch (error: any) {
      console.error("Email verification error:", error);
      return { success: false, error: error.message || "Verification failed" };
    }
  }

  private async findUserByVerificationToken(token: string): Promise<{ user: any; tokenRecord: any } | null> {
    const tokens = await storage.findActiveVerificationTokens();

    for (const tokenRecord of tokens) {
      const isMatch = await this.verifyPassword(token, tokenRecord.tokenHash);
      if (isMatch) {
        const user = await storage.getUser(tokenRecord.userId);
        if (user) {
          return { user, tokenRecord };
        }
      }
    }
    return null;
  }

  async resendVerificationEmail(email: string): Promise<{ success: boolean; error?: string }> {
    try {
      const user = await storage.getUserByEmail(email);
      if (!user) {
        return { success: true };
      }

      if (user.isEmailVerified) {
        return { success: false, error: "Email is already verified" };
      }

      await storage.invalidateUserVerificationTokens(user.id);

      const verificationToken = uuidv4();
      const tokenHash = await this.hashPassword(verificationToken);
      await storage.createEmailVerificationToken({
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_EXPIRY),
      });

      await sendVerificationEmail(email, verificationToken, user.firstName || undefined);

      return { success: true };
    } catch (error: any) {
      console.error("Resend verification error:", error);
      return { success: false, error: error.message || "Failed to resend verification" };
    }
  }

  // ============================================
  // PASSWORD RESET
  // ============================================

  async requestPasswordReset(email: string): Promise<{ success: boolean; error?: string }> {
    try {
      const user = await storage.getUserByEmail(email);
      if (!user) {
        return { success: true };
      }

      await storage.invalidateUserPasswordResetTokens(user.id);

      const resetToken = uuidv4();
      const tokenHash = await this.hashPassword(resetToken);
      await storage.createPasswordResetToken({
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + PASSWORD_RESET_EXPIRY),
      });

      await sendPasswordResetEmail(email, resetToken, user.firstName || undefined);

      return { success: true };
    } catch (error: any) {
      console.error("Password reset request error:", error);
      return { success: false, error: error.message || "Failed to send reset email" };
    }
  }

  async resetPassword(token: string, newPassword: string): Promise<AuthResult> {
    try {
      if (newPassword.length < 8) {
        return { success: false, error: "Password must be at least 8 characters" };
      }

      const result = await this.findUserByResetToken(token);
      if (!result) {
        return { success: false, error: "Invalid or expired reset link" };
      }

      const { user, tokenRecord } = result;

      const passwordHash = await this.hashPassword(newPassword);
      await storage.updateUser(user.id, { passwordHash });

      await storage.consumePasswordResetToken(tokenRecord.id);
      await storage.revokeAllUserRefreshTokens(user.id);

      if (!user.isEmailVerified) {
        await storage.updateUser(user.id, { isEmailVerified: true });
      }

      const { accessToken, refreshToken } = await this.generateTokens(user);

      // Emit password reset event
      authEvents.passwordReset({
        userId: user.id,
        email: user.email!,
      });

      return {
        success: true,
        user: this.mapUser(user),
        accessToken,
        refreshToken,
      };
    } catch (error: any) {
      console.error("Password reset error:", error);
      return { success: false, error: error.message || "Password reset failed" };
    }
  }

  private async findUserByResetToken(token: string): Promise<{ user: any; tokenRecord: any } | null> {
    const tokens = await storage.findActiveResetTokens();

    for (const tokenRecord of tokens) {
      const isMatch = await this.verifyPassword(token, tokenRecord.tokenHash);
      if (isMatch) {
        const user = await storage.getUser(tokenRecord.userId);
        if (user) {
          return { user, tokenRecord };
        }
      }
    }
    return null;
  }

  // ============================================
  // SSO OPERATIONS
  // ============================================

  async generateAuthorizationCode(userId: string, subdomain: string): Promise<string> {
    const now = Date.now();
    const expiredCodes: string[] = [];
    this.authorizationCodes.forEach((data, code) => {
      if (data.expiresAt < now) {
        expiredCodes.push(code);
      }
    });
    expiredCodes.forEach(code => this.authorizationCodes.delete(code));

    const code = uuidv4() + "-" + uuidv4();
    const expiresAt = now + 60 * 1000;

    this.authorizationCodes.set(code, { userId, subdomain, expiresAt });

    return code;
  }

  async exchangeAuthorizationCode(code: string, subdomain: string): Promise<AuthResult> {
    try {
      const codeData = this.authorizationCodes.get(code);

      if (!codeData) {
        return { success: false, error: "Invalid or expired authorization code" };
      }

      this.authorizationCodes.delete(code);

      if (codeData.expiresAt < Date.now()) {
        return { success: false, error: "Authorization code expired" };
      }

      if (codeData.subdomain !== subdomain) {
        return { success: false, error: "Subdomain mismatch" };
      }

      const user = await storage.getUser(codeData.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      const { accessToken, refreshToken } = await this.generateTokens(user, subdomain);

      // Emit login event
      authEvents.userLogin({
        userId: user.id,
        email: user.email || "",
        method: "sso",
      });

      return {
        success: true,
        user: this.mapUser(user),
        accessToken,
        refreshToken,
      };
    } catch (error: any) {
      console.error("Authorization code exchange error:", error);
      return { success: false, error: error.message || "Code exchange failed" };
    }
  }

  // ============================================
  // AGENT DELEGATION TOKENS (WARRANT layer — ADDITIVE)
  // ============================================

  /**
   * Mint a scoped, time-boxed JWT for a delegated agent (an OAuth2 client acting
   * on behalf of a human owner). ADDITIVE: reuses the existing HS256 signing
   * secret and issuer; does not touch the user access/refresh token flow.
   *
   * The token carries:
   *   sub             — the human owner's user id
   *   agent_client_id — the agent's OAuth2 client_id
   *   grant_id        — the delegation record id
   *   scopes          — the granted agent scopes
   *   token_use       — "agent" (so it can never be mistaken for a user access token)
   */
  mintAgentToken(params: {
    userId: string;
    agentClientId: string;
    grantId: string;
    scopes: string[];
    expiresInSec: number;
  }): { token: string; expiresIn: number } {
    const expiresIn = Math.max(1, Math.floor(params.expiresInSec));
    const token = jwt.sign(
      {
        sub: params.userId,
        agent_client_id: params.agentClientId,
        grant_id: params.grantId,
        scopes: params.scopes,
        token_use: "agent",
      },
      getJwtSecret(),
      {
        expiresIn,
        issuer: JWT_ISSUER,
      }
    );
    return { token, expiresIn };
  }

  /**
   * Verify an agent token minted by `mintAgentToken`. Returns the decoded
   * delegation claims, or null if invalid/expired or not an agent token.
   */
  verifyAgentToken(token: string): {
    userId: string;
    agentClientId: string;
    grantId: string;
    scopes: string[];
  } | null {
    try {
      const payload = jwt.verify(token, getJwtSecret(), {
        issuer: JWT_ISSUER,
      }) as any;

      if (payload.token_use !== "agent") {
        return null;
      }
      if (!payload.sub || !payload.grant_id || !payload.agent_client_id) {
        return null;
      }

      return {
        userId: payload.sub,
        agentClientId: payload.agent_client_id,
        grantId: payload.grant_id,
        scopes: Array.isArray(payload.scopes) ? payload.scopes : [],
      };
    } catch {
      return null;
    }
  }

  // ============================================
  // JWKS
  // ============================================

  getJwksPublicKey(): object {
    return {
      keys: [
        {
          kty: "oct",
          kid: "spacechild-auth-key-1",
          alg: "HS256",
          use: "sig",
        },
      ],
    };
  }

  // ============================================
  // HELPERS
  // ============================================

  private mapUser(dbUser: any): UserPublic {
    return {
      id: dbUser.id,
      email: dbUser.email,
      firstName: dbUser.firstName,
      lastName: dbUser.lastName,
      profileImageUrl: dbUser.profileImageUrl,
      role: dbUser.role,
      isEmailVerified: dbUser.isEmailVerified,
      createdAt: dbUser.createdAt,
      lastLoginAt: dbUser.lastLoginAt,
    };
  }
}

// Export singleton instance
export const authService = AuthService.getInstance();

// Export class for testing
export { AuthService };
