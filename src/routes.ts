/**
 * Auth Routes
 *
 * Express routes for authentication endpoints.
 * Ported from space-child-dream auth module with local imports.
 */

import { Router } from "express";
import { z } from "zod";
import { authService } from "./auth-service";
import { mfaService } from "./mfa";
import { authEvents } from "./events";
import {
  isAuthenticated,
  optionalAuth,
  requireAdmin,
  checkAuthRateLimit,
  clearAuthRateLimit,
  isValidSsoCallback,
  getClientIp,
} from "./middleware";
import { storage } from "./storage";

const router = Router();

// ============================================
// VALIDATION SCHEMAS
// ============================================

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

const notificationPreferencesSchema = z.object({
  notificationEmail: z.string().email().optional().nullable(),
  newAppsEnabled: z.boolean().optional(),
  updatesEnabled: z.boolean().optional(),
  marketingEnabled: z.boolean().optional(),
});

const mfaVerifySchema = z.object({
  partialToken: z.string(),
  method: z.string(),
  token: z.string(),
});

// ============================================
// REGISTRATION & LOGIN
// ============================================

router.post("/register", async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0].message });
    }

    const { email, password, firstName, lastName } = parsed.data;
    const result = await authService.register(email, password, firstName, lastName);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    const response: any = {
      success: true,
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
      },
    };

    if (result.accessToken) {
      response.accessToken = result.accessToken;
      response.refreshToken = result.refreshToken;
    }

    if (result.requiresVerification) {
      response.requiresVerification = true;
      response.message = "Please check your email to verify your account before logging in.";
    }

    res.json(response);
  } catch (error: any) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0].message });
    }

    const { email, password } = parsed.data;

    // Rate limit by email and IP
    const clientIp = getClientIp(req);
    const rateLimitKey = `login:${email.toLowerCase()}:${clientIp}`;
    const rateCheck = checkAuthRateLimit(rateLimitKey);

    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: `Too many login attempts. Please try again in ${rateCheck.remainingSeconds} seconds.`,
      });
    }

    const result = await authService.login(email, password, clientIp);

    if (!result.success) {
      return res.status(401).json({
        error: result.error,
        requiresVerification: result.requiresVerification,
      });
    }

    // Clear rate limit on successful login
    clearAuthRateLimit(rateLimitKey);

    // Check if MFA is required
    if (result.requiresMfa) {
      return res.json({
        requiresMfa: true,
        partialToken: result.partialToken,
        availableMethods: result.availableMethods,
        expiresAt: result.mfaExpiresAt,
        user: {
          id: result.user?.id,
          email: result.user?.email,
          firstName: result.user?.firstName,
          lastName: result.user?.lastName,
        },
      });
    }

    res.json({
      success: true,
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error: any) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// ============================================
// MFA ENDPOINTS
// ============================================

router.post("/mfa/verify", async (req, res) => {
  try {
    const parsed = mfaVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0].message });
    }

    const { partialToken, method, token } = parsed.data;

    // Rate-limit MFA verification by IP to prevent TOTP brute-force.
    // The partial token expires in 5 min; without this an attacker with a stolen
    // partialToken could enumerate all 10^6 TOTP codes before expiry.
    const clientIp = getClientIp(req);
    const mfaRateKey = `mfa_verify:${clientIp}`;
    const mfaRateCheck = checkAuthRateLimit(mfaRateKey);
    if (!mfaRateCheck.allowed) {
      return res.status(429).json({
        error: `Too many MFA attempts. Please try again in ${mfaRateCheck.remainingSeconds} seconds.`,
      });
    }

    const result = await mfaService.completeMfaLogin(partialToken, method, token);

    if (result.success) {
      clearAuthRateLimit(mfaRateKey);
    }

    if (!result.success) {
      return res.status(401).json({ error: result.error });
    }

    // Generate full tokens for completed MFA
    const { accessToken, refreshToken } = await authService.generateTokens(result.user!);

    res.json({
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
      },
      accessToken,
      refreshToken,
    });
  } catch (error: any) {
    console.error("MFA verification error:", error);
    res.status(500).json({ error: "MFA verification failed" });
  }
});

router.get("/mfa/status", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const status = await mfaService.getMfaStatus(claims.sub);
    res.json(status);
  } catch (error: any) {
    console.error("Get MFA status error:", error);
    res.status(500).json({ error: "Failed to get MFA status" });
  }
});

router.post("/mfa/totp/setup", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const setup = await mfaService.setupTotp(claims.sub);
    res.json(setup);
  } catch (error: any) {
    console.error("TOTP setup error:", error);
    res.status(500).json({ error: error.message || "Failed to setup TOTP" });
  }
});

router.post("/mfa/totp/verify", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: "TOTP token required" });
    }

    const verified = await mfaService.verifyTotpSetup(claims.sub, token);
    if (verified) {
      res.json({ success: true, message: "TOTP enabled successfully" });
    } else {
      res.status(400).json({ error: "Invalid TOTP token" });
    }
  } catch (error: any) {
    console.error("TOTP verification error:", error);
    res.status(500).json({ error: error.message || "Failed to verify TOTP" });
  }
});

router.delete("/mfa/totp", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    await mfaService.disableTotp(claims.sub);
    res.json({ success: true, message: "TOTP disabled successfully" });
  } catch (error: any) {
    console.error("TOTP disable error:", error);
    res.status(500).json({ error: "Failed to disable TOTP" });
  }
});

// ============================================
// EMAIL VERIFICATION
// ============================================

router.post("/verify-email", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: "Verification token required" });
    }

    const result = await authService.verifyEmail(token);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      message: "Email verified successfully! Welcome to SpaceChild Auth.",
    });
  } catch (error: any) {
    console.error("Email verification error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

router.post("/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }

    const result = await authService.resendVerificationEmail(email);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({
      success: true,
      message: "If an account exists with this email, a verification link has been sent.",
    });
  } catch (error: any) {
    console.error("Resend verification error:", error);
    res.status(500).json({ error: "Failed to resend verification" });
  }
});

// ============================================
// PASSWORD RESET
// ============================================

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }

    await authService.requestPasswordReset(email);

    res.json({
      success: true,
      message: "If an account exists with this email, a password reset link has been sent.",
    });
  } catch (error: any) {
    console.error("Forgot password error:", error);
    res.status(500).json({ error: "Failed to process request" });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      return res.status(400).json({ error: "Token and password required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const result = await authService.resetPassword(token, password);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      message: "Password reset successfully!",
    });
  } catch (error: any) {
    console.error("Reset password error:", error);
    res.status(500).json({ error: "Password reset failed" });
  }
});

// ============================================
// TOKEN OPERATIONS
// ============================================

router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token required" });
    }

    const result = await authService.refreshAccessToken(refreshToken);

    if (!result.success) {
      return res.status(401).json({ error: result.error });
    }

    res.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error: any) {
    console.error("Token refresh error:", error);
    res.status(500).json({ error: "Token refresh failed" });
  }
});

// ============================================
// USER INFO
// ============================================

router.get("/user", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await storage.getUser(claims.sub);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      profileImageUrl: user.profileImageUrl,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    });
  } catch (error: any) {
    console.error("Get user error:", error);
    res.status(500).json({ error: "Failed to get user" });
  }
});

router.post("/logout", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (claims?.sub) {
      await authService.revokeUserTokens(claims.sub, "user");

      // Emit logout event
      authEvents.userLogout({ userId: claims.sub });
    }
    res.json({ success: true });
  } catch (error: any) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Logout failed" });
  }
});

// ============================================
// ZK PROOF OPERATIONS
// ============================================

router.post("/zk/request", async (req, res) => {
  try {
    const proofRequest = await authService.createZkProofRequest();
    res.json(proofRequest);
  } catch (error: any) {
    console.error("ZK proof request error:", error);
    res.status(500).json({ error: error.message || "Failed to create proof request" });
  }
});

router.post("/zk/verify", async (req, res) => {
  try {
    const { sessionId, proof } = req.body;
    if (!sessionId || !proof) {
      return res.status(400).json({ error: "Session ID and proof required" });
    }

    // Rate limit ZKP verification attempts
    const clientIp = getClientIp(req);
    const rateLimitKey = `zkp:${clientIp}`;
    const rateCheck = checkAuthRateLimit(rateLimitKey);

    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: `Too many verification attempts. Please try again in ${rateCheck.remainingSeconds} seconds.`,
      });
    }

    const result = await authService.verifyZkProof({ sessionId, proof }, clientIp);

    if (!result.success) {
      return res.status(401).json({ error: result.error });
    }

    clearAuthRateLimit(rateLimitKey);

    res.json({
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (error: any) {
    console.error("ZK proof verification error:", error);
    res.status(500).json({ error: "Proof verification failed" });
  }
});

// ============================================
// JWKS
// ============================================

router.get("/.well-known/jwks.json", (_req, res) => {
  res.json(authService.getJwksPublicKey());
});

// ============================================
// CREDENTIALS
// ============================================

router.get("/credentials", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const credentials = await storage.getZkCredentialsByUser(claims.sub);
    res.json(credentials.map(c => ({
      id: c.id,
      type: c.credentialType,
      issuedAt: c.issuedAt,
      expiresAt: c.expiresAt,
      isRevoked: c.isRevoked,
    })));
  } catch (error: any) {
    console.error("Get credentials error:", error);
    res.status(500).json({ error: "Failed to get credentials" });
  }
});

// ============================================
// SSO ENDPOINTS
// ============================================

router.get("/sso/authorize", isAuthenticated, async (req, res) => {
  try {
    const { subdomain, callback } = req.query;
    const claims = (req as any).user?.claims;

    if (!subdomain || !callback) {
      return res.status(400).json({ error: "Missing subdomain or callback URL" });
    }

    if (!isValidSsoCallback(callback as string)) {
      console.warn(`SSO callback rejected - untrusted domain: ${callback}`);
      return res.status(400).json({ error: "Invalid callback URL - untrusted domain" });
    }

    if (!claims) {
      return res.redirect(`/?sso_callback=${encodeURIComponent(callback as string)}&subdomain=${subdomain}`);
    }

    const user = await storage.getUser(claims.sub);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Track subdomain access
    const existingAccess = await storage.getSubdomainAccess(user.id, subdomain as string);
    if (!existingAccess) {
      await storage.createSubdomainAccess({
        userId: user.id,
        subdomain: subdomain as string,
        accessLevel: "user",
      });
    } else {
      await storage.updateSubdomainLastAccess(user.id, subdomain as string);
    }

    const authCode = await authService.generateAuthorizationCode(user.id, subdomain as string);

    const callbackUrl = new URL(callback as string);
    callbackUrl.searchParams.set("code", authCode);
    callbackUrl.searchParams.set("subdomain", subdomain as string);

    res.redirect(callbackUrl.toString());
  } catch (error: any) {
    console.error("SSO authorize error:", error);
    res.status(500).json({ error: "SSO authorization failed" });
  }
});

router.post("/sso/token", async (req, res) => {
  try {
    const clientIp = getClientIp(req);
    const rateLimitResult = checkAuthRateLimit(`sso_token:${clientIp}`);
    if (!rateLimitResult.allowed) {
      return res.status(429).json({
        error: "Too many requests",
        retryAfter: rateLimitResult.remainingSeconds,
      });
    }

    const { code, subdomain } = req.body;

    if (!code) {
      return res.status(400).json({ error: "Authorization code required" });
    }

    if (!subdomain) {
      return res.status(400).json({ error: "Subdomain required" });
    }

    const result = await authService.exchangeAuthorizationCode(code, subdomain);

    if (!result.success) {
      return res.status(401).json({ error: result.error });
    }

    res.json({
      access_token: result.accessToken,
      refresh_token: result.refreshToken,
      token_type: "Bearer",
      expires_in: 900,
      user: {
        id: result.user!.id,
        email: result.user!.email,
        firstName: result.user!.firstName,
        lastName: result.user!.lastName,
      },
    });
  } catch (error: any) {
    console.error("SSO token exchange error:", error);
    res.status(500).json({ error: "Token exchange failed" });
  }
});

router.post("/sso/verify", async (req, res) => {
  try {
    const { token, subdomain } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Token required" });
    }

    const payload = await authService.verifyAccessToken(token);
    if (!payload) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (subdomain && payload.subdomain && payload.subdomain !== subdomain) {
      return res.status(403).json({ error: "Token not valid for this subdomain" });
    }

    res.json({
      valid: true,
      userId: payload.userId,
      email: payload.email,
      firstName: payload.firstName,
      lastName: payload.lastName,
      subdomain: payload.subdomain,
    });
  } catch (error: any) {
    console.error("SSO verify error:", error);
    res.status(500).json({ error: "Token verification failed" });
  }
});

// ============================================
// ADMIN ENDPOINTS
// ============================================

router.get("/admin/users", isAuthenticated, requireAdmin, async (req, res) => {
  try {
    const users = await storage.getAllUsers();
    res.json(users.map(u => ({
      id: u.id,
      email: u.email,
      firstName: u.firstName,
      lastName: u.lastName,
      isEmailVerified: u.isEmailVerified,
      role: u.role,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt,
    })));
  } catch (error: any) {
    console.error("Get users error:", error);
    res.status(500).json({ error: "Failed to get users" });
  }
});

router.post("/admin/users/:userId/revoke-tokens", isAuthenticated, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    await authService.revokeUserTokens(userId, "admin");
    res.json({ success: true, message: "All user tokens revoked" });
  } catch (error: any) {
    console.error("Revoke tokens error:", error);
    res.status(500).json({ error: "Failed to revoke tokens" });
  }
});

// ============================================
// NOTIFICATION PREFERENCES
// ============================================

router.get("/notification-preferences", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const prefs = await storage.getNotificationPreferences(claims.sub);
    const user = await storage.getUser(claims.sub);

    res.json({
      notificationEmail: prefs?.notificationEmail || user?.email || null,
      newAppsEnabled: prefs?.newAppsEnabled ?? true,
      updatesEnabled: prefs?.updatesEnabled ?? true,
      marketingEnabled: prefs?.marketingEnabled ?? false,
      accountEmail: user?.email || null,
    });
  } catch (error: any) {
    console.error("Get notification preferences error:", error);
    res.status(500).json({ error: "Failed to get notification preferences" });
  }
});

router.put("/notification-preferences", isAuthenticated, async (req, res) => {
  try {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const parsed = notificationPreferencesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0].message });
    }

    const { notificationEmail, newAppsEnabled, updatesEnabled, marketingEnabled } = parsed.data;

    const prefs = await storage.upsertNotificationPreferences({
      userId: claims.sub,
      notificationEmail: notificationEmail || null,
      newAppsEnabled: newAppsEnabled ?? true,
      updatesEnabled: updatesEnabled ?? true,
      marketingEnabled: marketingEnabled ?? false,
    });

    res.json({
      success: true,
      preferences: {
        notificationEmail: prefs.notificationEmail,
        newAppsEnabled: prefs.newAppsEnabled,
        updatesEnabled: prefs.updatesEnabled,
        marketingEnabled: prefs.marketingEnabled,
      },
    });
  } catch (error: any) {
    console.error("Update notification preferences error:", error);
    res.status(500).json({ error: "Failed to update notification preferences" });
  }
});

export default router;