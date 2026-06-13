/**
 * SpaceChild Auth Types
 * 
 * Type definitions for the authentication module.
 * Ported from space-child-dream auth module but made self-contained.
 */

// ============================================
// DATABASE MODEL TYPES
// ============================================

export interface User {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  profileImageUrl?: string | null;
  passwordHash: string | null;
  zkCredentialHash: string | null;
  isEmailVerified: boolean;
  role: string;
  lastLoginAt: Date | null;
  createdAt: Date | null;
  updatedAt: Date | null;
}

export interface UpsertUser {
  id?: string;
  email?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  profileImageUrl?: string | null;
  passwordHash?: string | null;
  zkCredentialHash?: string | null;
  isEmailVerified?: boolean;
  role?: string;
  lastLoginAt?: Date | null;
}

export interface ZkCredential {
  id: number;
  userId: string;
  credentialType: string;
  publicCommitment: string;
  credentialHash: string;
  issuedAt: Date;
  expiresAt: Date | null;
  isRevoked: boolean;
  metadata?: Record<string, any> | null;
}

export interface InsertZkCredential {
  userId: string;
  credentialType?: string;
  publicCommitment: string;
  credentialHash: string;
  expiresAt?: Date | null;
  isRevoked?: boolean;
  metadata?: Record<string, any> | null;
}

export interface ProofSession {
  id: number;
  sessionId: string;
  userId: string | null;
  challenge: string;
  proofType: string;
  status: string;
  expiresAt: Date;
  verifiedAt: Date | null;
  createdAt: Date;
}

export interface InsertProofSession {
  sessionId: string;
  userId?: string | null;
  challenge: string;
  proofType?: string;
  status?: string;
  expiresAt: Date;
  verifiedAt?: Date | null;
}

export interface RefreshToken {
  id: number;
  userId: string;
  tokenHash: string;
  deviceInfo: string | null;
  subdomain: string | null;
  expiresAt: Date;
  isRevoked: boolean;
  createdAt: Date;
}

export interface InsertRefreshToken {
  userId: string;
  tokenHash: string;
  deviceInfo?: string | null;
  subdomain?: string | null;
  expiresAt: Date;
  isRevoked?: boolean;
}

export interface SubdomainAccess {
  id: number;
  userId: string;
  subdomain: string;
  grantedAt: Date;
  lastAccessAt: Date | null;
  accessLevel: string;
}

export interface InsertSubdomainAccess {
  userId: string;
  subdomain: string;
  lastAccessAt?: Date | null;
  accessLevel?: string;
}

export interface EmailVerificationToken {
  id: number;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  sentAt: Date;
}

export interface InsertEmailVerificationToken {
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  consumedAt?: Date | null;
}

export interface PasswordResetToken {
  id: number;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

export interface InsertPasswordResetToken {
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  consumedAt?: Date | null;
}

// ============================================
// MFA TYPES
// ============================================

export interface MfaMethod {
  id: number;
  userId: string;
  type: string; // 'totp' | 'webauthn'
  name: string;
  isEnabled: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export interface InsertMfaMethod {
  userId: string;
  type: string;
  name: string;
  isEnabled?: boolean;
  lastUsedAt?: Date | null;
}

export interface TotpSecret {
  id: number;
  userId: string;
  encryptedSecret: string;
  backupCodes: string[];
  backupCodesUsed: number[];
  createdAt: Date;
  updatedAt: Date;
}

export interface InsertTotpSecret {
  userId: string;
  encryptedSecret: string;
  backupCodes?: string[];
  backupCodesUsed?: number[];
}

export interface WebauthnCredential {
  id: number;
  userId: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string[];
  aaguid: string | null;
  deviceType: string | null;
  backedUp: boolean;
  name: string;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export interface InsertWebauthnCredential {
  userId: string;
  credentialId: string;
  publicKey: string;
  counter?: number;
  transports?: string[];
  aaguid?: string | null;
  deviceType?: string | null;
  backedUp?: boolean;
  name: string;
  lastUsedAt?: Date | null;
}

export interface MfaChallenge {
  id: number;
  userId: string;
  challenge: string;
  type: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface InsertMfaChallenge {
  userId: string;
  challenge: string;
  type: string;
  expiresAt: Date;
  usedAt?: Date | null;
}

export interface MfaPendingLogin {
  id: number;
  userId: string;
  partialToken: string;
  requiredMethods: string[];
  expiresAt: Date;
  completedAt: Date | null;
  createdAt: Date;
}

export interface InsertMfaPendingLogin {
  userId: string;
  partialToken: string;
  requiredMethods: string[];
  expiresAt: Date;
  completedAt?: Date | null;
}

// ============================================
// PUBLIC USER TYPES
// ============================================

export interface UserPublic {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  profileImageUrl?: string | null;
  role: string;
  isEmailVerified: boolean;
  createdAt: Date | null;
  lastLoginAt?: Date | null;
}

// ============================================
// TOKEN TYPES
// ============================================

export interface SpaceChildTokenPayload {
  userId: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  subdomain?: string;
  type: "access" | "refresh";
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// ============================================
// AUTH RESULT TYPES
// ============================================

export interface AuthResult {
  success: boolean;
  user?: UserPublic;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
  // MFA fields
  requiresMfa?: boolean;
  partialToken?: string;
  availableMethods?: string[];
  mfaExpiresAt?: Date;
}

export interface RegisterResult extends AuthResult {
  requiresVerification?: boolean;
}

export interface LoginResult extends AuthResult {
  requiresVerification?: boolean;
}

// ============================================
// ZK PROOF TYPES
// ============================================

export interface ZKProofRequest {
  sessionId: string;
  challenge: string;
  expiresAt: Date;
}

export interface ZKProof {
  commitment: string;
  response: string;
  publicSignals: string[];
}

export interface ZKProofResponse {
  sessionId: string;
  proof: ZKProof;
}

// ============================================
// SSO TYPES
// ============================================

export interface SsoAuthorizeResult {
  redirectUrl: string;
}

export interface SsoTokenExchangeResult extends AuthResult {
  tokenType?: string;
  expiresIn?: number;
}

// ============================================
// MFA STATUS TYPES
// ============================================

export interface MfaStatus {
  hasMfa: boolean;
  methods: MfaMethod[];
  hasTotp: boolean;
  hasWebauthn: boolean;
  webauthnCredentialCount: number;
}

export interface TotpSetupResult {
  secret: string;
  otpauthUri: string;
  qrCodeUrl: string;
  backupCodes: string[];
}

export interface PendingLoginResult {
  partialToken: string;
  requiresMfa: true;
  availableMethods: string[];
  expiresAt: Date;
}

// ============================================
// RATE LIMITING TYPES
// ============================================

export interface RateLimitEntry {
  attempts: number;
  firstAttempt: number;
  blockedUntil?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remainingSeconds?: number;
  attemptsLeft?: number;
}

// ============================================
// CREDENTIAL TYPES
// ============================================

export interface ZkCredentialInfo {
  id: number;
  type: string;
  issuedAt: Date;
  expiresAt: Date | null;
  isRevoked: boolean;
}

// ============================================
// NOTIFICATION PREFERENCES
// ============================================

export interface NotificationPreferences {
  userId: string;
  notificationEmail: string | null;
  newAppsEnabled: boolean;
  updatesEnabled: boolean;
  marketingEnabled: boolean;
}

export interface InsertNotificationPreferences {
  userId: string;
  notificationEmail?: string | null;
  newAppsEnabled?: boolean;
  updatesEnabled?: boolean;
  marketingEnabled?: boolean;
}

// ============================================
// OAUTH2 CLIENT (read-only view for WARRANT layer)
// ============================================

/**
 * Minimal read view of an oauth2_clients row, used by the agent-delegation
 * (WARRANT) layer to validate ownership and allowed scopes. The oauth2_clients
 * table already exists in the schema; this type is additive.
 */
export interface OAuth2Client {
  id: number;
  clientId: string;
  name: string;
  description: string | null;
  redirectUris: string[];
  allowedScopes: string[];
  allowedGrantTypes: string[];
  isConfidential: boolean;
  isActive: boolean;
  ownerId: string | null;
  createdAt: Date | null;
  updatedAt: Date | null;
}

// ============================================
// AGENT GRANTS (WARRANT layer — ADDITIVE)
// ============================================

export type AgentGrantStatus = "active" | "revoked" | "expired";

/** Per-window rate constraint, e.g. { action: "trade", count: 10, windowSec: 3600 }. */
export interface AgentGrantPerWindow {
  action: string;
  count: number;
  windowSec: number;
}

/** Bounds attached to a delegation that the warrant check enforces. */
export interface AgentGrantConstraints {
  /** Maximum auto-approved impact for an action (units are surface-defined). */
  maxAutoImpact?: number;
  /** Optional per-window rate cap. */
  perWindow?: AgentGrantPerWindow;
  /** Allow forward-compatible extra constraint keys without losing them. */
  [key: string]: unknown;
}

export interface AgentGrant {
  id: string;
  clientId: string;
  userId: string;
  scopes: string[];
  boundWalletAddress: string | null;
  constraints: AgentGrantConstraints | null;
  status: AgentGrantStatus;
  createdAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
}

export interface InsertAgentGrant {
  id?: string;
  clientId: string;
  userId: string;
  scopes: string[];
  boundWalletAddress?: string | null;
  constraints?: AgentGrantConstraints | null;
  status?: AgentGrantStatus;
  expiresAt?: Date | null;
}