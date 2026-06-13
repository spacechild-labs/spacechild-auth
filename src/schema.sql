-- ============================================
-- SpaceChild Auth Database Schema
-- Converted from PostgreSQL/Drizzle to MySQL
-- ============================================

-- Enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- ============================================
-- Core Users Table
-- ============================================

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    email VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    profile_image_url VARCHAR(500),
    password_hash TEXT,
    zk_credential_hash TEXT,
    is_email_verified TINYINT(1) DEFAULT 0,
    role TEXT DEFAULT 'user' NOT NULL,
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_users_email (email),
    INDEX idx_users_role (role(20))
);

-- ============================================
-- ZK Credentials
-- ============================================

CREATE TABLE IF NOT EXISTS zk_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    credential_type TEXT NOT NULL DEFAULT 'space_child_identity',
    public_commitment TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NULL,
    is_revoked TINYINT(1) DEFAULT 0,
    metadata JSON,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_zk_credentials_user_id (user_id),
    INDEX idx_zk_credentials_commitment (public_commitment(100))
);

-- ============================================
-- Proof Sessions
-- ============================================

CREATE TABLE IF NOT EXISTS proof_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(36),
    challenge TEXT NOT NULL,
    proof_type TEXT NOT NULL DEFAULT 'auth',
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_proof_sessions_session_id (session_id),
    INDEX idx_proof_sessions_expires_at (expires_at)
);

-- ============================================
-- Refresh Tokens
-- ============================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash TEXT NOT NULL,
    device_info TEXT,
    subdomain TEXT,
    expires_at TIMESTAMP NOT NULL,
    is_revoked TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_refresh_tokens_token_hash (token_hash(255)),
    INDEX idx_refresh_tokens_user_id (user_id),
    INDEX idx_refresh_tokens_expires_at (expires_at)
);

-- ============================================
-- Subdomain Access
-- ============================================

CREATE TABLE IF NOT EXISTS subdomain_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    subdomain TEXT NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_access_at TIMESTAMP NULL,
    access_level TEXT DEFAULT 'user',
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_subdomain_access_user_id (user_id),
    INDEX idx_subdomain_access_subdomain (subdomain(100))
);

-- ============================================
-- Email Verification Tokens
-- ============================================

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP NULL,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_email_verification_tokens_user_id (user_id),
    INDEX idx_email_verification_tokens_expires (expires_at)
);

-- ============================================
-- Password Reset Tokens
-- ============================================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_password_reset_tokens_user_id (user_id),
    INDEX idx_password_reset_tokens_expires (expires_at)
);

-- ============================================
-- OAuth2 Clients
-- ============================================

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(128) UNIQUE NOT NULL,
    client_secret_hash TEXT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris JSON NOT NULL DEFAULT (JSON_ARRAY()),
    allowed_scopes JSON NOT NULL DEFAULT (JSON_ARRAY('openid', 'profile', 'email')),
    allowed_grant_types JSON NOT NULL DEFAULT (JSON_ARRAY('authorization_code', 'refresh_token')),
    is_confidential TINYINT(1) DEFAULT 1 NOT NULL,
    is_active TINYINT(1) DEFAULT 1 NOT NULL,
    owner_id VARCHAR(36),
    logo_uri TEXT,
    policy_uri TEXT,
    tos_uri TEXT,
    contacts JSON DEFAULT (JSON_ARRAY()),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE INDEX idx_oauth2_clients_client_id (client_id),
    INDEX idx_oauth2_clients_owner_id (owner_id),
    INDEX idx_oauth2_clients_is_active (is_active)
);

-- ============================================
-- OAuth2 Authorization Codes
-- ============================================

CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(128) UNIQUE NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    code_challenge TEXT,
    code_challenge_method VARCHAR(10),
    state TEXT,
    nonce TEXT,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_oauth2_auth_codes_code (code),
    INDEX idx_oauth2_auth_codes_client_id (client_id),
    INDEX idx_oauth2_auth_codes_user_id (user_id),
    INDEX idx_oauth2_auth_codes_expires_at (expires_at)
);

-- ============================================
-- OAuth2 Access Tokens
-- ============================================

CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    jti VARCHAR(128) UNIQUE NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(36),
    scopes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    is_revoked TINYINT(1) DEFAULT 0 NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_oauth2_access_tokens_jti (jti),
    INDEX idx_oauth2_access_tokens_client_id (client_id),
    INDEX idx_oauth2_access_tokens_user_id (user_id),
    INDEX idx_oauth2_access_tokens_expires_at (expires_at),
    INDEX idx_oauth2_access_tokens_is_revoked (is_revoked)
);

-- ============================================
-- OAuth2 Refresh Tokens
-- ============================================

CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    jti VARCHAR(128) UNIQUE NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    scopes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    parent_jti VARCHAR(128),
    rotated_at TIMESTAMP NULL,
    is_revoked TINYINT(1) DEFAULT 0 NOT NULL,
    revoked_reason TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_oauth2_refresh_tokens_jti (jti),
    INDEX idx_oauth2_refresh_tokens_client_id (client_id),
    INDEX idx_oauth2_refresh_tokens_user_id (user_id),
    INDEX idx_oauth2_refresh_tokens_parent_jti (parent_jti),
    INDEX idx_oauth2_refresh_tokens_expires_at (expires_at),
    INDEX idx_oauth2_refresh_tokens_is_revoked (is_revoked)
);

-- ============================================
-- OAuth2 Consents
-- ============================================

CREATE TABLE IF NOT EXISTS oauth2_consents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    scopes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_oauth2_consents_user_id (user_id),
    INDEX idx_oauth2_consents_client_id (client_id),
    UNIQUE INDEX idx_oauth2_consents_user_client (user_id, client_id)
);

-- ============================================
-- MFA Methods
-- ============================================

CREATE TABLE IF NOT EXISTS mfa_methods (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    type TEXT NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_enabled TINYINT(1) DEFAULT 1 NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_mfa_methods_user_id (user_id),
    INDEX idx_mfa_methods_type (type(20))
);

-- ============================================
-- TOTP Secrets
-- ============================================

CREATE TABLE IF NOT EXISTS totp_secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) UNIQUE NOT NULL,
    encrypted_secret TEXT NOT NULL,
    backup_codes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    backup_codes_used JSON NOT NULL DEFAULT (JSON_ARRAY()),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_totp_secrets_user_id (user_id)
);

-- ============================================
-- WebAuthn Credentials
-- ============================================

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    counter INT DEFAULT 0 NOT NULL,
    transports JSON DEFAULT (JSON_ARRAY()),
    aaguid VARCHAR(36),
    device_type VARCHAR(50),
    backed_up TINYINT(1) DEFAULT 0,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_webauthn_credentials_user_id (user_id),
    UNIQUE INDEX idx_webauthn_credentials_credential_id (credential_id(255))
);

-- ============================================
-- MFA Challenges
-- ============================================

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    challenge TEXT NOT NULL,
    type TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_mfa_challenges_user_id (user_id),
    INDEX idx_mfa_challenges_type (type(50)),
    INDEX idx_mfa_challenges_expires_at (expires_at)
);

-- ============================================
-- MFA Pending Logins
-- ============================================

CREATE TABLE IF NOT EXISTS mfa_pending_logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    partial_token TEXT UNIQUE NOT NULL,
    required_methods JSON NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_mfa_pending_logins_user_id (user_id),
    UNIQUE INDEX idx_mfa_pending_logins_partial_token (partial_token(255)),
    INDEX idx_mfa_pending_logins_expires_at (expires_at)
);

-- ============================================
-- Sessions (for Express session store if needed)
-- ============================================

CREATE TABLE IF NOT EXISTS sessions (
    sid VARCHAR(255) PRIMARY KEY,
    sess JSON NOT NULL,
    expire TIMESTAMP NOT NULL,
    
    INDEX idx_session_expire (expire)
);

-- ============================================
-- Create default admin user (optional - for testing)
-- ============================================

-- Uncomment to create a default admin user with password "admin123"
-- Password hash is bcrypt of "admin123" with salt rounds 12
/*
INSERT IGNORE INTO users (id, email, first_name, last_name, password_hash, is_email_verified, role) VALUES
('admin-user-id-123', 'admin@spacechild.love', 'Admin', 'User', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfVEqb.2lk5tHgC', 1, 'admin');
*/

-- ============================================
-- Agent Grants (WARRANT layer — ADDITIVE)
-- ============================================
-- A scoped, time-boxed, revocable delegation: an OAuth2 client (the "agent")
-- is authorised to act on behalf of a human owner (user_id) within `scopes`
-- (a subset of the agent-scope catalog and of the client's allowed_scopes)
-- and `constraints` (e.g. maxAutoImpact, per-window rate caps).
--
-- The actual token issuance reuses the existing oauth2_* tables / JWT signing;
-- agent_grants is the delegation record + constraints + revocation that the
-- introspection (warrant check) endpoint consults.
--
-- Note: like oauth2_access_tokens, client_id is indexed (referencing
-- oauth2_clients.client_id) but not hard-FK'd, matching the repo convention.
-- user_id keeps the same ON DELETE CASCADE FK pattern used throughout.

CREATE TABLE IF NOT EXISTS agent_grants (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    client_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    scopes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    bound_wallet_address VARCHAR(42) NULL,
    constraints JSON NULL,
    status ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_agent_grants_user_id (user_id),
    INDEX idx_agent_grants_client_id (client_id),
    INDEX idx_agent_grants_status (status)
);