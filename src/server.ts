/**
 * Express Server
 * 
 * Sets up the Express application with middleware, security, and auth routes.
 * Configurable CORS, JSON parsing, security headers, and health checks.
 */

import express from "express";
import cors from "cors";
import helmet from "helmet";
import authRoutes from "./routes";
import agentRoutes from "./agent-routes";

const PORT = parseInt(process.env.PORT || "3100");

// Parse CORS origins from environment
const corsOrigins = process.env.CORS_ORIGINS 
  ? process.env.CORS_ORIGINS.split(",").map(origin => origin.trim())
  : ["https://spacechild.love", "http://localhost:3000"];

/**
 * Create Express application
 */
export function createApp() {
  const app = express();

  // ============================================
  // SECURITY MIDDLEWARE
  // ============================================

  // Security headers
  app.use(helmet({
    crossOriginEmbedderPolicy: false, // Allow iframe embedding if needed
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for emails
        imgSrc: ["'self'", "data:", "https:"], // Allow external images
        connectSrc: ["'self'"], 
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
  }));

  // CORS configuration
  app.use(cors({
    origin: function(origin, callback) {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true);
      
      // Allow any localhost origin in development
      if (process.env.NODE_ENV !== "production" && origin.includes("localhost")) {
        return callback(null, true);
      }
      
      // Check against configured origins
      if (corsOrigins.includes(origin)) {
        return callback(null, true);
      }
      
      console.warn(`CORS rejected origin: ${origin}`);
      callback(new Error(`CORS policy violation: ${origin} not allowed`));
    },
    credentials: true, // Allow cookies/auth headers
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    exposedHeaders: ["X-Total-Count"], // Expose pagination headers if needed
    maxAge: 86400, // Cache preflight for 24 hours
  }));

  // ============================================
  // BODY PARSING
  // ============================================

  // Parse JSON bodies
  app.use(express.json({ 
    limit: "10mb", // Allow reasonable payload sizes
    strict: true,
    type: "application/json"
  }));

  // Parse URL-encoded bodies (for form submissions)
  app.use(express.urlencoded({ 
    extended: true,
    limit: "10mb"
  }));

  // ============================================
  // REQUEST LOGGING
  // ============================================

  // Simple request logging in development
  if (process.env.NODE_ENV !== "production") {
    app.use((req, res, next) => {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] ${req.method} ${req.path} - ${req.ip}`);
      next();
    });
  }

  // ============================================
  // HEALTH CHECK
  // ============================================

  app.get("/health", (req, res) => {
    res.json({ 
      status: "ok", 
      service: "spacechild-auth",
      version: process.env.npm_package_version || "1.0.0",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || "development"
    });
  });

  // Root endpoint with service info
  app.get("/", (req, res) => {
    res.json({
      service: "SpaceChild Auth",
      version: process.env.npm_package_version || "1.0.0",
      description: "Standalone authentication and authorization service for the SpaceChild ecosystem",
      endpoints: {
        health: "/health",
        auth: "/auth/*",
        jwks: "/auth/.well-known/jwks.json",
        docs: "https://github.com/spacechild/auth#readme"
      },
      environment: process.env.NODE_ENV || "development"
    });
  });

  // ============================================
  // AUTH ROUTES
  // ============================================

  // Mount auth routes under /auth prefix
  app.use("/auth", authRoutes);

  // WARRANT layer (ADDITIVE): agent-delegation router under /auth/agents.
  // Registered as a separate sub-router; does not alter existing /auth handlers.
  app.use("/auth/agents", agentRoutes);

  // ============================================
  // ERROR HANDLING
  // ============================================

  // 404 handler
  app.use("*", (req, res) => {
    res.status(404).json({
      error: "Not Found",
      message: `The requested resource ${req.originalUrl} was not found on this server.`,
      service: "spacechild-auth"
    });
  });

  // Global error handler
  app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error("Unhandled error:", error);

    // Don't leak error details in production
    const isDev = process.env.NODE_ENV !== "production";
    
    res.status(error.status || 500).json({
      error: error.name || "Internal Server Error",
      message: isDev ? error.message : "An internal server error occurred",
      ...(isDev && error.stack ? { stack: error.stack } : {}),
      service: "spacechild-auth"
    });
  });

  return app;
}

/**
 * Start the HTTP server
 */
export function startServer() {
  const app = createApp();

  const server = app.listen(PORT, () => {
    console.log(`🚀 SpaceChild Auth server running on port ${PORT}`);
    console.log(`📡 Health check: http://localhost:${PORT}/health`);
    console.log(`🔐 Auth endpoints: http://localhost:${PORT}/auth/*`);
    console.log(`🌍 CORS origins: ${corsOrigins.join(", ")}`);
    console.log(`🛡️  Environment: ${process.env.NODE_ENV || "development"}`);
  });

  // Graceful shutdown handling
  const gracefulShutdown = (signal: string) => {
    console.log(`\n${signal} received. Starting graceful shutdown...`);
    
    server.close((err) => {
      if (err) {
        console.error("Error during server shutdown:", err);
        process.exit(1);
      }
      
      console.log("✅ Server closed successfully");
      process.exit(0);
    });

    // Force exit after 30 seconds
    setTimeout(() => {
      console.log("⚠️  Forced shutdown after 30 seconds");
      process.exit(1);
    }, 30000);
  };

  // Handle shutdown signals
  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));

  // Handle uncaught exceptions
  process.on("uncaughtException", (error) => {
    console.error("Uncaught Exception:", error);
    gracefulShutdown("UNCAUGHT_EXCEPTION");
  });

  process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection at:", promise, "reason:", reason);
    gracefulShutdown("UNHANDLED_REJECTION");
  });

  return server;
}