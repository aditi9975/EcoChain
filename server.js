// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const connectDB = require('./database/connection');
const logger = require('./utils/logger');

// Import performance optimization middleware
const compressionMiddleware = require('./middleware/compression');
const { cacheMiddleware } = require('./middleware/cache');
const { apiLimiter } = require('./middleware/rateLimiter');

// Import monitoring and logging middleware
const requestLogger = require('./middleware/requestLogger');
const { monitoringMiddleware, healthCheck } = require('./middleware/monitoring');

// Provide development defaults for JWT if not set
process.env.JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
process.env.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_me';
process.env.JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 4002; // Changed from 4001 to 4002 to avoid conflicts

// Create HTTP server
const server = http.createServer(app);

// Initialize WebSocket server with options for production stability
const wss = new WebSocket.Server({ 
  server, 
  path: '/ws',
  // Add options for better production stability
  clientTracking: true,
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024
    },
    // Other options set to defaults
    clientNoContextTakeover: true, // Defaults to negotiated value.
    serverNoContextTakeover: true, // Defaults to negotiated value.
    serverMaxWindowBits: 10, // Defaults to negotiated value.
    concurrencyLimit: 10, // Limits zlib concurrency for perf.
    threshold: 1024 // Size (in bytes) below which messages should not be compressed.
  }
});

// Add WebSocket upgrade handling for better proxy compatibility
server.on('upgrade', (request, socket, head) => {
  // Check if the request is for the WebSocket path
  if (request.url.startsWith('/ws')) {
    // Handle the WebSocket upgrade
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    // Destroy the socket if it's not for WebSocket
    socket.destroy();
  }
});

// Middleware
const { corsOptions, securityHeaders } = require('./config/security');
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://ecochain-j1nj.onrender.com',
    'https://ecochain07.netlify.app',
    'https://*.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400
}));
app.use(compressionMiddleware());
app.use(express.json({ limit: '10mb' })); // Increased limit for image uploads
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Increased limit

// Request logging and monitoring
app.use(requestLogger());
app.use(monitoringMiddleware);

// Apply security headers
app.use((req, res, next) => {
  Object.entries(securityHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });
  next();
});

// Apply global rate limiting to all routes
app.use(apiLimiter);

// Connect to MongoDB
connectDB().catch(err => {
  logger.error('Failed to connect to database:', err);
  logger.warn('Server will continue running without database connection. Some features may not work properly.');
  // In development mode, we'll continue running even without DB connection
  // process.exit(1);
});

// Basic route for testing
app.get('/', (req, res) => {
  res.json({ 
    message: 'Welcome to EcoChain API',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Health check endpoint for monitoring
app.get('/health', healthCheck);

// API routes
const apiRoutes = require('./routes');
// Serve static assets under API for dev proxy compatibility
app.use('/api/assets', express.static('public'));
// Serve product images specifically (this should come before general uploads)
app.use('/uploads/product-images', express.static('public/uploads/product-images'));
// Serve uploaded files with cache control for production
app.use('/uploads', express.static('public/uploads', {
  maxAge: '1d', // Cache for 1 day in production
  etag: true
}));
app.use('/api', apiRoutes);

// Import error handling middleware
const { errorHandler, notFound, asyncHandler } = require('./middleware/errorHandler');

// Error handling middleware (must be after all routes)
app.use(notFound);
app.use(errorHandler);

// Keep track of heartbeat for each client
const heartbeats = new Map();

// WebSocket connection handling
wss.on('connection', (ws, req) => {
  try {
    logger.info('WebSocket connection attempt', { 
      url: req.url,
      origin: req.headers.origin,
      userAgent: req.headers['user-agent']
    });
    
    // Extract token from URL query parameters
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    
    if (!token) {
      logger.warn('WebSocket connection rejected: No authentication token provided');
      ws.close(1008, 'Authentication required');
      return;
    }
    
    // Verify JWT token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        logger.warn('Invalid WebSocket authentication attempt', { error: err.message });
        ws.close(1008, 'Invalid token');
        return;
      }
      
      // Store user info in the WebSocket connection
      ws.userId = decoded.id;
      ws.isAuthenticated = true;
      
      // Initialize heartbeat tracking
      heartbeats.set(ws, Date.now());
      
      logger.info(`WebSocket client connected: ${ws.userId}`);
      
      // Send welcome message
      ws.send(JSON.stringify({
        type: 'connection',
        message: 'Connected to EcoChain sync service',
        timestamp: Date.now()
      }));
      
      // Set up heartbeat timeout check
      const heartbeatCheck = setInterval(() => {
        const lastHeartbeat = heartbeats.get(ws) || 0;
        const now = Date.now();
        
        // If no heartbeat in over 90 seconds, close connection
        if (now - lastHeartbeat > 90000) {
          logger.info(`WebSocket client timeout: ${ws.userId}`);
          clearInterval(heartbeatCheck);
          heartbeats.delete(ws);
          ws.close(1000, 'Connection timeout');
        }
      }, 30000); // Check every 30 seconds
      
      // Clean up on close
      ws.on('close', () => {
        clearInterval(heartbeatCheck);
        heartbeats.delete(ws);
        if (ws.userId) {
          logger.info(`WebSocket client disconnected: ${ws.userId}`, {
            readyState: ws.readyState
          });
        } else {
          logger.info('WebSocket client disconnected: Unauthenticated connection');
        }
      });
    });
  } catch (error) {
    logger.error('WebSocket connection error:', error);
    ws.close(1011, 'Server error');
  }
  
  // Handle incoming messages
  ws.on('message', (message) => {
    try {
      if (!ws.isAuthenticated) {
        logger.warn('Message received from unauthenticated WebSocket connection');
        return;
      }
      
      const data = JSON.parse(message);
      
      // Update heartbeat on any message
      heartbeats.set(ws, Date.now());
      
      // Handle different message types
      switch (data.type) {
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
          break;
          
        case 'subscribe':
          if (Array.isArray(data.entities)) {
            // Store subscriptions for this connection
            ws.subscriptions = data.entities;
            ws.send(JSON.stringify({
              type: 'subscribed',
              entities: data.entities,
              timestamp: Date.now()
            }));
          }
          break;
          
        default:
          logger.warn(`Unknown WebSocket message type: ${data.type}`);
      }
    } catch (error) {
      logger.error('Error handling WebSocket message:', error);
    }
  });
  
  // Handle disconnection
  ws.on('close', (code, reason) => {
    logger.info('WebSocket connection closed', { 
      code, 
      reason: reason.toString(),
      userId: ws.userId 
    });
    
    if (ws.userId) {
      logger.info(`WebSocket client disconnected: ${ws.userId}`);
    }
  });
  
  // Handle errors
  ws.on('error', (error) => {
    logger.error('WebSocket error:', error);
  });
});

// Function to broadcast updates to subscribed clients
global.broadcastUpdate = (entityType, changeType, changes) => {
  const message = JSON.stringify({
    type: 'sync',
    entityType,
    changeType,
    changes,
    timestamp: Date.now()
  });
  
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && 
        client.isAuthenticated && 
        (!client.subscriptions || client.subscriptions.includes(entityType))) {
      try {
        client.send(message);
      } catch (error) {
        logger.error('Error sending WebSocket message:', error);
        // Close the connection if we can't send messages
        client.close(1011, 'Send error');
      }
    }
  });
};

// Start the server
server.listen(PORT, () => {
  logger.info(`Server is running on port ${PORT}`);
  logger.info(`API available at http://localhost:${PORT}/api`);
  logger.info(`WebSocket server available at ws://localhost:${PORT}/ws`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Shutting down WebSocket server...');
  wss.close(() => {
    logger.info('WebSocket server closed');
  });
  
  mongoose.connection.close(() => {
    logger.info('MongoDB connection closed due to app termination');
    process.exit(0);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});