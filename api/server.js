// api/server.js - Vercel serverless function
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const connectDB = require('../database/connection');
const logger = require('../utils/logger');

// Provide development defaults for JWT if not set
process.env.JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
process.env.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_me';
process.env.JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

const app = express();

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://ecochain07.netlify.app',
    /\.vercel\.app$/
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400
}));

// Handle preflight CORS requests globally
app.options('*', cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://ecochain07.netlify.app',
    /\.vercel\.app$/
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(morgan('combined', { stream: logger.stream }));

// Security middleware (can be expanded later)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Connect to MongoDB
connectDB().catch(err => {
  logger.error('Failed to connect to database:', err);
  logger.warn('Server will continue running without database connection. Some features may not work properly.');
});

// Basic route for testing
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to EcoChain API',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes
const apiRoutes = require('../routes');
app.use('/api', apiRoutes);

// Import error handling middleware
const { errorHandler, notFound } = require('../middleware/errorHandler');

// Error handling middleware (must be after all routes)
app.use(notFound);
app.use(errorHandler);

// Export for Vercel
module.exports = app;
