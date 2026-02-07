/**
 * Express Server Configuration
 * 
 * Backend API for npm package security analysis
 */

const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5050;

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors());
app.use(express.json({ limit: '50mb' })); // Support large file uploads
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ============================================
// ROUTES
// ============================================

const analyzeRoutes = require('./routes/analyze.route');
const rulesRoutes = require('./routes/rules.route');

app.use('/api', analyzeRoutes);
app.use('/api/rules', rulesRoutes);

// ============================================
// ROOT ENDPOINT
// ============================================

app.get('/', (req, res) => {
  res.json({
    service: 'NPM Package Security Analysis API',
    version: '2.0.0',
    status: 'operational',
    endpoints: {
      analysis: {
        main: 'POST /api/analyze',
        listRules: 'GET /api/analyze/rules'
      },
      rules: {
        list: 'GET /api/rules',
        info: 'GET /api/rules/:ruleId',
        execute: 'POST /api/rules/:ruleId'
      }
    },
    documentation: 'https://github.com/your-repo/api-docs',
    examples: {
      analyzeByName: {
        endpoint: 'POST /api/analyze',
        body: {
          packageName: 'express',
          tier: 'standard'
        }
      },
      analyzeByUpload: {
        endpoint: 'POST /api/analyze',
        body: {
          files: [
            { path: 'index.js', content: 'console.log("test");' }
          ],
          packageJson: {
            name: 'my-package',
            version: '1.0.0'
          },
          tier: 'quick'
        }
      },
      runSingleRule: {
        endpoint: 'POST /api/rules/1',
        body: {
          files: [
            { path: 'index.js', content: 'eval("malicious")' }
          ]
        }
      }
    }
  });
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
    }
  });
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path,
    method: req.method,
    hint: 'Visit GET / for API documentation'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log('╔════════════════════════════════════════╗');
  console.log('║  NPM Security Analysis API             ║');
  console.log('╠════════════════════════════════════════╣');
  console.log(`║  Server running on port ${PORT}         ║`);
  console.log(`║  Environment: ${process.env.NODE_ENV || 'development'}              ║`);
  console.log('╠════════════════════════════════════════╣');
  console.log('║  Endpoints:                            ║');
  console.log('║    POST /api/analyze                   ║');
  console.log('║    GET  /api/analyze/rules             ║');
  console.log('║    GET  /api/rules                     ║');
  console.log('║    POST /api/rules/:ruleId             ║');
  console.log('╚════════════════════════════════════════╝');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

module.exports = app;