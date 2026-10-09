import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import { apiRouter } from './server/api/routes.js';
import { DataStore } from './server/db/store.js';
import { SandboxManager } from './server/sandbox/manager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Initialize data store and sandbox temp base
  DataStore.initialize();
  SandboxManager.initialize();

  // Middleware
  app.use(express.json({ limit: '20mb' }));

  // Mount API Router
  app.use('/api', apiRouter);

  // In production, serve dist folder. In dev, attach Vite middleware.
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        watch: null,
        hmr: false,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SandTrace] Security Observatory Server active at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[SandTrace] Failed to start server:', err);
  process.exit(1);
});
