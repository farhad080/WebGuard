import { configureServerTimeouts, createApp } from './app.js';
import { config } from './config.js';

// Fail fast on missing secrets.
void config.jwtSecret;

const server = createApp().listen(config.port, () => {
  console.log(`WebGuard API listening on http://localhost:${config.port}`);
});
configureServerTimeouts(server);
