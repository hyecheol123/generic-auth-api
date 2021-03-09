/**
 * Starting express application middleware for generic-auth-api project
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import {Server} from 'http';
import ExpressServer from './ExpressServer';
import ServerConfig from './ServerConfig';

const configInstance = new ServerConfig(); // Configuration of the server
const expressServer = new ExpressServer(configInstance); // express server setup

// Startup the express server
const {app} = expressServer;
const server: Server = app.listen(configInstance.expressPort);
console.log(`Start Auth API Server at port ${configInstance.expressPort}`);

// Gracefully shutdown express server
const shutdown = async (): Promise<void> => {
  // Close database connection
  await expressServer.closeDB();

  // Close API Server
  server.close(() => {
    console.log('Shutdown Auth API Server');
    // eslint-disable-next-line no-process-exit
    process.exit(0);
  });
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
