/**
 * express Router middleware for authentication API's alive checks
 * Used for Kubernetes liveness/readiness proves
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import dbCheck from '../datatypes/dbCheck';
import HTTPError from '../exceptions/HTTPError';

const aliveRouter = express.Router();

// GET /alive: Check for server alive (liveness)
aliveRouter.get('/', (_req: express.Request, res: express.Response) => {
  // If Server not alive, no response will send
  res.status(200).send();
});

// GET /alive/ready: Check whether server ready to handle requests (readiness)
aliveRouter.get(
  '/ready',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Check DB Connection
      const result = await dbCheck(req.app.locals.dbClient);

      /* istanbul ignore else */
      if (result) {
        res.status(200).send();
      } else {
        throw new HTTPError(500, 'DB Connection Fail - Not Ready');
      }
    } /* istanbul ignore next */ catch (e) {
      next(e);
    }
  }
);

export default aliveRouter;
