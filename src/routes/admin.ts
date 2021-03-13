/**
 * express Router middleware for authentication API's admin operations
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import AuthToken from '../datatypes/AuthToken';
import {User, validateNewUserForm} from '../datatypes/User';
import AuthenticationError from '../exceptions/AuthenticationError';
import BadRequestError from '../exceptions/BadRequestError';
import HTTPError from '../exceptions/HTTPError';
import NotFoundError from '../exceptions/NotFoundError';

const adminRouter = express.Router();

// POST /admin/user: Create new user
adminRouter.post(
  '/user',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify admin's access token
      const content: AuthToken = await req.app.locals.accessTokenVerify(req);
      if (content.admin !== true) {
        throw new AuthenticationError();
      }

      // Verify admin's input
      const newUser: User = req.body;
      if (!validateNewUserForm(newUser)) {
        throw new BadRequestError();
      }

      // membersince update
      newUser.membersince = new Date(newUser.membersince);
      newUser.membersince.setMilliseconds(0);
      // Hash Password
      const hashedPassword = req.app.locals.hash(
        newUser.username,
        newUser.membersince.toISOString(),
        newUser.password
      );
      if (newUser.admin !== true) {
        newUser.admin = false;
      }

      // Write to DB
      try {
        await req.app.locals.dbClient.query(
          'INSERT INTO user (username, password, membersince, admin) values (?, ?, ?, ?)',
          [newUser.username, hashedPassword, newUser.membersince, newUser.admin]
        );
      } catch (e) {
        /* istanbul ignore else */
        if (e.code === 'ER_DUP_ENTRY') {
          // Only handles duplicated key error
          throw new HTTPError(400, 'Duplicated Username');
        } else {
          throw e;
        }
      }

      // Response
      res.status(201).send();
    } catch (e) {
      next(e);
    }
  }
);

adminRouter.delete(
  '/user/:username',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify admin's access token
      const content: AuthToken = await req.app.locals.accessTokenVerify(req);
      if (content.admin !== true) {
        throw new AuthenticationError();
      }
      const delTarget = req.params.username; // username that will be deleted

      // Delete From Database
      const queryResult = await req.app.locals.dbClient.query(
        'DELETE FROM user WHERE username = ?',
        [delTarget]
      );
      if (queryResult.affectedRows !== 1) {
        // When user not found
        throw new NotFoundError();
      }

      // Delete Sessions
      await req.app.locals.dbClient.query(
        'DELETE FROM session WHERE username = ?',
        [delTarget]
      );

      // response
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

export default adminRouter;
