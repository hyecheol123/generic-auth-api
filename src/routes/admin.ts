/**
 * express Router middleware for admin operations of authentication API
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import AuthToken from '../datatypes/AuthToken';
import {NewUserForm, validateNewUserForm} from '../datatypes/NewUserForm';
import AuthenticationError from '../exceptions/AuthenticationError';
import BadRequestError from '../exceptions/BadRequestError';

const adminRouter = express.Router();

// POST /admin/users: Add new user
adminRouter.post(
  '/users',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify Admin User's AccessToken
      const tokenContents: AuthToken = req.app.locals.accessTokenVerify(req);
      if (tokenContents.admin !== true) {
        // user is not admin
        throw new AuthenticationError();
      }

      // Verify the input
      let newUserForm: NewUserForm; // storage for username and password
      if (validateNewUserForm(req.body)) {
        const input = req.body;
        const userTimestamp = new Date(input.timestamp);
        input.timestamp = userTimestamp;
        newUserForm = input;
      } else {
        throw new BadRequestError();
      }

      // Hash Password
      const hashedPassword = req.app.locals.hash(
        newUserForm.username,
        newUserForm.timestamp.toISOString(),
        newUserForm.password
      );
      newUserForm.password = hashedPassword;

      // Generate new User
      await req.app.locals.dbClient.query(
        'INSERT INTO `user`(username, password, timestamp, admin) values (?, ?, ?, ?, ?)',
        [
          newUserForm.username,
          newUserForm.password,
          newUserForm.timestamp,
          newUserForm.admin,
        ]
      );

      // Response
      res.status(201).json({message: 'New User Created'});
    } catch (e) {
      next(e);
    }
  }
);

// DELETE /admin/users/{username}: Remove existing user

export default adminRouter;
