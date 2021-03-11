/**
 * express Router middleware for authentication API
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import * as jwt from 'jsonwebtoken';
import AuthToken from '../datatypes/AuthToken';
import {
  LoginCredentials,
  validateLoginCredentials,
} from '../datatypes/LoginCredentials';
import {User} from '../datatypes/User';
import AuthenticationError from '../exceptions/AuthenticationError';
import BadRequestError from '../exceptions/BadRequestError';

const authRouter = express.Router();

// POST /login: Login to get tokens
authRouter.post(
  '/login',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify User's Input
      const loginCredential: LoginCredentials = req.body;
      if (!validateLoginCredentials(loginCredential)) {
        throw new BadRequestError();
      }

      // Retrieve user information from database
      const queryResult = await req.app.locals.dbClient.query(
        'SELECT * FROM user WHERE username = ?',
        [loginCredential.username]
      );
      if (queryResult.length < 1) {
        // No user found
        throw new AuthenticationError();
      }
      const user: User = queryResult[0];

      // Check Password
      const hashedPassword = req.app.locals.hash(
        user.username,
        new Date(user.membersince).toISOString(),
        loginCredential.password
      );
      if (hashedPassword !== user.password) {
        throw new AuthenticationError();
      }

      // Create Access Token
      const tokenContent: AuthToken = {username: user.username, type: 'access'};
      if (user.admin) {
        tokenContent.admin = true;
      }
      const jwtOption: jwt.SignOptions = {
        algorithm: 'HS512',
        expiresIn: '15m',
      };
      const accessToken = jwt.sign(
        tokenContent,
        req.app.get('jwtAccessKey'),
        jwtOption
      );
      // Create Refresh Token
      const refreshTokenExpires = new Date(new Date().getTime() + 120 * 60000);
      tokenContent.type = 'refresh';
      jwtOption.expiresIn = '120m';
      const refreshToken = jwt.sign(
        tokenContent,
        req.app.get('jwtRefreshKey'),
        jwtOption
      );

      // Save Refresh Token to DB
      await req.app.locals.dbClient.query(
        'INSERT INTO session (token, expiresAt, username) values (?, ?, ?)',
        [refreshToken, refreshTokenExpires, user.username]
      );

      // Response
      const cookieOption: express.CookieOptions = {
        httpOnly: true,
        maxAge: 15 * 60 * 1000,
      };
      res.cookie('X-ACCESS-TOKEN', accessToken, cookieOption);
      cookieOption.maxAge = 120 * 60 * 120;
      res.cookie('X-REFRESH-TOKEN', refreshToken, cookieOption);
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

export default authRouter;
