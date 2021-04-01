/**
 * express Router middleware for authentication API
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import * as jwt from 'jsonwebtoken';
import AuthToken from '../datatypes/AuthToken';
import {
  ChangePassword,
  validateChangePassword,
} from '../datatypes/ChangePassword';
import {
  LoginCredentials,
  validateLoginCredentials,
} from '../datatypes/LoginCredentials';
import RefreshTokenVerifyResult from '../datatypes/RefreshTokenVerifyResult';
import {User} from '../datatypes/User';
import Session from '../datatypes/Session';
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
      const sessionInfo = new Session(
        refreshToken,
        refreshTokenExpires,
        user.username
      );
      await Session.create(req.app.locals.dbClient, sessionInfo);

      // Response
      const cookieOption: express.CookieOptions = {
        httpOnly: true,
        maxAge: 15 * 60,
      };
      res.cookie('X-ACCESS-TOKEN', accessToken, cookieOption);
      cookieOption.maxAge = 120 * 60;
      res.cookie('X-REFRESH-TOKEN', refreshToken, cookieOption);
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

// DELETE /logout: Logout from current session
authRouter.delete(
  '/logout',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify the refreshToken
      const refreshTokenVerify = req.app.locals.refreshTokenVerify(req);

      // Delete from the database
      const query = Session.delete(
        req.app.locals.dbClient,
        req.cookies['X-REFRESH-TOKEN']
      );

      await Promise.all([refreshTokenVerify, query]);

      // Clear Cookie & Response
      res.clearCookie('X-ACCESS-TOKEN', {httpOnly: true, maxAge: 0});
      res.clearCookie('X-REFRESH-TOKEN', {httpOnly: true, maxAge: 0});
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

// DELETE /logout/other-sessions: Logout from other sessions
authRouter.delete(
  '/logout/other-sessions',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // verify the refresh token
      const {content} = await req.app.locals.refreshTokenVerify(req);
      const username = (content as AuthToken).username;

      // Logout From other Session (Remove DB)
      await Session.deleteNotCurrent(
        req.app.locals.dbClient,
        req.cookies['X-REFRESH-TOKEN'],
        username
      );

      // Response
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

// GET /renew: Renew Tokens by using RefreshToken
authRouter.get(
  '/renew',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify the refresh Token
      // eslint-disable-next-line prettier/prettier
      const verifyResult: RefreshTokenVerifyResult = await req.app.locals
        .refreshTokenVerify(req);

      // Check User Existence
      const dbResult = await req.app.locals.dbClient.query(
        'SELECT * FROM user WHERE username = ?',
        [verifyResult.content.username]
      );
      if (dbResult.length !== 1) {
        // User Not Found
        throw new AuthenticationError();
      }

      // Token options
      const cookieOption: express.CookieOptions = {
        httpOnly: true,
        maxAge: 120 * 60,
      };

      // Create New Refresh Tokens & Write Cookie
      const queries = [];
      if (verifyResult.needRenew) {
        // Create Refresh Token
        const tokenExpire = new Date(new Date().getTime() + 120 * 60000);
        const refreshToken = jwt.sign(
          verifyResult.content,
          req.app.get('jwtRefreshKey'),
          {algorithm: 'HS512', expiresIn: '120m'}
        );

        // Delete previous session and save new Refresh Token to DB
        const sessionInfo = new Session(
          refreshToken,
          tokenExpire,
          verifyResult.content.username
        );
        const query1 = Session.delete(
          req.app.locals.dbClient,
          req.cookies['X-REFRESH-TOKEN']
        );
        const query2 = Session.create(req.app.locals.dbClient, sessionInfo);
        queries.push(query1);
        queries.push(query2);

        // Set Cookie
        res.cookie('X-REFRESH-TOKEN', refreshToken, cookieOption);
      }

      // Create New Access Tokens & Write Cookie
      cookieOption.maxAge = 15 * 60;
      verifyResult.content.type = 'access';
      const accessToken = jwt.sign(
        verifyResult.content,
        req.app.get('jwtAccessKey'),
        {algorithm: 'HS512', expiresIn: '15m'}
      );
      // Set Cookie
      res.cookie('X-ACCESS-TOKEN', accessToken, cookieOption);

      // Wait for DB operation
      if (queries.length !== 0) {
        await Promise.all(queries);
      }

      // Response
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

// PUT /password: Change Password
authRouter.put(
  '/password',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // verify the refresh token
      const {content} = await req.app.locals.refreshTokenVerify(req);
      const username = (content as AuthToken).username;

      // Verify User's Input
      const changePassword: ChangePassword = req.body;
      if (!validateChangePassword(changePassword)) {
        throw new BadRequestError();
      }

      // Retrieve User information from DB
      const queryResult = await req.app.locals.dbClient.query(
        'SELECT * FROM user WHERE username = ?',
        [username]
      );
      const user: User = queryResult[0];

      // Check current password
      let hashedPassword = req.app.locals.hash(
        user.username,
        new Date(user.membersince).toISOString(),
        changePassword.currentPassword
      );
      if (hashedPassword !== user.password) {
        throw new AuthenticationError();
      }

      // Generate new hashed password
      hashedPassword = req.app.locals.hash(
        user.username,
        new Date(user.membersince).toISOString(),
        changePassword.newPassword
      );

      // Update DB & Logout from other sessions
      const query1 = req.app.locals.dbClient.query(
        'UPDATE user SET password = ? WHERE username = ?;',
        [hashedPassword, username]
      );
      const query2 = Session.deleteNotCurrent(
        req.app.locals.dbClient,
        req.cookies['X-REFRESH-TOKEN'],
        username
      );
      await Promise.all([query1, query2]);

      // Response
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

export default authRouter;
