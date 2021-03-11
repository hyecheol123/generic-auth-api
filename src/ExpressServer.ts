/**
 * Express application middleware dealing with the API requests
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import * as mariadb from 'mariadb';
import * as jwt from 'jsonwebtoken';
import * as cookieParser from 'cookie-parser';
import ServerConfig from './ServerConfig';
import AuthenticationError from './exceptions/AuthenticationError';
import HTTPError from './exceptions/HTTPError';
import AuthToken from './datatypes/AuthToken';
import authRouter from './routes/auth';

/**
 * Class contains Express Application and other relevent instances/functions
 */
export default class ExpressServer {
  app: express.Application;

  /**
   * Constructor for ExpressAppHelper
   *
   * @param config Server's configuration
   */
  constructor(config: ServerConfig) {
    // Setup Express Application
    this.app = express(); // initialize express application
    this.app.locals.dbClient = mariadb.createPool({
      // Create db connection pool and link to the express application
      host: config.dbURL,
      port: config.dbPort,
      user: config.dbUsername,
      password: config.dbPassword,
      database: config.defaultDatabase,
      compress: true,
    });

    // link password hash function to the express application
    this.app.locals.hash = config.hash;

    // JWT Keys
    this.app.set('jwtAccessKey', config.jwtSecretKey);
    this.app.set('jwtRefreshKey', config.jwtRefreshKey);

    // link functions to verify JWT Tokens
    // function to verify access token, return username
    this.app.locals.accessTokenVerify = (req: express.Request): AuthToken => {
      if ('X-ACCESS-TOKEN' in req.cookies) {
        let tokenContents: AuthToken; // place to store contents of JWT
        // Verify and retrieve the token contents
        try {
          tokenContents = jwt.verify(
            req.cookies['X-ACCESS-TOKEN'].split(' ')[1],
            config.jwtSecretKey,
            {algorithms: ['HS512']}
          ) as AuthToken;
        } catch (e) {
          throw new AuthenticationError();
        }
        if (tokenContents.type !== 'access') {
          throw new AuthenticationError();
        } else {
          return tokenContents;
        }
      } else {
        throw new AuthenticationError();
      }
    };
    // function to verify refresh token, return username
    this.app.locals.refreshTokenVerify = (req: express.Request): AuthToken => {
      if ('X-REFRESH-TOKEN' in req.cookies) {
        let tokenContents: AuthToken; // place to store contents of JWT
        // Verify and retrieve the token contents
        try {
          tokenContents = jwt.verify(
            req.cookies['X-REFRESH-TOKEN'].split(' ')[1],
            config.jwtRefreshKey,
            {algorithms: ['HS512']}
          ) as AuthToken;
        } catch (e) {
          throw new AuthenticationError();
        }
        if (tokenContents.type !== 'refresh') {
          throw new AuthenticationError();
        } else {
          return tokenContents;
        }
      } else {
        throw new AuthenticationError();
      }
    };

    // Setup Parsers
    this.app.use(express.json());
    this.app.use(cookieParser());

    // Add List of Routers
    this.app.use('/', authRouter);

    // Default Error Handler
    this.app.use(
      (
        err: HTTPError | Error,
        _req: express.Request,
        res: express.Response,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _next: express.NextFunction
      ): void => {
        if (!(err instanceof HTTPError)) {
          console.error(err);
          err = new HTTPError(500, 'Server Error');
        }
        res.status((err as HTTPError).statusCode).json({error: err.message});
      }
    );
  }

  /**
   * Close connection with Database server gracefully
   */
  async closeDB(): Promise<void> {
    await this.app.locals.dbClient.end();
    console.log('DB Connection Closed');
  }
}
