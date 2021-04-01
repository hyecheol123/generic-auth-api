/**
 * Define type and CRUD methods for each user entry
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import * as mariadb from 'mariadb';
import {LoginCredentials} from './LoginCredentials';
import HTTPError from '../exceptions/HTTPError';
import NotFoundError from '../exceptions/NotFoundError';

/**
 * Class for User
 */
export default class User implements LoginCredentials {
  membersince: string | Date; // in ISO Date format
  admin?: boolean;
  password: string;
  username: string;

  constructor(since: Date, pw: string, username: string, admin: boolean) {
    this.membersince = since;
    this.password = pw;
    this.username = username;
    this.admin = admin;
  }

  // Validator for JSON object containing information of NewUserForm
  static validateNewUserForm = addFormats(new Ajv()).compile({
    type: 'object',
    properties: {
      username: {type: 'string'},
      password: {type: 'string'},
      admin: {type: 'boolean'},
      membersince: {type: 'string', format: 'date-time'},
    },
    required: ['username', 'password', 'membersince'],
    additionalProperties: false,
  });

  /**
   * Create an User entry in the DB
   *
   * @param dbClient DB Connection Pool
   * @param user User Information
   */
  static async create(dbClient: mariadb.Pool, user: User): Promise<void> {
    try {
      await dbClient.query(
        'INSERT INTO user (username, password, membersince, admin) values (?, ?, ?, ?)',
        [user.username, user.password, user.membersince, user.admin]
      );
    } catch (e) {
      /* istanbul ignore else */
      if (e.code === 'ER_DUP_ENTRY') {
        throw new HTTPError(400, 'Duplicated Username');
      } else {
        throw e;
      }
    }
  }

  /**
   * Delete an User entry from DB
   *
   * @param dbClient DB Connection Pool
   * @param username username associated with the User
   */
  static async delete(dbClient: mariadb.Pool, username: string): Promise<void> {
    const queryResult = await dbClient.query(
      'DELETE FROM user WHERE username = ?',
      username
    );
    if (queryResult.affectedRows !== 1) {
      // When user not found
      throw new NotFoundError();
    }
  }

  /**
   * Retrieve an User entry from DB
   *
   * @param dbClient DB Connection Pool
   * @param username username associated with the User
   */
  static async read(dbClient: mariadb.Pool, username: string): Promise<User> {
    const queryResult = await dbClient.query(
      'SELECT * FROM user WHERE username = ?',
      username
    );
    if (queryResult.length !== 1) {
      throw new NotFoundError();
    }
    const user: User = queryResult[0];
    user.membersince = new Date(user.membersince);
    return user;
  }

  /**
   * Update User's Password
   *
   * @param dbClient DB Connection Pool
   * @param username username associated with the new User
   * @param password Updated Password
   */
  static async updatePassword(
    dbClient: mariadb.Pool,
    username: string,
    password: string
  ): Promise<void> {
    const args = [password, username];
    await dbClient.query(
      'UPDATE user SET password = ? WHERE username = ?;',
      args
    );
  }
}
