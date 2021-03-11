/**
 * Configuration for the Test Environment.
 * Work identical as ServerConfig of src.
 *
 * @author Hyecheol (Jerry) Jang
 */

import * as crypto from 'crypto';
import ConfigObj from '../src/datatypes/ConfigObj';
import ServerConfigTemplate from '../src/ServerConfigTemplate';

/**
 * Module contains the configuration
 */
export default class TestConfig extends ServerConfigTemplate {
  /**
   * Constructor for TestConfig
   *
   * @param identifier Identifier to specify the test database
   */
  constructor(identifier: string) {
    const config: ConfigObj = {
      db: {
        dbURL: 'localhost',
        dbPort: 3306,
        dbUsername: 'testdb',
        dbPassword: '',
        defaultDatabase: identifier,
      },
      expressPort: 3000,
      jwtKeys: {jwtSecretKey: 'keySecret', jwtRefreshKey: 'keySecret'},
    };
    super(config);
  }

  /**
   * Function to create hashed password
   *
   * @param id user's id (used to generate salt)
   * @param additionalSalt unique additional salt element for each user
   * @param secretString string to be hashed (password, etc)
   * @returns {string} Hashed Password
   */
  hash(
    id: crypto.BinaryLike,
    additionalSalt: crypto.BinaryLike,
    secretString: crypto.BinaryLike
  ): string {
    const salt: crypto.BinaryLike = id.toString() + additionalSalt.toString();
    return crypto
      .pbkdf2Sync(secretString, salt, 10, 64, 'sha512')
      .toString('base64');
  }
}
