/**
 * Configuration for the Server
 *
 * This file contains important credentials.
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import {BinaryLike} from 'crypto';
import ConfigObj from './datatypes/ConfigObj';

/**
 * Module contains the configuration
 * Need to implement hash function
 */
export default abstract class ServerConfigTemplate {
  // DB Config
  readonly dbURL: string;
  readonly dbPort: number;
  readonly dbUsername: string;
  readonly dbPassword: string;
  readonly defaultDatabase: string;

  // Express API Server Setup
  readonly expressPort: number;

  // JWT Token Confidentials
  readonly jwtSecretKey: string;
  readonly jwtRefreshKey: string;

  /**
   * Constructor for ServerConfig Object
   *
   * @param config configuration parameters will given by an object
   */
  constructor(config: ConfigObj) {
    // Setup DB Connection
    this.dbURL = config.db.dbURL;
    this.dbPort = config.db.dbPort;
    this.dbUsername = config.db.dbUsername;
    this.dbPassword = config.db.dbPassword;
    this.defaultDatabase = config.db.defaultDatabase;

    // Setup Express API Server
    this.expressPort = config.expressPort;

    // Setup JWT Token Credentials
    this.jwtSecretKey = config.jwtKeys.jwtSecretKey;
    this.jwtRefreshKey = config.jwtKeys.jwtRefreshKey;
  }

  /**
   * Function to create hashed password
   *
   * Detail of this function also should not be disclosed for security purpose.
   * Should not be uploaded to version control system (git).
   *
   * @param id user's id (used to generate salt)
   * @param additionalSalt unique additional salt element for each user
   * @param secretString string to be hashed (password, etc)
   * @returns {string} Hashed Password
   */
  abstract hash(
    id: BinaryLike,
    additionalSalt: BinaryLike,
    secretString: BinaryLike
  ): string;
}
