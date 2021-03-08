/**
 * Configuration for the Server
 *
 * This file contains important credentials. Should not be uploaded to version control system (git).
 *
 * @author Hyecheol (Jerry) Jang
 */

import * as crypto from 'crypto';

/**
 * Module contains the configuration
 */
export default class ServerConfig {
  // DB Config
  static dbURL = '[Replace with Your DB URL]'; // Include port information here
  static dbUsername = '[Replace with your DB Username]';
  static dbPassword = '[Replace with your DB Password]';

  // Express API Server Setup
  static expressPort = 3000;

  // JWT Token Confidentials
  static jwtSecretKey = '[Replace with your secret key]';
  static jwtRefreshKey = '[Replace with your refresh key]';

  /**
   * Function to create hashed password
   *
   * Detail of this function also should not be disclosed for security purpose.
   * Should not be uploaded to version contro system (git).
   *
   * @param id user's id (used to generate salt)
   * @param additionalSalt unique additional salt element for each user
   * @param secretString string to be hashed (password, etc)
   */
  static hash(
    id: crypto.BinaryLike,
    additionalSalt: crypto.BinaryLike,
    secretString: crypto.BinaryLike
  ): string {
    // TODO: Should generate your own hash function
    const salt: crypto.BinaryLike = id.toString() + additionalSalt.toString();
    return crypto
      .pbkdf2Sync(secretString, salt, 10, 64, 'sha512')
      .toString('base64');
  }
}
