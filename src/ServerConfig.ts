/**
 * Configuration for the Server
 *
 * This file contains important credentials. Should not be uploaded to version control system (git).
 *
 * @author Hyecheol (Jerry) Jang
 */

import * as crypto from 'node:crypto';
import ServerConfigTemplate from './ServerConfigTemplate';

/**
 * Module contains the configuration
 */
export default class ServerConfig extends ServerConfigTemplate {
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
  hash(
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
