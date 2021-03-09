/**
 * Define Authentiation Error based on HTTPError
 * Contains HTTP Status code and message for commonly caused
 * Authentication Error
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import HTTPError from './HTTPError';

/**
 * Authentication Error is a type of HTTPError, of which status code is 401
 */
export default class AuthenticationError extends HTTPError {
  /**
   * Constructor for Authentication Error
   */
  constructor() {
    super(401, 'Authentication information is missing/invalid');
  }
}
