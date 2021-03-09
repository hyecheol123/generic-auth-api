/**
 * Define HTTPError
 * Contains HTTP Status code and message.
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

/**
 * HTTPError will thrown when server encounter any error/exception
 */
export default class HTTPError extends Error {
  readonly statusCode: number; // Store HTTP Status Code

  /**
   * Constructor for HTTPError
   * @param statusCode HTTP Status code
   * @param message Short message to explane the error
   */
  constructor(statusCode: number, message: string) {
    super(message); // Call constructor of Error
    this.statusCode = statusCode;

    // Set the prototype explicitly.
    Object.setPrototypeOf(this, HTTPError.prototype);
  }
}
