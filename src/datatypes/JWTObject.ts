/**
 * Object type definition for JWT Token Payload
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import AuthToken from './AuthToken';

export default interface JWTObject extends AuthToken {
  iat?: number; // issued at
  exp?: number; // expire at
}
