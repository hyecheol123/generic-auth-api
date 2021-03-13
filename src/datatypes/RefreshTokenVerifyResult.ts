/**
 * Define type for the objects that contains the result
 * for RefreshToken verification
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import AuthToken from './AuthToken';

/**
 * Interface for RefreshTokenVerifyResult
 */
export default interface RefreshTokenVerifiyResult {
  content: AuthToken;
  needRenew: boolean;
}
