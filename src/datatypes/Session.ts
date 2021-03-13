/**
 * Define type for each session entry in the database
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

/**
 * Interface for each Session
 */
export default interface Session {
  token: string; // RefreshToken
  expiresAt: string; // format: datetime
  username: string;
}
