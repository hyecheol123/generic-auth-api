/**
 * Define type for each session entry in the database
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as mariadb from 'mariadb';

/**
 * Interface for each Session
 */
export interface Session {
  token: string; // RefreshToken
  expiresAt: Date; // In DB, format: datetime string
  username: string;
}

/**
 * Create a session entry in the DB
 *
 * @param dbClient DB Connection Pool
 * @param session Session Information
 */
export async function createSession(
  dbClient: mariadb.Pool,
  session: Session
): Promise<void> {
  await dbClient.query(
    'INSERT INTO session (token, expiresAt, username) values (?, ?, ?)',
    [session.token, session.expiresAt, session.username]
  );
}

/**
 * Delete current session from database
 *
 * @param dbClient DB Connection Pool
 * @param token refreshToken associated with the Session
 */
export async function deleteSession(
  dbClient: mariadb.Pool,
  token: string
): Promise<void> {
  await dbClient.query('DELETE FROM session WHERE token = ?', token);
}

/**
 * Delete sessions associated with the username, but leave current session
 *
 * @param dbClient DB Connection Pool
 * @param currentToken refreshToken associated with the current Session
 * @param username used to find Session associated with the username
 */
export async function deleteSessionNotCurrent(
  dbClient: mariadb.Pool,
  currentToken: string,
  username: string
): Promise<void> {
  await dbClient.query(
    'DELETE FROM session WHERE username = ? AND (NOT token = ?)',
    [username, currentToken]
  );
}

/**
 * Delete sessions associated with the username
 *
 * @param dbClient DB Connection Pool
 * @param username used to find Sessions associated with the username
 */
export async function deleteSessionAll(
  dbClient: mariadb.Pool,
  username: string
): Promise<void> {
  await dbClient.query('DELETE FROM session WHERE username = ?', username);
}

/**
 * Retrieve Session with given token
 *
 * @param dbClient DB Connection Pool
 * @param token refreshToken associated with the Session
 */
export async function readSession(
  dbClient: mariadb.Pool,
  token: string
): Promise<Session[]> {
  return await dbClient.query('SELECT * FROM session WHERE token = ?', token);
}
