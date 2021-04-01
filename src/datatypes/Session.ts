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
 * Function to create a session entry in the DB
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
