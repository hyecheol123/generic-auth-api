/**
 * Check Methods for database connection
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as mariadb from 'mariadb';

/**
 * Function to check whether DB connection has been established or not
 *
 * @param dbClient DB Connection Pool
 */
export default async function dbCheck(
  dbClient: mariadb.Pool
): Promise<boolean> {
  const queryResult = await dbClient.query("SELECT 'Hello World!'");
  return (
    queryResult.length === 1 &&
    queryResult[0]['Hello World!'] === 'Hello World!'
  );
}
