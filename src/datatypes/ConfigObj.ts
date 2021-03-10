/**
 * Define types for the objects related with configuring the server
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

/**
 * Interface to define ConfigObj object
 * This type of object will given to the constructor of ServerConfig
 */
export default interface ConfigObj {
  db: DbObj; // contain database configuration parameters
  expressPort: number; // indicate express server port
  jwtKeys: JwtKeyObj; // indicate jwt token credentials
}

/**
 * Interface to define DbObj object
 * This type of object should be contained in the ConfigObj
 */
interface DbObj {
  dbURL: string; // URL indicating the location of database server
  dbPort: number; // Port number to access database server
  dbUsername: string;
  dbPassword: string;
  defaultDatabase: string; // default database name
}

/**
 * Interface to define jwtKeyObj object
 * This type of object should be contained in the ConfigObj
 */
interface JwtKeyObj {
  jwtSecretKey: string; // key that used to validate the token
  jwtRefreshKey: string; // different key that used to  validate refresh token
}
