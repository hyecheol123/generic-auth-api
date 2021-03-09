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
  jwtKeys: jwtKeyObj; // indicate jwt token credentials
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
}

/**
 * Interface to define jwtKeyObj object
 * This type of object should be contained in the ConfigObj
 */
interface jwtKeyObj {
  jwtSecretKey: string; // key that will used to validate the token
  jwtRefreshKey: string; // different key that will used to validate refresh token
}
