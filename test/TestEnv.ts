/**
 * Setup test environment
 *  - Setup Database for testing
 *  - Build In-memory table that will be used during the testing
 *  - Setup express server
 * Teardown test environment after test
 *  - Remove used table and close database connection from the express server
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as crypto from 'crypto';
import * as mariadb from 'mariadb';
import ExpressServer from '../src/ExpressServer';
import DBTable from './datatypes/DBTable';
import TestConfig from './TestConfig';

/**
 * Class for Test Environment
 */
export default class TestEnv {
  testConfig: TestConfig; // Configuration Object (to use hash function later)
  expressServer: ExpressServer; // Express Server Object
  dbClient: mariadb.Pool; // DB Client Object
  tableIdentifier: string; // unique identifier string for the table

  /**
   * Constructor for TestEnv
   *  - Setup express server
   *  - Setup db client
   */
  constructor() {
    this.testConfig = new TestConfig(); // Generate TestConfig obj

    // Create db connection pool
    this.dbClient = mariadb.createPool({
      host: this.testConfig.dbURL,
      port: this.testConfig.dbPort,
      user: this.testConfig.dbUsername,
      password: this.testConfig.dbPassword,
      compress: true,
    });

    // Setup ExpressServer
    this.expressServer = new ExpressServer(this.testConfig);
  }

  /**
   * beforeEach test case, run this function
   * - Setup Database for testing
   * - Build In-memory table that will be used during the testing
   *
   * @param dbTableList List of DBTable object that indicate
   *   the list of DBTables that will be used during the test.
   * @param identifier Identifier to specify the test
   */
  async start(dbTableList: DBTable[], identifier: string): Promise<void> {
    // Hash identifier to create new identifier string
    this.tableIdentifier = crypto
      .createHash('md5')
      .update(identifier)
      .digest('hex');

    // Remove duplicates in the dbTableList
    dbTableList = Array.from(new Set(dbTableList));

    // Put the Data to the Database
    for (const i in dbTableList) {
      switch (i) {
        case DBTable.USER:
          await this.userTable();
          break;
        case DBTable.SESSION:
          await this.sessionTable();
          break;
        default:
          throw new Error('DBTable Not Valid!!');
      }
    }
  }

  /**
   * Helper method to create user table for testing
   */
  private async userTable(): Promise<void> {
    // Create Table
    await this.dbClient.query(
      `CREATE TABLE user_${this.tableIdentifier} (` +
        'id VARCHAR(12) NOT NULL PRIMARY KEY, ' +
        'password CHAR(88) NOT NULL, ' +
        'membersince TIMESTAMP NULL DEFAULT NULL, ' +
        'admin BOOLEAN NOT NULL) ENGINE = MEMORY;'
    );

    // Sample Data
    const sampleUsers = [];
    // user1, password
    let userTimestamp = new Date('2021-03-10T00:50:43.309Z');
    sampleUsers.push([
      'user1',
      this.testConfig.hash('user1', userTimestamp.toISOString(), 'password'),
      userTimestamp.toISOString(),
      false,
    ]);
    // user2, password12!
    userTimestamp = new Date('2021-03-07T01:15:42.200Z');
    sampleUsers.push([
      'user2',
      this.testConfig.hash('user2', userTimestamp.toISOString(), 'password12!'),
      userTimestamp.toISOString(),
      false,
    ]);
    // admin, rootpw!!
    userTimestamp = new Date('2021-02-07T01:15:36.198Z');
    sampleUsers.push([
      'admin',
      this.testConfig.hash('admin', userTimestamp.toISOString(), 'rootpw!!'),
      userTimestamp.toISOString,
      true,
    ]);

    // Insert User Information (3 user)
    await this.dbClient.batch(
      `INSERT INTO user_${this.tableIdentifier}` +
        '(id, password, membersince, admin) values (?, ?, ?, ?)',
      sampleUsers
    );
  }

  /**
   * Helper method to create session table for testing
   */
  private async sessionTable(): Promise<void> {
    // Create Table
    await this.dbClient.query(
      `CREATE TABLE session_${this.tableIdentifier} (` +
        'token VARCHAR(400) NOT NULL PRIMARY KEY, ' +
        'expiresAt TIMESTAMP NULL DEFAULT NULL, ' +
        'userID VARCHAR(12) NOT NULL, ' +
        'INDEX userIDIdx(userID)) ENGINE = MEMORY;'
    );

    // Sessions will be created by calling Login API
  }

  /**
   * Teardown test environment after test
   *  - Remove used table and close database connection from the express server
   */
  async stop(): Promise<void> {
    // Drop tables
    await this.dbClient.query(
      'DROP TABLE IF EXISTS ' +
        `user_${this.tableIdentifier}, session_${this.tableIdentifier};`
    );

    // Close database connection of the express server
    await this.expressServer.closeDB();

    // Close database connection used during tests
    await this.dbClient.end();
  }
}
