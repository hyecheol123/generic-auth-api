/**
 * Jest unit test for authentication API's user add admin feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
import {User} from '../../../src/datatypes/User';
import AuthToken from '../../../src/datatypes/AuthToken';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';

describe('POST /admin/user - Admin Feature: Add New User', () => {
  let testEnv: TestEnv;
  let accessToken: string;
  let refreshToken: string;
  let memberSince: Date;
  let newUser: User;

  beforeAll(() => {
    // Set new timeout
    jest.setTimeout(120000);
  });

  beforeEach(async () => {
    // Setup TestEnv
    testEnv = new TestEnv(expect.getState().currentTestName);

    // Start Test Environment
    const dbTable: DBTable[] = [DBTable.USER, DBTable.SESSION];
    await testEnv.start(dbTable);

    // New Member Information
    memberSince = new Date();
    memberSince.setMilliseconds(0);
    newUser = {
      username: 'admin2',
      password: 'newpw',
      membersince: memberSince.toISOString(),
      admin: true,
    };

    // Login with admin user
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    accessToken = response.header['set-cookie'][0].split('; ')[0].split('=')[1];
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];
  });

  afterEach(async () => {
    await testEnv.stop();
  });

  test('Success Add - Admin User', async done => {
    // Request
    let response = await request(testEnv.expressServer.app)
      .post('/admin/user')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send(newUser);
    expect(response.status).toBe(201);

    // DB Check
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin2'"
    );
    expect(queryResult.length).toBe(1);
    expect(new Date(queryResult[0].membersince).toISOString()).toBe(
      memberSince.toISOString()
    );
    expect(queryResult[0].admin).toBeTruthy();
    const hashedPassword = testEnv.testConfig.hash(
      newUser.username,
      memberSince.toISOString(),
      newUser.password
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // Able to login with new Account
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin2', password: 'newpw'});
    expect(response.status).toBe(200);
    done();
  });

  test('Success Add - Non-Admin User', async done => {
    // Request
    newUser = {
      username: 'user3',
      password: 'newpw',
      membersince: memberSince.toISOString(),
    };
    let response = await request(testEnv.expressServer.app)
      .post('/admin/user')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send(newUser);
    expect(response.status).toBe(201);

    // DB Check
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user3'"
    );
    expect(queryResult.length).toBe(1);
    expect(new Date(queryResult[0].membersince).toISOString()).toBe(
      memberSince.toISOString()
    );
    expect(queryResult[0].admin).toBeFalsy();
    const hashedPassword = testEnv.testConfig.hash(
      newUser.username,
      memberSince.toISOString(),
      newUser.password
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // Able to login with new Account
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user3', password: 'newpw'});
    expect(response.status).toBe(200);
    done();
  });

  test('Fail - Use Refresh Token as Access Token', async done => {
    // Request
    const response = await request(testEnv.expressServer.app)
      .post('/admin/user')
      .set('Cookie', [`X-ACCESS-TOKEN=${refreshToken}`])
      .send(newUser);
    expect(response.status).toBe(401);

    // DB Check
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin2'"
    );
    expect(queryResult.length).toBe(0);
    done();
  });

  test('Fail - Use Access token generated with wrong key', async done => {
    // generate accessToken
    const tokenContent: AuthToken = {
      username: 'admin1',
      type: 'access',
      admin: true,
    };
    const jwtOption: jwt.SignOptions = {
      algorithm: 'HS512',
      expiresIn: '15m',
    };
    const accessToken = jwt.sign(tokenContent, 'wrong-key', jwtOption);

    // Request
    const response = await request(testEnv.expressServer.app)
      .post('/admin/user')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send(newUser);
    expect(response.status).toBe(401);

    // DB Check
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin2'"
    );
    expect(queryResult.length).toBe(0);
    done();
  });

  test('Fail - No Token', async done => {
    // Request
    let response = await request(testEnv.expressServer.app)
      .post('/admin/user')
      .set('Cookie', ['X-ACCESS-TOKEN='])
      .send(newUser);
    expect(response.status).toBe(401);

    // DB Check
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin2'"
    );
    expect(queryResult.length).toBe(0);

    // Request - Without Cookie
    response = await request(testEnv.expressServer.app)
      .post('/admin/user')
      .send(newUser);
    expect(response.status).toBe(401);

    // DB Check
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin2'"
    );
    expect(queryResult.length).toBe(0);
    done();
  });
});
