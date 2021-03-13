/**
 * Jest unit test for authentication API's logout feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import AuthToken from '../../src/datatypes/AuthToken';
import DBTable from '../datatypes/DBTable';
import TestEnv from '../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';

describe('DELETE /logout - Logout from current session', () => {
  let testEnv: TestEnv;

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
  });

  afterEach(async () => {
    await testEnv.stop();
  });

  test('Success Logout', async done => {
    // User Login (Retrieve Refresh Token)
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    const refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Logout Request
    response = await request(testEnv.expressServer.app)
      .delete('/logout')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Cookie Clear Check
    let cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    expect(cookie[1]).toBe('');
    cookie = response.header['set-cookie'][1].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-REFRESH-TOKEN'); // check for Refresh Token Name
    expect(cookie[1]).toBe('');

    // Check Session DB Table
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE token = ?',
      [refreshToken]
    );
    expect(queryResult.length).toBe(0);
    done();
  });

  test('Fail - Use Access Token to Logout', async done => {
    // User Login (Retrieve Refresh Token)
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'password'});
    expect(response.status).toBe(200);
    const accessToken = response.header['set-cookie'][0]
      .split('; ')[0]
      .split('=')[1];
    const refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Logout Request
    response = await request(testEnv.expressServer.app)
      .delete('/logout')
      .set('Cookie', [`X-REFRESH-TOKEN=${accessToken}`]);
    expect(response.status).toBe(401);

    // Check Session DB Table
    // Still need to be logged in
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE token = ?',
      [refreshToken]
    );
    expect(queryResult.length).toBe(1);
    done();
  });

  test('Fail - Use Non-registered Refresh Token', async done => {
    // Generate Refersh Token
    const tokenContent: AuthToken = {username: 'user2', type: 'refresh'};
    const jwtOption: jwt.SignOptions = {
      algorithm: 'HS512',
      expiresIn: '120m',
    };
    const refreshToken = jwt.sign(
      tokenContent,
      testEnv.testConfig.jwtRefreshKey,
      jwtOption
    );

    // Logout Request
    const response = await request(testEnv.expressServer.app)
      .delete('/logout')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(401);
    done();
  });
});
