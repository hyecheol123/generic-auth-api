/**
 * Jest unit test for authentication API's renew token feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import MockDate from 'mockdate';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';
import AuthToken from '../../../src/datatypes/AuthToken';

describe('POST /login - Login with username and password', () => {
  let testEnv: TestEnv;
  let refreshToken: string;

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

    // Login
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Set MockDate
    const currentTime = new Date();
    currentTime.setMinutes(new Date().getMinutes() + 15); // expire accessToken
    MockDate.set(currentTime);
  });

  afterEach(async () => {
    await testEnv.stop();
    MockDate.reset();
  });

  test('Success Renewal - only access token / admin', async done => {
    // Login
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Set MockDate
    const currentTime = new Date();
    currentTime.setMinutes(new Date().getMinutes() + 15); // expire accessToken
    MockDate.set(currentTime);

    // Renewal Request
    response = await request(testEnv.expressServer.app)
      .get('/renew')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Check Cookie and Token Values
    const jwtOption: jwt.VerifyOptions = {algorithms: ['HS512']};
    // Parse Access Token
    const cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    const tokenPayload: AuthToken = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtSecretKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('admin');
    expect(tokenPayload.type).toBe('access');
    expect(tokenPayload.admin).toBe(true);

    // Check Session DB Table - Previous Token Remaining
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE token = ?',
      [refreshToken]
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].username).toBe('admin');
    done();
  });

  test('Success Renewal - only access token / non-admin', async done => {
    // Renewal Request
    const response = await request(testEnv.expressServer.app)
      .get('/renew')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Check Cookie and Token Values
    const jwtOption: jwt.VerifyOptions = {algorithms: ['HS512']};
    // Parse Access Token
    const cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    const tokenPayload: AuthToken = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtSecretKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('user2');
    expect(tokenPayload.type).toBe('access');
    expect(tokenPayload.admin).toBeUndefined();

    // Check Session DB Table - Previous Token Remaining
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE token = ?',
      [refreshToken]
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].username).toBe('user2');
    done();
  });

  test('Success Renewal - refreshToken renewed / admin', async done => {
    // Login
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Set MockDate
    const currentTime = new Date();
    // refreshToken about to expire
    currentTime.setMinutes(new Date().getMinutes() + 110);
    MockDate.set(currentTime);

    // Renewal Request
    response = await request(testEnv.expressServer.app)
      .get('/renew')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Check Cookie and Token Values
    const jwtOption: jwt.VerifyOptions = {algorithms: ['HS512']};
    // Parse Access Token
    let cookie = response.header['set-cookie'][1].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    let tokenPayload: AuthToken = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtSecretKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('admin');
    expect(tokenPayload.type).toBe('access');
    expect(tokenPayload.admin).toBe(true);
    // Parse Refresh Token
    cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-REFRESH-TOKEN'); // Check for Refresh Token Name
    tokenPayload = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtRefreshKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('admin');
    expect(tokenPayload.type).toBe('refresh');
    expect(tokenPayload.admin).toBe(true);

    // Check Session DB Table - Previous Token Removed, New Token Exist
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(cookie[1]);
    done();
  });

  test('Success Renewal - refreshToken renewed / non-admin', async done => {
    // Set MockDate
    const currentTime = new Date();
    // refreshToken about to expire - 15min has been passed so far
    currentTime.setMinutes(new Date().getMinutes() + 95);
    MockDate.set(currentTime);

    // Renewal Request
    const response = await request(testEnv.expressServer.app)
      .get('/renew')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Check Cookie and Token Values
    const jwtOption: jwt.VerifyOptions = {algorithms: ['HS512']};
    // Parse Access Token
    let cookie = response.header['set-cookie'][1].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    let tokenPayload: AuthToken = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtSecretKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('user2');
    expect(tokenPayload.type).toBe('access');
    expect(tokenPayload.admin).toBeUndefined();
    // Parse Refresh Token
    cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-REFRESH-TOKEN'); // Check for Refresh Token Name
    tokenPayload = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtRefreshKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('user2');
    expect(tokenPayload.type).toBe('refresh');
    expect(tokenPayload.admin).toBeUndefined();

    // Check Session DB Table - Previous Token Remaining
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(cookie[1]);
    done();
  });

  test('Fail - Expired Refresh Token', async done => {
    // Set MockDate
    const currentTime = new Date();
    // refreshToken Expired - 15min has been passed so far
    currentTime.setMinutes(new Date().getMinutes() + 110);
    MockDate.set(currentTime);

    // Renewal Request
    const response = await request(testEnv.expressServer.app)
      .get('/renew')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(401);

    // DB Cannot be tested as it has own clock
    done();
  });

  // TEST: Already Logged Out Token
  test('Fail - Expired Refresh Token', async done => {
    // Logout Request
    let response = await request(testEnv.expressServer.app)
      .delete('/logout')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Renewal Request
    response = await request(testEnv.expressServer.app)
      .get('/renew')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(401);

    // DB Tested while testing Logout feature
    done();
  });
});
