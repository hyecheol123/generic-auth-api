/**
 * Jest unit test for authentication API's login feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import AuthToken from '../../../src/datatypes/AuthToken';
import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import MockDate from 'mockdate';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';

describe('POST /login - Login with username and password', () => {
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

  test('Success Login - User', async done => {
    // Request
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);

    // Check Cookie & token Information
    const jwtOption: jwt.VerifyOptions = {algorithms: ['HS512']};
    // Parse Access Token
    let cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    let tokenPayload: AuthToken = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtSecretKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('user2');
    expect(tokenPayload.type).toBe('access');
    expect(tokenPayload.admin).toBeUndefined();
    // Parse Refersh Token
    cookie = response.header['set-cookie'][1].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-REFRESH-TOKEN'); // check for Refresh Token Name
    tokenPayload = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtRefreshKey,
      jwtOption
    ) as AuthToken; // Check for RefreshToken contents
    expect(tokenPayload.username).toBe('user2');
    expect(tokenPayload.type).toBe('refresh');
    expect(tokenPayload.admin).toBeUndefined();

    // Check Session DB Table
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(cookie[1]);
    if (
      new Date(queryResult[0].expiresAt) >
      new Date(new Date().getTime() + 120 * 60000 + 1000)
    ) {
      fail();
    }
    done();
  });

  test('Success Login - Admin', async done => {
    // Request
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);

    // Check Cookie & token Information
    const jwtOption: jwt.VerifyOptions = {algorithms: ['HS512']};
    // Parse Access Token
    let cookie = response.header['set-cookie'][0].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-ACCESS-TOKEN'); // Check for Access Token Name
    let tokenPayload: AuthToken = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtSecretKey,
      jwtOption
    ) as AuthToken; // Check for AccessToken contents
    expect(tokenPayload.username).toBe('admin');
    expect(tokenPayload.type).toBe('access');
    expect(tokenPayload.admin).toBe(true);
    // Parse Refersh Token
    cookie = response.header['set-cookie'][1].split('; ')[0].split('=');
    expect(cookie[0]).toBe('X-REFRESH-TOKEN'); // check for Refresh Token Name
    tokenPayload = jwt.verify(
      cookie[1],
      testEnv.testConfig.jwtRefreshKey,
      jwtOption
    ) as AuthToken; // Check for RefreshToken contents
    expect(tokenPayload.username).toBe('admin');
    expect(tokenPayload.type).toBe('refresh');
    expect(tokenPayload.admin).toBe(true);

    // Check Session DB
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(cookie[1]);
    if (
      new Date(queryResult[0].expiresAt) >
      new Date(new Date().getTime() + 120 * 60000 + 1000)
    ) {
      fail();
    }
    done();
  });

  // Success Login - Removed Expired Token
  test('Success - Expire Token Removed', async done => {
    // Login Request
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);

    // Another Login after 120m
    const currentDate = new Date();
    currentDate.setHours(currentDate.getHours() + 2);
    currentDate.setMinutes(currentDate.getMinutes() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);

    // Only have one Session in the DB
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    done();
  });

  test('Bad Request', async done => {
    // Request without body
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send();
    expect(response.status).toBe(400);

    // Request without username
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({password: 'rootpw!!'});
    expect(response.status).toBe(400);

    // Request without password
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin'});
    expect(response.status).toBe(400);
    let queryResult = await testEnv.dbClient.query('SELECT * FROM session');
    expect(queryResult.length).toBe(0);

    // Request with additional parameters
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!', admin: true});
    expect(response.status).toBe(400);
    queryResult = await testEnv.dbClient.query('SELECT * FROM session');
    expect(queryResult.length).toBe(0);

    done();
  });

  test('Authentication Error - User Not Found', async done => {
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user', password: 'password12!'});
    expect(response.status).toBe(401);
    const queryResult = await testEnv.dbClient.query('SELECT * FROM session');
    expect(queryResult.length).toBe(0);
    done();
  });

  test('Authentication Error - Wrong Password', async done => {
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!!'});
    expect(response.status).toBe(401);
    const queryResult = await testEnv.dbClient.query('SELECT * FROM session');
    expect(queryResult.length).toBe(0);
    done();
  });
});
