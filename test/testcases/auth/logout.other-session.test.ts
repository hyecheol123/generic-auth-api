/**
 * Jest unit test for authentication API's logout from other sessions feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import MockDate from 'mockdate';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';

describe('DELETE /logout/other-sessions - Logout from other sessions', () => {
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

    // Create Two more sessions
    const currentDate = new Date();
    MockDate.set(currentDate.getTime());
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
  });

  afterEach(async () => {
    await testEnv.stop();
    MockDate.reset();
  });

  test('Success Logout from other Sessions', async done => {
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
      .delete('/logout/other-sessions')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Check Session DB Table
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE username = ?',
      ['user2']
    );
    expect(queryResult.length).toBe(1); // only current session exists
    expect(queryResult[0].token).toBe(refreshToken);
    done();
  });

  test('Fail - Invalid Token', async done => {
    // User Login (Retrieve Token)
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    const accessToken = response.header['set-cookie'][0]
      .split('; ')[0]
      .split('=')[1];

    // Logout Request
    response = await request(testEnv.expressServer.app)
      .delete('/logout/other-sessions')
      .set('Cookie', [`X-REFRESH-TOKEN=${accessToken}`]);
    expect(response.status).toBe(401);

    // Check Session DB Table
    // Still need to be logged in + Other sessions alive
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE username = ?',
      ['user2']
    );
    expect(queryResult.length).toBe(3);
    done();
  });

  test('Fail - Token NOT in DB', async done => {
    // User Login (Retrieve Token)
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    const refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];
    // User Logout (Remove token from DB)
    response = await request(testEnv.expressServer.app)
      .delete('/logout')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(200);

    // Logout Request
    response = await request(testEnv.expressServer.app)
      .delete('/logout/other-sessions')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(401);

    // Check Session DB Table
    // Other sessions alive
    const queryResult = await testEnv.dbClient.query(
      'SELECT * FROM session WHERE username = ?',
      ['user2']
    );
    expect(queryResult.length).toBe(2);
    done();
  });
});
