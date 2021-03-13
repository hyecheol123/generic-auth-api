/**
 * Jest unit test for authentication API's user delete admin feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';

describe('DELETE /admin/user/{username} - Admin Feature: DELETE User', () => {
  let testEnv: TestEnv;
  let accessToken: string;

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

    // Login with admin user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    accessToken = response.header['set-cookie'][0].split('; ')[0].split('=')[1];

    // Login with test target
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'password'});
    expect(response.status).toBe(200);
  });

  afterEach(async () => {
    await testEnv.stop();
  });

  test('Success Delete User', async done => {
    // Request
    const response = await request(testEnv.expressServer.app)
      .delete('/admin/user/user1')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`]);
    expect(response.status).toBe(200);

    // DB Check
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(0);
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(0);
    done();
  });

  test('Fail - Delete with Non-Admin Credentials', async done => {
    // Login with Non-Admin Account
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    accessToken = response.header['set-cookie'][0].split('; ')[0].split('=')[1];

    // Request
    response = await request(testEnv.expressServer.app)
      .delete('/admin/user/user1')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`]);
    expect(response.status).toBe(401);

    // DB Check
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    done();
  });

  test('Fail - Invalid AccessToken', async done => {
    // Request
    const response = await request(testEnv.expressServer.app)
      .delete('/admin/user/user1')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}abcd`]);
    expect(response.status).toBe(401);

    // DB Check
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    done();
  });

  test('Fail - Delete Not Existing User', async done => {
    // Request
    const response = await request(testEnv.expressServer.app)
      .delete('/admin/user/user3')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`]);
    expect(response.status).toBe(404);
    done();
  });
});
