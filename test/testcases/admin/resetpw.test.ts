/**
 * Jest unit test for authentication API's user reset password admin feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';
// eslint-disable-next-line node/no-unpublished-import
import MockDate from 'mockdate';

describe('PUT /admin/user/{username}/password - Reset Password', () => {
  let testEnv: TestEnv;
  let accessToken: string;
  let currentDate: Date;

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
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    accessToken = response.header['set-cookie'][0].split('; ')[0].split('=')[1];

    // Set MockDate
    currentDate = new Date();
    MockDate.set(currentDate.getDate());
  });

  afterEach(async () => {
    await testEnv.stop();
    MockDate.reset();
  });

  test('Success - Delete Non-Admin User', async done => {
    // Login with the target user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'password'});
    expect(response.status).toBe(200);
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'password'});
    expect(response.status).toBe(200);

    // Password Change Request
    response = await request(testEnv.expressServer.app)
      .put('/admin/user/user1/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send({newPassword: 'newPW123!!'});
    expect(response.status).toBe(200);

    // DB Check - User
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user1',
      new Date(queryResult[0].membersince).toISOString(),
      'newPW123!!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(0);

    // Able to Login with new PW
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'newPW123!!'});
    expect(response.status).toBe(200);
    done();
  });

  test('Success - Delete Admin User', async done => {
    // Login with the target user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);

    // Password Change Request
    response = await request(testEnv.expressServer.app)
      .put('/admin/user/admin/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send({newPassword: 'newPW123!!'});
    expect(response.status).toBe(200);

    // DB Check - User
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'admin',
      new Date(queryResult[0].membersince).toISOString(),
      'newPW123!!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(0);

    // Able to Login with new PW
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'newPW123!!'});
    expect(response.status).toBe(200);
    done();
  });

  test('Fail - Use Non-Admin Access Token', async done => {
    // Login with the target user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'password'});
    expect(response.status).toBe(200);
    accessToken = response.header['set-cookie'][0].split('; ')[0].split('=')[1];

    // Password Change Request
    response = await request(testEnv.expressServer.app)
      .put('/admin/user/user1/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send({newPassword: 'newPW123!!'});
    expect(response.status).toBe(401);

    // DB Check - User (Not Changed)
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user1',
      new Date(queryResult[0].membersince).toISOString(),
      'password'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session (Not Logged Out)
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);

    // Not Able to Login with new PW
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'newPW123!!'});
    expect(response.status).toBe(401);
    done();
  });

  test('Fail - Bad Request', async done => {
    // Login with the target user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);

    // Password Change Request - Wrong Key
    response = await request(testEnv.expressServer.app)
      .put('/admin/user/user1/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send({password: 'newPW123!!'});
    expect(response.status).toBe(400);

    // Password Change Request - No Body
    response = await request(testEnv.expressServer.app)
      .put('/admin/user/user1/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`]);
    expect(response.status).toBe(400);

    // Password Change Request - Additional Field
    response = await request(testEnv.expressServer.app)
      .put('/admin/user/user1/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send({currentPW: 'password', newPassword: 'newPW123!!'});
    expect(response.status).toBe(400);

    // DB Check - User (Not Changed)
    const queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user1'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user1',
      new Date(queryResult[0].membersince).toISOString(),
      'password'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // Not Able to Login with new PW
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user1', password: 'newPW123!!'});
    expect(response.status).toBe(401);
    done();
  });

  test('Fail - Not Existing User', async done => {
    // Password Change Request
    const response = await request(testEnv.expressServer.app)
      .put('/admin/user/user3/password')
      .set('Cookie', [`X-ACCESS-TOKEN=${accessToken}`])
      .send({newPassword: 'newPW123!!'});
    expect(response.status).toBe(404);
    done();
  });
});
