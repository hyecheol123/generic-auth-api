/**
 * Jest unit test for authentication API's Change Password feature
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
  let refreshToken: string;
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

    // Create Two more sessions
    currentDate = new Date();
    MockDate.set(currentDate.getDate());
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());

    // Retrieve refreshToken for the user
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'password12!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];
  });

  afterEach(async () => {
    await testEnv.stop();
    MockDate.reset();
  });

  test('Success - Change Password (Admin User)', async done => {
    // Login with admin user & retrieve refresh token
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());

    // Retrieve refreshToken for the user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Password change request
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'rootpw!!', newPassword: 'newpw123'});
    expect(response.status).toBe(200);

    // DB Check - User: Password Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'admin',
      new Date(queryResult[0].membersince).toISOString(),
      'newpw123'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(refreshToken);

    // DB Check - Session: Other user's session not cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session where username = 'user2'"
    );
    expect(queryResult.length).toBe(3);

    // Login with changed password
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'newpw123'});
    expect(response.status).toBe(200);
    done();
  });

  test('Success - Change Password (Non-Admin User)', async done => {
    // Password change request
    let response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'password12!', newPassword: 'newpw123'});
    expect(response.status).toBe(200);

    // DB Check - User: Password Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user2',
      new Date(queryResult[0].membersince).toISOString(),
      'newpw123'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(refreshToken);

    // Login with changed password
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'newpw123'});
    expect(response.status).toBe(200);
    done();
  });
});
