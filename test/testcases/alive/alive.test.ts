/**
 * Jest unit test for authentication API's server alive/ready check
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';

describe('Server Alive/Ready Check', () => {
  let testEnv: TestEnv;

  beforeAll(() => {
    // Set new timeout
    jest.setTimeout(120000);
  });

  beforeEach(async () => {
    // Setup TestEnv
    testEnv = new TestEnv(expect.getState().currentTestName);

    // Start Test Environment
    await testEnv.start([]);
  });

  afterEach(async () => {
    await testEnv.stop();
  });

  // Server alive
  test('GET /alive - Server Alive', async () => {
    // Check server is alive
    const response = await request(testEnv.expressServer.app).get('/alive');
    expect(response.status).toBe(200);
  });

  // Server Ready
  test('GET /alive/ready - Server Ready', async () => {
    // Check server is ready
    const response = await request(testEnv.expressServer.app).get(
      '/alive/ready'
    );
    expect(response.status).toBe(200);
  });
});
