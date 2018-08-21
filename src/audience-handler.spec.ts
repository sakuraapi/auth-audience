// tslint:disable:no-duplicate-imports
import { IAuthenticator } from '@sakuraapi/core';
import * as express       from 'express';
import {
  NextFunction,
  Request,
  Response
}                         from 'express';
import { sign }           from 'jsonwebtoken';
import * as request       from 'supertest';
import {
  addAuthAudience,
  IAuthAudienceOptions
}                         from './audience-handler';
// tslint:enable:no-duplicate-imports

describe('jwtAudienceHandler', () => {

  const mockSapi = {
    config: {}
  } as any;

  const options: IAuthAudienceOptions = {
    audience: ['testAudience1', 'testAudience2'],
    issuer: 'testIssuer',
    key: '1234'
  };

  function getMockHandler(authAudience: IAuthenticator) {
    return async (req: Request, res: Response, next: NextFunction) => {

      const result = await authAudience.authenticate.bind(authAudience)(req, res);

      if (!result.success) {
        return res.status(result.status).send(result.data || undefined);
      }
      next();

    };
  }

  function setupTestApp(opt?: any) {
    opt = opt || {};
    opt = Object.assign(opt, options);

    const app = express();

    const authAudience: IAuthenticator = addAuthAudience(mockSapi, opt).authenticators[0];

    app.use(getMockHandler((authAudience)));
    app.get('*', (req, res, next) => {
      res.status(200).json({
        fallthrough: true,
        jwt: res.locals.jwt
      });
      next();
    });

    return app;
  }

  it('returns 401 with no Authorization header (#7)', async (done) => {

    const result = await request(setupTestApp())
      .get('/')
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;
    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });

  it('returns 401 when expired', async (done) => {

    const token = sign({
      aud: options.audience,
      exp: 0,
      iss: options.issuer
    }, options.key);

    const result = await request(setupTestApp())
      .get('/')
      .set('Authorization', `Bearer ${token}`)
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });

  it('returns 401 when token is invalid', async (done) => {
    const result = await request(setupTestApp())
      .get('/')
      .set('Authorization', `Bearer 123`)
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });

  it('returns 400 when the auth scheme does not match', async (done) => {
    const token = sign({
      aud: options.audience,
      iss: options.issuer,
      tokenInjected: true
    }, options.key);

    const result = await request(setupTestApp())
      .get('/')
      .set('Authorization', `JWT ${token}`)
      .expect(400)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });

  it('injects jtw token into res.locals.jwt by default when valid auth', async (done) => {

    const payload = {
      aud: options.audience,
      iss: options.issuer,
      tokenInjected: true
    };
    const token = sign(payload, options.key);

    const result = await request(setupTestApp())
      .get('/')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.jwt.aud).toEqual(payload.aud);
    expect(body.jwt.iss).toBe(payload.iss);
    expect(body.jwt.tokenInjected).toBe(payload.tokenInjected);

    done();
  });

  it('supports having no auth scheme set', async (done) => {

    const payload = {
      aud: options.audience,
      iss: options.issuer,
      tokenInjected: true
    };
    const token = sign(payload, options.key);

    const result = await request(setupTestApp({authScheme: ''}))
      .get('/')
      .set('Authorization', `${token}`)
      .expect(200)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.jwt.aud).toEqual(payload.aud);
    expect(body.jwt.iss).toBe(payload.iss);
    expect(body.jwt.tokenInjected).toBe(payload.tokenInjected);
    done();
  });

  it('returns 401 when token is invalid and no auth scheme set', async (done) => {
    const result = await request(setupTestApp())
      .get('/')
      .set('Authorization', `123`)
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });
});
