// tslint:disable:no-duplicate-imports
import {IAuthenticator} from '@sakuraapi/core';
import * as debugInit from 'debug';
import * as express from 'express';
import {NextFunction, Request, Response} from 'express';
import {sign} from 'jsonwebtoken';
import * as request from 'supertest';
import {addAuthAudience, IAuthAudienceOptions} from './audience-handler';
// tslint:enable:no-duplicate-imports

const debug = debugInit('auth-audience:test-handler');
describe('jwtAudienceHandler', () => {

  const mockSapi = {
    config: {}
  } as any;

  const regularOptions: IAuthAudienceOptions = {
    audience: 'testAudience',
    issuer: 'testIssuer',
    key: '1234'
  };

  const domainedOptions: IAuthAudienceOptions = {
    domainedAudiences: {
      default: {
        audience: 'audience2.somedomain.somewhere',
        issuer: 'issuer2.somedomain.somewhere',
        key: '456'
      },
      field: {
        audience: 'audience1.somedomain.somewhere',
        issuer: 'issuer1.somedomain.somewhere',
        key: '123'
      }
    }
  };

  const arrayOptions: IAuthAudienceOptions = {
    audience: ['testAudience1', 'testAudience2'],
    issuer: 'testIssuer',
    key: 'wxyz'
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
    opt = Object.assign(opt, regularOptions);
    debug('opt ', opt);

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

    const result = await request(setupTestApp(regularOptions))
      .get('/')
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;
    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });

  it('returns 401 when expired', async (done) => {

    const token = sign({
      aud: regularOptions.audience,
      exp: 0,
      iss: regularOptions.issuer
    }, regularOptions.key);

    const result = await request(setupTestApp(regularOptions))
      .get('/')
      .set('Authorization', `Bearer ${token}`)
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });

  it('returns 401 when token is invalid', async (done) => {
    const result = await request(setupTestApp(regularOptions))
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
      aud: regularOptions.audience,
      iss: regularOptions.issuer,
      tokenInjected: true
    }, regularOptions.key);

    const result = await request(setupTestApp(regularOptions))
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
      aud: regularOptions.audience,
      iss: regularOptions.issuer,
      tokenInjected: true
    };
    const token = sign(payload, regularOptions.key);

    const result = await request(setupTestApp(regularOptions))
      .get('/')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.jwt.aud).toBe(payload.aud);
    expect(body.jwt.iss).toBe(payload.iss);
    expect(body.jwt.tokenInjected).toBe(payload.tokenInjected);

    done();
  });

  it('supports having no auth scheme set', async (done) => {

    const payload = {
      aud: regularOptions.audience,
      iss: regularOptions.issuer,
      tokenInjected: true
    };
    const token = sign(payload, regularOptions.key);

    const result = await request(setupTestApp({authScheme: ''}))
      .get('/')
      .set('Authorization', `${token}`)
      .expect(200)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.jwt.aud).toBe(payload.aud);
    expect(body.jwt.iss).toBe(payload.iss);
    expect(body.jwt.tokenInjected).toBe(payload.tokenInjected);
    done();
  });

  it('returns 401 when token is invalid and no auth scheme set', async (done) => {
    const result = await request(setupTestApp(regularOptions))
      .get('/')
      .set('Authorization', `123`)
      .expect(401)
      .catch(done.fail);

    const body = (result as any).body;

    expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
    done();
  });
  describe('domained Audiences', () => {
    it('reads domained audience config', async (done) => {
      const result = await request(setupTestApp(domainedOptions))
        .get('/')
        .set('Authorization', `abcd`)
        .expect(401)
        .catch(done.fail);
      const body = (result as any).body;

      expect(body.fallthrough).not.toBeDefined('Auth should not have gotten here');
      done();
    });

    it('processes the default domain', async (done) => {
      const aud = domainedOptions.domainedAudiences.default.audience;
      const key = domainedOptions.domainedAudiences.default.key;
      const iss = domainedOptions.domainedAudiences.default.issuer;

      const payload = {
        aud,
        domain: 'default',
        iss,
        tokenInjected: true
      };
      const token = sign(payload, key);

      const result = await
        request(setupTestApp(domainedOptions))
          .get('/')
          .set('Authorization', `${token}`)
          .expect(200)
          .catch(done.fail);
      done();
    });

    it('processes the default domain implicitly (not expressed in the token)', async (done) => {
      const aud = domainedOptions.domainedAudiences.default.audience;
      const key = domainedOptions.domainedAudiences.default.key;
      const iss = domainedOptions.domainedAudiences.default.issuer;

      const payload = {
        aud,
        iss,
        tokenInjected: true
      };
      const token = sign(payload, key);

      const result = await
        request(setupTestApp(domainedOptions))
          .get('/')
          .set('Authorization', `${token}`)
          .expect(200)
          .catch(done.fail);
      done();
    });

    it('processes the a non-default domain', async (done) => {
      const domain = 'field';
      const aud = domainedOptions.domainedAudiences[domain].audience;
      const key = domainedOptions.domainedAudiences[domain].key;
      const iss = domainedOptions.domainedAudiences[domain].issuer;

      const payload = {
        aud,
        domain,
        iss,
        tokenInjected: true
      };
      const token = sign(payload, key);

      const result = await
        request(setupTestApp(domainedOptions))
          .get('/')
          .set('Authorization', `${token}`)
          .expect(200)
          .catch(done.fail);
      done();
    });

    it('fails if you give the key of the other server', async (done) => {
      const domain = 'field';
      const aud = domainedOptions.domainedAudiences[domain].audience;
      const key = domainedOptions.domainedAudiences.default.key;
      const iss = domainedOptions.domainedAudiences[domain].issuer;

      const payload = {
        aud,
        domain,
        iss,
        tokenInjected: true
      };
      const token = sign(payload, key);

      const result = await
        request(setupTestApp(domainedOptions))
          .get('/')
          .set('Authorization', `${token}`)
          .expect(401)
          .catch(done.fail);
      done();
    });
  });
});
