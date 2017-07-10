import * as express from 'express';
import {sign} from 'jsonwebtoken';
import * as request from 'supertest';
import {addAuthAudience, IAuthAudienceOptions} from './audience-handler';

describe('jwtAudienceHandler', () => {

  const mockSapi = {
    config: {}
  } as any;

  const options: IAuthAudienceOptions = {
    audience: 'testAudience',
    issuer: 'testIssuer',
    key: '1234'
  };

  it('returns unauthorized without a valid token', (done) => {
    const app = express();
    const plugin = addAuthAudience(mockSapi, options);
    app.use(plugin.middlewareHandlers[0]);
    app.get('*', (req, res, next) => {
      res.status(200).json({});
      next();
    });

    request(app)
      .get('/')
      .expect(401)
      .then(done)
      .catch(done.fail);
  });

  it('returns unauthorized when expired', (done) => {
    const app = express();
    const plugin = addAuthAudience(mockSapi, options);
    app.use(plugin.middlewareHandlers[0]);
    app.get('*', (req, res, next) => {
      res.status(200).json({});
      next();
    });

    const token = sign({
      aud: options.audience,
      exp: 0,
      iss: options.issuer
    }, options.key);

    request(app)
      .get('/')
      .set('Authorization', `Bearer ${token}`)
      .expect(401)
      .then(done)
      .catch(done.fail);
  });

  it('returns 401 when the auth scheme does not match', (done) => {
    const app = express();
    const plugin = addAuthAudience(mockSapi, options);
    app.use(plugin.middlewareHandlers[0]);
    app.get('*', (req, res, next) => {
      res
        .status(200)
        .json({jwt: res.locals.jwt});
      next();
    });

    const token = sign({
      aud: options.audience,
      iss: options.issuer,
      tokenInjected: true
    }, options.key);

    request(app)
      .get('/')
      .set('Authorization', `JWT ${token}`)
      .expect(401)
      .then(done)
      .catch(done.fail);
  });

  it('injects jtw token into res.locals.jwt by default when valid auth', (done) => {
    const app = express();
    const plugin = addAuthAudience(mockSapi, options);
    app.use(plugin.middlewareHandlers[0]);
    app.get('*', (req, res, next) => {
      res
        .status(200)
        .json({jwt: res.locals.jwt});
      next();
    });

    const token = sign({
      aud: options.audience,
      iss: options.issuer,
      tokenInjected: true
    }, options.key);

    request(app)
      .get('/')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .then((response) => expect(response.body.jwt.tokenInjected).toBeTruthy())
      .then(done)
      .catch(done.fail);
  });

  it('supports having no auth scheme set', (done) => {
    const opt = Object.assign({authScheme: ''}, options);
    const app = express();
    const plugin = addAuthAudience(mockSapi, opt);
    app.use(plugin.middlewareHandlers[0]);
    app.get('*', (req, res, next) => {
      res
        .status(200)
        .json({jwt: res.locals.jwt});
      next();
    });

    const token = sign({
      aud: options.audience,
      iss: options.issuer,
      tokenInjected: true
    }, options.key);

    request(app)
      .get('/')
      .set('Authorization', `${token}`)
      .expect(200)
      .then((response) => expect(response.body.jwt.tokenInjected).toBeTruthy())
      .then(done)
      .catch(done.fail);
  });
});
