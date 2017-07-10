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

  describe('does not return 401 for excluded routes', () => {
    const opt = Object.assign({
      excludedRoutes: [
        /^\/$/,
        {
          regex: /^\/test1$/
        },
        {
          method: {POST: true},
          regex: /^\/test2$/
        }
      ]
    }, options);
    const app = express();
    const plugin = addAuthAudience(mockSapi, opt);
    app.use(plugin.middlewareHandlers[0]);
    app.all('*', (req, res, next) => {
      res
        .status(200)
        .json({jwt: res.locals.jwt || 'not-defined'});
      next();
    });

    it('routes not excluded still require auth', (done) => {
      request(app)
        .get('/secure_route')
        .expect(401)
        .then(done)
        .catch(done.fail);
    });


    it('does not include the query as part of the route being evaluated', (done) => {
      request(app)
        .get('/?queryParam="a"')
        .expect(200)
        .then((response) => {
          expect(response.body.jwt).toBe('not-defined');
        })
        .then(done)
        .catch(done.fail);
    });

    it('simple route', (done) => {
      request(app)
        .get('/')
        .expect(200)
        .then((response) => {
          expect(response.body.jwt).toBe('not-defined');
        })
        .then(done)
        .catch(done.fail);
    });

    it('exclude route with RouteExclusion with just Regex', (done) => {
      request(app)
        .get('/test1')
        .expect(200)
        .then((response) => {
          expect(response.body.jwt).toBe('not-defined');
        })
        .then(done)
        .catch(done.fail);
    });

    it('exclude route with RouteExclusion with Regex and Method', (done) => {
      request(app)
        .post('/test2')
        .expect(200)
        .then((response) => {
          expect(response.body.jwt).toBe('not-defined');
        })
        .then(done)
        .catch(done.fail);
    });

    it('does not exclude route with RouteExclusion with matching Regex and not matching Method', (done) => {
      request(app)
        .get('/test2')
        .expect(401)
        .then(done)
        .catch(done.fail);
    });

    it('injects the token for routes not requiring auth when the token is present', (done) => {
      const token = sign({
        aud: options.audience,
        iss: options.issuer,
        tokenInjected: true
      }, options.key);

      request(app)
        .post('/test2')
        .set('Authorization', `${token}`)
        .expect(200)
        .then((response) => {
          expect(response.body.jwt.tokenInjected).toBeTruthy();
        })
        .then(done)
        .catch(done.fail);
    });

    describe('baseUri', () => {

      const opt = Object.assign({
        excludedRoutes: [
          /^\/$/
        ]
      }, options);

      const mockSapiBaseUri = Object.assign({
        baseUri: '/testApi'
      }, mockSapi);

      const app = express();
      const plugin = addAuthAudience(mockSapiBaseUri, opt);
      app.use(plugin.middlewareHandlers[0]);
      app.all('*', (req, res, next) => {
        res
          .status(200)
          .json({jwt: res.locals.jwt || 'not-defined'});
        next();
      });

      it('strips the base url before processing exclusions', (done) => {
        request(app)
          .get('/testApi/')
          .expect(200)
          .then((response) => {
            expect(response.body.jwt).toBe('not-defined');
          })
          .then(done)
          .catch(done.fail);
      });

      it('sanity check to make sure it is still failing properly', (done) => {
        request(app)
          .get('/')
          .expect(401)
          .then(done)
          .catch(done.fail);
      });
    });
  });
});
