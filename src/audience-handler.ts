import {SakuraApi, SakuraApiModuleResult} from '@sakuraapi/api';
import {NextFunction, Request, Response} from 'express';
import {verify} from 'jsonwebtoken';

export type jsonBuilder = (req: Request, res: Response) => Promise<any>;
export type jsonErrBuilder = (err: any, req: Request, res: Response) => Promise<any>;

export interface IAuthAudienceOptions {
  /**
   * The expected audience to verify; Leave undefined to not check
   */
  audience?: string;

  /**
   * The header from which to get the token
   */
  authHeader?: string;
  /**
   * The authentication scheme expected. For example, `Bearer`. Leave undefined if no authentication
   * scheme is expected
   */
  authScheme?: string;

  /**
   * The issuer expected; Leave undefined to not check
   */
  issuer?: string;

  /**
   * See: https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
   * If not provided, defaults to `options.audience` and `options.issuer`. If either of those are not provided
   * an attempt is made to find the missing value in SakuraApi's config under `authorization.jwt.audience` and
   * `authorization.jwt.issuer`.
   */
  jwtVerifyOptions?: any;

  /**
   * The public or private key to use for verifying the signature of the JWT token
   */
  key?: string;

  /**
   * False (default) to not call next() on when unauthorized. Set to true if you want the handler to callback
   * and pass control to the next handler even if the jwt token doesn't authenticate. If true, the error object
   * will be passed to next if there was an error.
   */
  nextOnError?: boolean;

  /**
   * The status code to return if there's an unexpected error (500 by default)
   */
  serverErrorStatusCode?: number;
  /**
   * A function that generates a json object to return if there's a server error. If none is provided,
   * the server error response will not have a body.
   */
  serverErrorJson?: jsonErrBuilder;

  /**
   * The status code to return if the token is invalid (401 by default)
   */
  unauthorizedStatusCode?: number;
  /**
   * A function that generates a json object to return if the token is not authorized. If none is provided,
   * the server response will not have a body.
   */
  unauthorizedJson?: jsonBuilder;
}

function addAuthAudience(sapi: SakuraApi, options: IAuthAudienceOptions): SakuraApiModuleResult {
  options = options || {} as IAuthAudienceOptions;

  options.audience = options.audience
    || ((sapi.config.authentication || {} as any).jwt || {} as any).audience
    || undefined;

  options.authHeader = options.authHeader || 'Authorization';
  options.authScheme = options.authScheme || 'Bearer';

  options.issuer = options.issuer
    || ((sapi.config.authentication || {} as any).jwt || {} as any).issuer
    || undefined;

  options.jwtVerifyOptions = options.jwtVerifyOptions || {
      audience: options.audience,
      issuer: options.issuer
    };

  options.key = options.key
    || (((sapi.config || {} as any).authentication || {} as any).jwt || {} as any).key
    || '';

  options.serverErrorStatusCode = options.serverErrorStatusCode || 500;
  options.serverErrorJson = options.serverErrorJson || (() => {
      return Promise.resolve(null);
    });

  options.unauthorizedStatusCode = options.unauthorizedStatusCode || 401;
  options.unauthorizedJson = options.unauthorizedJson || (() => {
      return Promise.resolve(null);
    });

  function jwtAudienceHandler(req: Request, res: Response, next: NextFunction) {
    const body = req.body || {};

    const authHeader = req.get(options.authHeader || 'Authorization');

    if (!authHeader) {
      sendUnauthorized(options, req, res, next);
      return;
    }

    const authHeaderParts = authHeader.split(' ');
    let token;

    if (authHeaderParts.length === 1) {
      // no auth scheme

      if (authHeader === options.authScheme) {
        // auth scheme was provided with no token
        sendUnauthorized(options, req, res, next);
        return;
      }

      token = authHeader;
    } else if (authHeaderParts.length === 2) {
      // with auth scheme

      if (authHeaderParts[0].toLowerCase() !== options.authScheme) {
        // auth scheme doesn't match expected
        sendUnauthorized(options, req, res, next);
        return;
      }

      token = authHeaderParts[1];
    } else {
      // auth header has unexpected content
      sendUnauthorized(options, req, res, next);
      return;
    }

    new Promise(
      (resolve, reject) => {
        verify(token, options.key, options.jwtVerifyOptions, (err, decoded) => {
          (err) ? reject(err) : resolve(decoded);
        });
      })
      .then((payload) => {
        res.locals.jwt = payload;
        next();
      })
      .catch(() => {
        sendUnauthorized(options, req, res, next);
      });
  }

  return {
    // TODO needs to be added to SakuraApi
    // beforeHandlers: [
    //   jwtAudienceHandler
    // ],
    models: [],
    routables: []
  };
}

function sendUnauthorized(options, req, res, next) {
  options
    .unauthorizedJson(req, res)
    .then((json) => {
      res
        .status(options.unauthorizedStatusCode)
        .json(json);
      if (options.nextOnError) {
        next();
      }

    })
    .catch((err) => {
      options
        .serverErrorJson(err, req, res)
        .then((errJson) => {
          res
            .status(options.serverErrorStatusCode)
            .json(errJson);
          if (options.nextOnError) {
            next(errJson);
          }
        });
    });
}
