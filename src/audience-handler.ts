import {SakuraApi, SakuraApiPluginResult} from '@sakuraapi/api';
import {NextFunction, Request, Response} from 'express';
import {verify} from 'jsonwebtoken';

export type jsonBuilder = (req: Request, res: Response) => Promise<any>;
export type jsonErrBuilder = (err: any, req: Request, res: Response) => Promise<any>;
export type authorizedHandler = (jwtPayload: any, req: Request, res: Response) => Promise<any>;
export type verifyErrorHandler = (err: Error, jwtPayload: any, req: Request, res: Response) => Promise<any>;

/**
 * Allows [[IAuthAudienceOptions.routeExclusion]] to be narrowed to specific HTTP methods.
 * For example:
 * <pre>
 *     routeExclusion = [
 *        {
 *          method: 'get',
 *          regex: /^\/user/
 *        }
 *     ]
 * </pre>
 */
export interface IRouteExclusion {
  method?: { [key: string]: boolean };
  regex: RegExp;
}

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
   * The authentication scheme expected. For example, `Bearer`. Set to empty string if no authentication
   * scheme is expected
   */
  authScheme?: string;

  /**
   * Defines a list of routes that will not return a `serverErrorStatusCode`. If a JWT is present, it will still be
   * added. The array can be a combination of Regular Expressions or [[RouteExclusion]]. [[RouteExclusion]] allows
   * you to further narrow the match to specific HTTP methods.
   */
  excludedRoutes?: IRouteExclusion[] | RegExp[];

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
   * Called when the jwt token is successfully verified. If you provide this function, you are responsible for
   * storing the `jwtPayload` in a way that's accessible by the rest of the handler chain. If not provided,
   * the `jwtPayload` can be found on the Response object: `res.locals.jwt`.
   */
  onAuthorized?: authorizedHandler;

  /**
   * Called when there's a verification error (if defined). Allows you to intercept error handling for customization.
   * If not provided, the status code [[unauthorizedStatusCode]] is sent by default. If it is provided, resolve
   * the promise when done to prevent [[unauthorizedStatusCode]], otherwise, reject and [[unauthorizedStatusCode]]
   * will be sent
   */
  onVerifyError?: verifyErrorHandler;

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

export function addAuthAudience(sapi: SakuraApi, options: IAuthAudienceOptions): SakuraApiPluginResult {
  options = options || {} as IAuthAudienceOptions;

  options.audience = options.audience
    || ((sapi.config.authentication || {} as any).jwt || {} as any).audience
    || undefined;

  options.authHeader = options.authHeader || 'Authorization';

  options.authScheme = (options.authScheme === '') ? '' : options.authScheme || 'Bearer';

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

  options.onAuthorized = options.onAuthorized || ((payload, req, res) => {
      res.locals.jwt = payload;
      return Promise.resolve();
    });

  options.serverErrorStatusCode = options.serverErrorStatusCode || 500;
  options.serverErrorJson = options.serverErrorJson || (() => {
      return Promise.resolve(null);
    });

  options.unauthorizedStatusCode = options.unauthorizedStatusCode || 401;
  options.unauthorizedJson = options.unauthorizedJson || (() => {
      return Promise.resolve(null);
    });

  const baseUrlOffset = (sapi.baseUrl) ? sapi.baseUrl.length : 0;

  function jwtAudienceHandler(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.get(options.authHeader || 'Authorization');
    const reqAuth = !isExcludedRoute(options, baseUrlOffset, req, res);

    if (!authHeader && reqAuth) {
      sendUnauthorized(options, req, res, next);
      return;
    }

    const authHeaderParts = (authHeader)
      ? authHeader.split(' ')
      : [];

    let token;
    if (options.authScheme === '' || authHeaderParts.length === 1) {
      // no auth scheme
      if (authHeader === options.authScheme && reqAuth) {
        // auth scheme was provided with no token
        sendUnauthorized(options, req, res, next);
        return;
      }

      token = authHeader;
    } else if (authHeaderParts.length === 2) {
      // with auth scheme

      if (authHeaderParts[0].toLowerCase() !== options.authScheme.toLowerCase() && reqAuth) {
        // auth scheme doesn't match expected
        sendUnauthorized(options, req, res, next);
        return;
      }

      token = authHeaderParts[1];
    } else {
      // auth header has unexpected content
      if (reqAuth) {
        sendUnauthorized(options, req, res, next);
        return;
      }
    }

    new Promise(
      (resolve, reject) => {
        verify(token, options.key, options.jwtVerifyOptions, (err, payload) => {
          (err && reqAuth)
            ? reject(err)
            : resolve(payload);
        });
      })
      .then((payload) => {
        options
          .onAuthorized(payload, req, res)
          .then(() => next())
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
              })
              .catch((unexpectedError) => {
                if (options.nextOnError) {
                  next(unexpectedError);
                }
              });
          });
      })
      .catch((err) => {
        if (options.onVerifyError) {
          options
            .onVerifyError(err, token, req, res)
            .then(() => next())
            .catch(() => {
              sendUnauthorized(options, req, res, next);
            });
        } else {
          sendUnauthorized(options, req, res, next);
        }
      });
  }

  return {
    middlewareHandlers: [jwtAudienceHandler]
  };
}

function isExcludedRoute(options, baseUrlOffset: number, req: Request, res: Response) {

  if (!options.excludedRoutes) {
    return false;
  }

  const path = req.originalUrl.split('?')[0].substring(baseUrlOffset);

  let result = false;
  for (const regex of options.excludedRoutes) {
    if (regex instanceof RegExp) {
      if (regex.test(path)) {
        result = true;
        break;
      }
      continue;
    }

    if (!regex.method || (regex.method[req.method])) {
      if (regex.regex.test(path)) {
        result = true;
        break;
      }
      continue;
    }
  }

  return result;
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
