import {
  AuthenticationHandler,
  AuthenticatorPlugin,
  AuthenticatorPluginResult,
  IAuthenticator,
  IAuthenticatorConstructor,
  SakuraApi,
  SakuraApiPluginResult
} from '@sakuraapi/core';
import * as debugInit from 'debug';
import {Request, Response} from 'express';
import {decode, verify} from 'jsonwebtoken';

export type jsonBuilder = (req: Request, res: Response) => Promise<any>;
export type jsonErrBuilder = (err: any, req: Request, res: Response) => Promise<any>;
export type authorizedHandler = (jwtPayload: any, req: Request, res: Response) => Promise<any>;
export type verifyErrorHandler = (err: Error, jwtPayload: any, req: Request, res: Response) => Promise<any>;

const debug = debugInit('auth-audience:handler');

/**
 * interface used by domainedAudiences
 */
export interface IAudiences {
  [domain: string]: {
    [server: string]: string
  };
}

export interface IAuthAudienceOptions {
  /**
   * The expected audience to verify; Leave undefined to not check
   */
  audience?: string | string[];

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
   * The issuer expected; Leave undefined to not check
   */
  issuer?: string;

  /**
   * The a dictionary of domains and their keys
   */
  domainedAudiences?: IAudiences;

  /**
   * the expiration time on the key
   */
  exp?: string;

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
   * Called when the jwt token is successfully verified. If you provide this function, you are responsible for
   * storing the `jwtPayload` in a way that's accessible by the rest of the handler chain. If not provided,
   * the `jwtPayload` can be found on the Response object: `res.locals.jwt`.
   */
  onAuthorized?: authorizedHandler;

  /**
   * Called when there's a verification error (if defined). Allows you to intercept error handling for customization.
   *
   * [[IAuthAudienceOptions.unauthorizedStatusCode]] will be returned when verification of credentials fail.
   *
   * Return a the json object that is the body of the response.
   */
  onVerifyError?: verifyErrorHandler;

  /**
   * The status code to return if there's an unexpected error (500 by default)
   */
  serverErrorStatusCode?: number;

  /**
   * A function that generates a json object to return if there's a server error. If none is provided,
   * the server error response will not have a body.
   *
   * Return a the json object that is the body of the response.
   */
  serverErrorJson?: jsonErrBuilder;

  /**
   * The status code to return if the token is invalid (401 by default)
   */
  unauthorizedStatusCode?: number;

  /**
   * A function that generates a json object to return if the token is not authorized. If none is provided,
   * the server response will not have a body.
   *
   * Return a the json object that is the body of the response.
   */
  unauthorizedJson?: jsonBuilder;

  /**
   * The status code to return if the request is bad / malformed (400 by default)
   */
  badRequestStatusCode?: number;

  /**
   * A function that generates a json object to return if the request is bad / malformed. If none is provided,
   * the server response will not have a body.
   *
   * Return a the json object that is the body of the response.
   */
  badRequestJson?: jsonErrBuilder;
}

@AuthenticatorPlugin()
export class AuthAudience implements IAuthenticator, IAuthenticatorConstructor {

  constructor(private authenticators: AuthenticationHandler[]) {
  }

  /**
   * Attempts each of the AuthenticationHandlers. Upon success, return the result of the successful handler,
   * otherwise, return the result of the first failure.
   * @param req Express Request
   * @param res Express Response
   * @returns {Promise<AuthenticatorPluginResult>}
   */
  async authenticate(req, res): Promise<AuthenticatorPluginResult> {
    debug('.authenticate called');
    let firstFailure: AuthenticatorPluginResult;

    for (const auth of this.authenticators) {
      const authAttempt = await auth(req, res);

      if (authAttempt && !authAttempt.success && !firstFailure) {
        firstFailure = authAttempt;
      } else {
        return authAttempt;
      }
    }

    return firstFailure;
  }
}

export function addAuthAudience(sapi: SakuraApi, options: IAuthAudienceOptions): SakuraApiPluginResult {
  debug('.addAuthAudience called');
  options = options || {} as IAuthAudienceOptions;

  options.audience = options.audience
    || ((sapi.config.authentication || {} as any).jwt || {} as any).audience
    || undefined;
  debug('options.audience ', options.audience);

  options.authHeader = options.authHeader || 'Authorization';

  options.authScheme = (options.authScheme === '') ? '' : options.authScheme || 'Bearer';

  options.issuer = options.issuer
    || ((sapi.config.authentication || {} as any).jwt || {} as any).issuer
    || undefined;
  options.jwtVerifyOptions = options.jwtVerifyOptions || {
    audience: options.audience,
    issuer: options.issuer
  };
  debug('options.jwtVerifyOptions ', options.jwtVerifyOptions);

  options.key = options.key
    || (((sapi.config || {} as any).authentication || {} as any).jwt || {} as any).key
    || '';

  options.onAuthorized = options.onAuthorized || (async (payload, req, res) => {
    res.locals.jwt = payload;
  });

  options.onVerifyError = options.onVerifyError || (async (err, token, req, res) => {
    return null;
  });

  options.serverErrorStatusCode = options.serverErrorStatusCode || 500;
  options.serverErrorJson = options.serverErrorJson || (async () => {
    return null;
  });

  options.unauthorizedStatusCode = options.unauthorizedStatusCode || 401;
  options.unauthorizedJson = options.unauthorizedJson || (async () => {
    return null;
  });

  options.badRequestStatusCode = options.badRequestStatusCode || 400;
  options.badRequestJson = options.badRequestJson || (async () => {
    return null;
  });

  async function jwtAudienceHandler(req: Request, res: Response): Promise<AuthenticatorPluginResult> {
    debug('.jwtAudienceHandler called');
    let token;

    try {
      const authHeader = req.get(options.authHeader || 'Authorization');

      if (!authHeader) {
        const err = Error('NO_AUTHORIZATION_HEADER');
        token = '';

        return {
          data: await options.onVerifyError(err, token, req, res),
          error: err,
          status: options.unauthorizedStatusCode,
          success: false
        } as AuthenticatorPluginResult;
      }

      const authHeaderParts = (authHeader)
        ? authHeader.split(' ')
        : [];

      if (options.authScheme === '' || authHeaderParts.length === 1) {
        // no auth scheme
        if (authHeader === options.authScheme) {
          // auth scheme was provided with no token
          const missingAuthTokenErr = new Error('NO_AUTH_TOKEN');
          return {
            data: await options.badRequestJson(missingAuthTokenErr, req, res),
            error: missingAuthTokenErr,
            status: options.badRequestStatusCode,
            success: false
          } as AuthenticatorPluginResult;
        }

        token = authHeader;
      } else if (authHeaderParts.length === 2) {
        // with auth scheme
        if (authHeaderParts[0].toLowerCase() !== options.authScheme.toLowerCase()) {
          // auth scheme doesn't match expected
          const unexpectedAuthSchemeErr = new Error('UNEXPECTED_AUTH_SCHEME');
          return {
            data: await options.badRequestJson(unexpectedAuthSchemeErr, req, res),
            error: unexpectedAuthSchemeErr,
            status: options.badRequestStatusCode,
            success: false
          } as AuthenticatorPluginResult;
        }
        token = authHeaderParts[1];

      } else {
        // auth header has unexpected content
        const unexpectedAuthHeaderContentErr = new Error('UNEXPECTED_AUTH_HEADER_CONTENT');
        return {
          data: await options.badRequestJson(unexpectedAuthHeaderContentErr, req, res),
          error: unexpectedAuthHeaderContentErr,
          status: options.badRequestStatusCode,
          success: false
        } as AuthenticatorPluginResult;

      }
    } catch (err) {
      return {
        data: await options.serverErrorJson(err, req, res),
        error: err,
        status: options.serverErrorStatusCode,
        success: false
      } as AuthenticatorPluginResult;
    }

    try {
      // if doing multi domain config, decode token, look at domain field and set the jwtVerifyOptions to that domain's config
      let key = options.key;
      const jwtVerifyOptions = options.jwtVerifyOptions;
      if (options.domainedAudiences) {
        const decodedToken = decode(token, {json: true});
        // tslint:disable-next-line:no-string-literal
        let domain = decodedToken['domain'];
        // the default domain may not send a domain in the token.  In that case, the domain is set to default if empty
        if (!domain) {
          domain = 'default';
        }
        if (domain && options.domainedAudiences[domain]) {
          // tslint:disable:no-string-literal
          jwtVerifyOptions.audience = options.domainedAudiences[domain]['audience'];
          jwtVerifyOptions.issuer = options.domainedAudiences[domain]['issuer'];
          key = options.domainedAudiences[domain]['key'];
          // tslint:enable:no-string-literal
        }
      }
      const payload = await verifyJwt(token, key, jwtVerifyOptions);

      return {
        data: await options.onAuthorized(payload, req, res),
        // this shouldn't matter since SakuraApi will call next() to move to the next handler if
        // authentication succeeds
        status: 200,
        success: true
      };

    } catch (err) {
      return {
        data: await options.onVerifyError(err, token, req, res),
        error: err,
        status: options.unauthorizedStatusCode,
        success: false
      } as AuthenticatorPluginResult;
    }
  }

  const authenticators: IAuthenticator[] = [
    new AuthAudience([jwtAudienceHandler])
  ];

  return {
    authenticators
  };
}

function verifyJwt(token, key, jwtVerifyOptions): Promise<any> {
  return new Promise((resolve, reject) => {
    verify(token, key, jwtVerifyOptions, (err, payload) => {
      (err) ? reject(err) : resolve(payload);
    });
  });
}
