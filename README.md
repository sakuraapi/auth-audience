
# auth-audience

Middleware to support JWT audience role for SakuraApi servers

Include this as a plugin when instantiating `SakuraApi`. For example:
```
  const authAudienceOptions = {
    // see: IAuthAudienceOptions for all your options
  };
  
  const sapi = new SakuraApi({
    // ... other stuff
    plugins: [
      {
        options: authAudienceOptions,
        order: 1,
        plugin: addAuthAudience
      }
    ]
  });
```

# Install
`npm i @sakuraapi/auth-audience`


# Configuration

You'll need to setup your environment (`src/config/environment.ts`, for example) with at least the following:
```
modules.export = {
  authentication: {
    jwt: {
      audience: "audience.somedomain.somewhere",
      issuer: "issuer.somedomain.somewhere",
      key: "12345678901234567890123456789012"
    }
  }
};
```

The `audience` is the identifier for the server on which you are implementing this plugin, it should have also been configured in your `auth-native-authority` or `auth-oauth-authority` settings.

The `issuer` is the identifier of the server that's providing the JWT credentials. 

The key is the shared secret with the issuer. It's a 32 character key. Remember, if your issuer is supporting multiple audience servers, they don't have to share the same private keys -- in fact, you might not want them to.

This shouldn't need to be stated: don't commit your production private keys to your repo. Instead, inject them during deployment. How you do this is beyond the scope of this readme. This, by the way, is why you don't provide your key via the `authOptions` above. By putting it in your config files, you're able to create a config file for production that takes an environmental variable instead of having the key hard coded.

## domained Audience
There will be times when in a multi tenanted environment when you will want to have a server authenticate on those different domains.  Each domain will have the 3-tuple of `audience`-`issuer`-`key`.  This auth-audience plugin is able to handle multiple domains (i.e., depending on the domain in the JWT, determining if the audience is supported and if the JWT signs correctly with the secret key for that audience given the domain)
```
   jwt: {
       domainedAudiences: {
           "field": {
               audience: "audience1.somedomain.somewhere",
               issuer: "issuer1.somedomain.somewhere",
               key: "123"
           },
           "default": {
               audience: "audience2.somedomain.somewhere",
               issuer: "issuer2.somedomain.somewhere",
               key: "456"
           }
       }
   }
   ```
   
# Use
`auth-audience` exports `AuthAudience`. This can be used on your `@Routable` api calsses.

Some rules to keep in mind:

1. Authenticators are applied from left to right (in terms of their placement in an array).
1. Each route has an array of authenticators that is a defined as `[...route-level-authenticators, ...class-level-authenticators]`.
1. The first authenticator to succeed stops the iteration through authenticators.
1. If all authenticators fail, the first one to have failed dictates the response.
1. Authenticators can be provided alone, or as an array.

## Example 1:
```
@Routable({
    authenticators: [AuthAudience, Anonymous],
    baseUrl: 'someapi'
})
class SomeApi {}
```
(`Anonymous` is an authenticator exported by `@sakuraapi/api`).

Example 1 subjects all `someapi` routes to `AuthAudience`. If that fails, then it subjects the request to `Anonymous` (which will never fail). If `AuthAudience` succeeds, a JWT for the user will be available on `res.locals.jwt` (or wherever you put it if you override `onAuthorized` in your options).

## Example 2:
```
@Routable({
    authenticators: AuthAudience,
    baseUrl: 'someapi'
})
class SomeApi {}
```

Subjects all `someapi` routes to `AuthAudience`, if that fails the user will get a 401 or whatever you set in your options.

## Example 3
```
@Routable({
    baseUrl: 'someapi'
})
class SomeApi {}
```
This just lets everything through.

## Example 4
```
@Routable({
    baseUrl: 'someapi'
})
class SomeApi {
    @Route({
        authenticators: Anonymous
        method: 'get',
        path: 'handler1'
    })
    handler1(res, req, next) {
        next();
    }

    @Route({
        authenticators: AuthAudience
        method: 'get',
        path: 'handler2'
    })
    handler2(res, req, next) {
        next();
    }
}
```
Here, `someapi/handler1` route is Anonymous and will let anyone through. `someapi/handler2` route is subjected to `AuthAudience`.

## Example 5
 ```
 @Routable({
     authenticators: AuthAudience,
     baseUrl: 'someapi'
 })
 class SomeApi {
     @Route({
         authenticators: Anonymous
         method: 'get',
         path: 'handler1'
     })
     handler1(res, req, next) {
         next();
     }
 
     @Route({
         method: 'get',
         path: 'handler2'
     })
     handler2(res, req, next) {
         next();
     }
 }
 ```
In the above example, all routes would be subjected to `AuthAudience`, but `someapi/handler1` would override that and let anyone through as Anonymous.

In this case, route `someapi/handler1` would not have a JWT injected since Anonymous would be executed before `AuthAudience`. Be careful with your ordering.

# Contributions
[![CLA assistant](https://cla-assistant.io/readme/badge/sakuraapi/auth-audience)](https://cla-assistant.io/sakuraapi/auth-audience)

* Sign the Contributor License Agreement (CLA)
* Fork the project; make your contribution (don't forget to write your unit-tests); do a pull request back to develop (pull updates frequently to not fall too far behind)
* Before heading off to work on something, considering collaborating first by either (1) opening an issue or (2) starting a conversation on gitter or in the Google forum that leads to back to (1)
* All work should be done against an issue (https://github.com/sakuraapi/auth-audience/issues)
* All contributions require unit-tests
* Use the linter (`npm run lint`) to verify you comply with the style guide
* Reset your changes to the docs/ directory before submitting changes - that directory is generated by TypeDoc and we only update it when we're releasing new updates. If you want to update the documentation, change the appropriate comments in the code.


# Bug Reporting
* An ideal bug report will include a PR with a unit-testing demonstrating the bug. TDBR (test driven bug reporting). :)
* Feel free to open an issue before you start working on a PR to prove / demonstrate your bug report, but please close that ticket if you find that your bug was an error on your side

# Community and Conduct

Everyone should be treated with respect. Though candor is encouraged, being mean will not be tolerated.
