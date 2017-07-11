# auth-audience
Middleware to support JWT audience role for SakuraApi servers

# Example
Wherever your instantiate your instance of SakuraApi:
```
export const sapi = new SakuraApi({
  models: [User],
  plugins: [
    // ...,
    {
      plugin: addAuthAudience,
      options: {
        excludedRoutes: [
          /^\/$/,
          {
            regex:/^\/login$/
          },
          {
            regex:/^\/user$/,
            method: {
              GET: true
            }
          }
        ]
      }
    }
    // ...
  ],
  routables: [UserApi]
});
```

This will set the following routes as not requiring authentication to access:
```
/       any method
/login  any method
/user   GET only
```

Some tips:

1. Don't forget to properly anchor your Regex (`^`, starts with), otherwise, you'll find routes like `/\//` match every request.
1. You can allow multiple methods when using the `{regex: //, method: {}}` approach... just make sure they're ALL CAPS and set to `true`.
1. If you find yourself building crazy lists of exclusions, his might not be the right plugin for you. This assumes that most of your routes are secured by a token and that there's some exceptions (like logging in and registering).

# `baseUrl`
If you have a `baseUrl` set on your instance of `SakuraApi`, `auth-audience` will strip it before doing comparisons. So, if your base url is `/api` and the path you want to exclude is `/api/users`, write your Regex for `/users`.
