# passport-coding

> Passport for Coding

## 安装

    $ yarn add passport-coding

## 使用

#### Configure Strategy

```js
 passport.use(new Strategy({
        appID: {APPID},
        name:{可以设置组件的名字}
        appSecret: {APPSECRET},
        getToken: {getToken},
        saveToken: {saveToken}
      },
      function(accessToken, refreshToken, profile,expires_in, done) {
        return done(err,profile);
      }
));

The `getToken` and `saveToken` can be provided to initialize Wechat OAuth instance.
```

#### Authenticate Requests

```js
router.get("/auth/coding", passport.authenticate("coding", options));
```

## License

Copyright (c) 2019 adger 
