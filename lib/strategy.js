"use strict";
const util = require("util");
const fly = require('flyio');
const passport = require("passport-strategy");
const debug = require("debug")("passport-coding");

function CodingStrategy(options, verify) {
  options = options || {};

  if (!verify) {
    throw new TypeError("CodingStrategy required a verify callback");
  }

  if (typeof verify !== "function") {
    throw new TypeError("_verify must be function");
  }

  if (!options.key) {
    throw new TypeError("CodingStrategy requires a appID option");
  }

  if (!options.secret) {
    throw new TypeError("CodingStrategy requires a appSecret option");
  }

  passport.Strategy.call(this, options, verify);

  this.name = options.name || "coding";
  this._verify = verify;

  this.key = options.key;
  this.secret = options.secret;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from 'passport.Strategy'
 */
util.inherits(CodingStrategy, passport.Strategy);

CodingStrategy.prototype.authenticate = function (req, options) {
  let self = this;
  if (!req._passport) {
    return this.error(new Error("passport.initialize() middleware not in use"));
  }
  options = options || {};
  // 获取code,并校验相关参数的合法性
  if (req.query && !req.query.code) {
    return self.fail(401);
  }
  // 获取 code 授权成功
  if (req.query && req.query.code) {
    let code = req.query.code;
    debug("coding callback -> \n %s", req.url);
    // 获取 token
    let url = `https://kbit.coding.net/api/oauth/access_token?client_id=${this.key}&client_secret=${this.secret}&grant_type=authorization_code&code=${code}`
    fly.post(url).then(function (response) {
      // 校验完成信息
      function verified(err, user, info) {
        if (err) {
          return self.error(err);
        }
        if (!user) {
          return self.fail(info);
        }
        self.success(user, info);
      }

      if (response.status === 200) {
        let token;
        if (typeof response.data === 'string') {
          token = JSON.parse(response.data);
        } else {
          token = response.data;
        }
        // 获取用户信息
        let userUrl = `https://kbit.coding.net/api/current_user?access_token=${token['access_token']}`;
        fly.get(userUrl).then(user => {
          if (user.status === 200) {
            if (user.data.code === 0) {
              if (self._passReqToCallback) {
                self._verify(
                  req,
                  token["access_token"],
                  token["refresh_token"],
                  token["expires_in"],
                  user.data.data,
                  verified
                );
              } else {
                self._verify(
                  token["access_token"],
                  token["refresh_token"],
                  token["expires_in"],
                  user.data.data,
                  verified
                );
              }
            } else {
              console.log(user.data.msg);
              return self.error('授权失败，请重试');
            }
          } else {
            return self.error('授权失败，请重试');
          }
        }).catch(err => {
          return self.error(err);
        });
      } else {
        return self.error('获取code失败');
      }
    }).catch(err => {
      return self.error(err);
    });
  } else {
    self.fail("缺少 code", 401);
  }
};

module.exports = CodingStrategy;
