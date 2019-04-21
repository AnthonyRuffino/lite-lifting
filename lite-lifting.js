'use strict';
class LiteLifting {
  constructor(config) {

    
    const defaultConfig = {
      port: process.env.ll_port || 8080,
      ip: process.env.ll_ip || "0.0.0.0",
      securePort: process.env.ll_securePort || 443,
      secureIP: process.env.ll_secureIP || "0.0.0.0",
      configureTLS: undef(process.env.ll_configureTLS, false),
      dbUser: process.env.ll_dbUser || 'root',
      dbSecret: process.env.ll_dbSecret || 'secret',
      dbHost: process.env.ll_dbHost || '127.0.0.1',
      dbPort: process.env.ll_dbPort || '3306',
      jwtSecret: process.env.ll_jwtSecret || [1, 1, 1].flatMap(Math.random).reduce((a, b) => a + '' + b),
      useHostCookie: undef(process.env.ll_useHostCookie, true),
      useJwtCookiePasser: undef(process.env.ll_useJwtCookiePasser, true),
      useLoggerPlusPlus: undef(process.env.ll_useLoggerPlusPlus, false),
      useNoExtension: undef(process.env.ll_useNoExtension, true),
      usePublicPrivateTests: undef(process.env.ll_usePublicPrivateTests, true),
      userService: defaultUserService,
      useSocketBuddy: undef(process.env.ll_useSocketBuddy, false),
      useYourSql: undef(process.env.ll_useYourSql, true),
      loglevels: ['info', 'warn', 'error']
    };
    defaulter(config, defaultConfig);
    
    this.loggers = config.loglevels
      .map((level)=> ({ enabled: true, _: console[level], level}))
      .reduce((a, c)=> ({...a, [c.level]: c}),{});
      
    this.configureLoggerPlusPlus(config);
    this.log('info', 'Starting Lite Lifting Framework');
    
    this.http = require('http');
    this.express = require('express');
    this.fs = require('fs');
    this.formidable = require('formidable');


    // ROUTER AND SERVER
    this.router = this.express();
    this.server = this.http.createServer(this.router);


    // COOKIE PARSER
    this.router.use(require('cookie-parser')());


    // BODY PARSER
    this.bodyParser = require('body-parser');
    this.urlencodedParser = this.bodyParser.urlencoded({ extended: false });
    this.router.use(this.bodyParser.json());


    // HOST COOKIE
    this.configureHostCookie(config);


    // SECURE SERVER
    this.secureServer = config.freshCertConfig && require('fresh-cert')({
      router: this.router,
      sslKeyFile: config.freshCertConfig.sslKeyFile,
      sslDomainCertFile: config.freshCertConfig.sslDomainCertFile,
      sslCaBundleFile: config.freshCertConfig.sslCaBundleFile
    });

    this.configureYourSql(config);
    
    this.configureStorming(config);

    this.plugInMiddleware(config);

    this.socketIOAndJwt(config);

    this.configurePublicPrivateTests(config);

    this.config = config;
    
    
  }
  
  log(level, msg) {
    (this.loggers[level] && this.loggers[level].enabled) && this.loggers[level]._(msg);
  }
  
  

  start(callBack) {
    if (this.yourSql) {
      this.yourSql.createDatabase(this.config.schema).then(() => {
        ormSync();
      }).catch((err) => {
        this.log('error', err);
        ormSync();
      });
    }
    else {
      ormSync();
    }
    const ormSync = () => {
      if(this.storming) {
        this.storming.sync(startHttpServer);
      } else {
        startHttpsServer();
      }
    };
    const startHttpServer = (secureAddress, secureAddressErr) => {
      this.server.listen(this.config.port, this.config.ip, () => {
        let address = this.server.address();
        this.log('info', "Server listening at", address.address + ":" + address.port);
        callBack({address, secureAddress, secureAddressErr});
      });
    };
    const startHttpsServer = () => {
      if (this.secureServer != null) {
        try {
          this.secureServer.listen(this.config.securePort, this.secureIp, function() {
            let address = this.secureServer.address();
            this.log('info', "Secure server listening at", address.address + ":" + address.port);
            startHttpServer(address);
          });
        }
        catch (secureAddressErr) {
          this.log('error', "Error starting secure server: " + secureAddressErr);
          startHttpServer(null, secureAddressErr);
        }
      } else {
        this.log('warn', "No HTTPS configured. Set 'freshCertConfig' property.");
        startHttpServer();
      }
    };
  }


  configurePublicPrivateTests(config) {
    if (config.usePublicPrivateTests) {
      this.router.get("/public", function(req, res) {
        res.json({ message: "Public Success!", user: req.user });
      });

      this.router.get("/private", this.jwtCookiePasser.authRequired(), function(req, res) {
        res.json({ message: "Private Success!", user: req.user });
      });
    }
  }

  configureLoggerPlusPlus(config) {
    if (config.useLoggerPlusPlus) {
      require('logger-plus-plus')(
        defaulter(
          config.loggerPlusPlusConfig || {}, {
            enabled: undef(process.env.ll_lpp_enabled, true),
            enabledTypes: {
              log: undef(process.env.ll_loggerPlusPlus_log, true),
              error: undef(process.env.ll_loggerPlusPlus_error, true),
              debug: undef(process.env.ll_loggerPlusPlus_debug, true),
              trace: undef(process.env.ll_loggerPlusPlus_trace, true),
              warn: undef(process.env.ll_loggerPlusPlus_warn, true),
              info: undef(process.env.ll_loggerPlusPlus_info, true),
            }
          }));
    }
  }

  configureHostCookie(config) {
    if (config.useHostCookie) {
      this.router.use(require('host-cookie')(
        defaulter(
          config.hostCookieConfig || {}, {
            defaultHost: process.env.ll_hostCookie_defaultHost,
            maxAge: undef(process.env.ll_hostCookie_maxAge, (1000 * 60 * 60 * 24 * 365)),
          }
        )));
    }
  }

  configureYourSql(config) {
    this.yourSql = null;
    if (!config.useYourSql) {
      return;
    }
    this.yourSql = require('your-sql')();
    this.yourSqlConfig = defaulter(config.yourSqlConfig || {}, {
      host: process.env.ll_yourSql_host || '127.0.0.1',
      user: process.env.ll_yourSql_user || 'root',
      password: process.env.ll_yourSql_password || 'secret',
      database: process.env.ll_yourSql_database || 'litelifting',
      connectionLimit: process.env.ll_yourSql_connectionLimit || 100,
      debug: process.env.ll_yourSql_debug || true
    });
    this.yourSql.init(this.yourSqlConfig);
  }
  
  configureStorming(config) {
    this.storming = null;
    if (!config.useStorming) {
      return;
    } else if(!this.yourSql) {
      this.log('error', 'storming requires your-sql');
      return;
    }
    const entities = [];
    
    this.storming = require('storming')(defaulter(config.stormingConfig || {},{
        ip: this.yourSqlConfig.host,
        user: this.yourSqlConfig.user,
        password: this.yourSqlConfig.password,
        database: this.yourSqlConfig.database,
        yourSql: this.yourSql,
        entities,
        loadDefaultData: process.env.ll_storming_loadDefaultData
      }));
  }

  plugInMiddleware(config) {
    if (!config.publicdir) {
      this.router.use('/', (req, res, next) => {
        res.writeHead(200, {
          'Content-Type': 'application/javascript'
        });
        res.end('<H1>Lite Lifting</H1>');
      });
    }

    // File system middleware
    if (config.useNoExtension) {
      this.router.use(require('no-extension')(global.__publicdir));
    }

    if (config.publicdir) {
      this.router.use(this.express.static(config.publicdir));
    }

  }

  socketIOAndJwt(config) {

    if (config.useJwtCookiePasser) {
      this.jwtCookiePasser = new(require('jwt-cookie-passer')).JwtCookiePasser(
        defaulter(config.jwtCookiePasserConfig || {}, {
          domain: config.host,
          secretOrKey: config.jwtSecret,
          expiresIn: config.sessionExpiration,
          useJsonOnLogin: false,
          useJsonOnLogout: false
        }));
    }

    this.socketBuddy = null;
    if (config.useSocketBuddy) {
      this.log('debug', '---SOCKET BUDDY');
      this.socketBuddy = require('socket-buddy')({
        server: this.secureServer !== null ? this.secureServer : this.server,
        tokenUtil: this.jwtCookiePasser
      });
      this.socketBuddy.init();
    }
    else if (config.socketBuddyInstance) {
      this.socketBuddy = config.socketBuddyInstance({
        server: this.secureServer !== null ? this.secureServer : this.server,
        tokenUtil: this.jwtCookiePasser
      });
      this.socketBuddy.init();
    }

    if (config.useJwtCookiePasser) {
      this.debug('log', '---JWT');
      this.jwtCookiePasser.init(
        defaulter(config.jwtCookiePasserConfig || {}, {
          router: this.router,
          urlencodedParser: this.urlencodedParser,
          userService: this.userService,
          loginLogoutHooks: {
            passRawUserInLoginHook: true,
            loginUserHook: (req, mappedUser, token, user) => {
              let sio = this.socketBuddy;
              if (sio && sio.loginUserHook && typeof sio.loginUserHook === 'function') {
                sio.loginUserHook(req, mappedUser, token, user);
              }
              (this.loginHooks || []).forEach((hook) => {
                hook(req, mappedUser, token, user);
              });
            },
            logoutUserHook: (req) => {
              let sio = this.socketBuddy;
              if (sio && sio.logoutUserHook && typeof sio.logoutUserHook === 'function') {
                sio.logoutUserHook(req);
              }
              (this.logoutHooks || []).forEach((hook) => {
                hook(req);
              });
            }
          }
        }));
    }
  }
}


var undef = (v, o) => v !== undefined ? v : o;
var defaulter = (params, def) => {
  Object.entries(def || {}).forEach((d) => {
    params[d[0]] = undef(params[d[0]], d[1]);
  });
  return params;
};

var defaultUserService = {
  login: (username, password, callback) => {
    if (username === password) {
      callback(null, { id: username, username: username });
    }
    else {
      callback('Invalid user or credentials');
    }
  },
  getUserById: (id, callback) => {
    callback({ id: id, username: id });
  },
  mapUserForJwtToken: (user) => {
    return user;
  }
};


module.exports = function(config) {
  return new LiteLifting(config);
};
