'use strict';
class LiteLifting {
  constructor(config, global) {

    console.log('Starting Lite Lifting Framework');
    (() => {
      const defaultConfig = {
        jwtSecret: process.env.ll_jwtSecret || [1, 1, 1].flatMap(Math.random).reduce((a, b) => a + '' + b),
        dbUser: process.env.ll_dbUser || 'root',
        dbSecret: process.env.ll_dbSecret || 'secret',
        dbHost: process.env.ll_dbPort || '127.0.0.1',
        dbPort: process.env.ll_dbHost || '3306',
        useYourSql: undef(process.env.ll_useYourSql || true),
        useLoggerPlusPlus: undef(process.env.ll_useLoggerPlusPlus || true),
        useHostCookie: undef(process.env.ll_useHostCookie || true),
        useNoExtension: undef(process.env.ll_useNoExtension || true),
        useSocketBuddy: undef(process.env.ll_useSocketBuddy || false),
        useJwtCookiePasser: undef(process.env.ll_useJwtCookiePasser || true),
        usePublicPrivateTests: undef(process.env.ll_usePublicPrivateTests || true),
        
        
        configureTLS: undef(process.env.configureTLS || true),
        userService: defaultUserService
      };

      defaulter(config, defaultConfig);
      this.configureLoggerPlusPlus(config);
    })()


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
    this.secureServer = config.configureTLS && require('fresh-cert')({
      router: this.routher,
      sslKeyFile: process.env.sslKeyFile || './ssl/domain-key.pem',
      sslDomainCertFile: process.env.sslDomainCertFile || './ssl/domain.org.crt',
      ssCaBundleFile: process.env.ssCaBundleFile || './ssl/bundle.crt'
    });

    this.configureYourSql(config);

    this.plugInMiddleware(config);
      
    this.socketIOAndJwt(config);
    
    this.configurePublicPrivateTests(config);
    
    this.config = config;
  }
  
  run() {
    if(this.yourSql) {
      this.yourSql.createDatabase(this.config.schema).then(() => {
        //ormHelper.sync(start);
        start();
      }).catch((err) => {
        console.log(err);
        start();
      });      
    }
    const start = () => {
      //////////////////////////
      //START UP SERVER(S)//////
      //////////////////////////
      
      //HTTPS
      if (this.secureServer != null) {
        try {
          this.secureServer.listen(process.env.SECURE_PORT || 443, process.env.SECURE_IP || "0.0.0.0", function() {
            let addr = this.secureServer.address();
            console.log("Secure server listening at", addr.address + ":" + addr.port);
          });
        }
        catch (err2) {
          console.log("Err: " + err2);
          //secureServerErr = "Err: " + err2;
        }
      }
      
      
      if (this.server === undefined || this.server === null) {
        this.server = this.http.createServer(this.router);
      }
      
      
      this.server.listen(process.env.PORT || 3000, process.env.IP || "0.0.0.0", function() {
        console.log('Starting lite-lifting server...');
        console.log('process.env.IP: ' + process.env.IP);
        console.log('process.env.PORT: ' + process.env.PORT);
        let addr = this.server.address();
        console.log("Lite server listening at", addr.address + ":" + addr.port);
      });
    };
  }
  
  
  configurePublicPrivateTests(config) {
    if(config.usePublicPrivateTests) {
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
            enabled: undef(process.env.LL_LPP_enabled, true),
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
            defaultHost: undef(process.env.ll_hostCookie_defaultHost, config.host),
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
    this.yourSql.init(defaulter(config.yourSqlConfig, {
      host: process.env.ll_yourSql_host || '127.0.0.1',
      user: process.env.ll_yourSql_user || 'root',
      password: process.env.ll_yourSql_password || 'secret',
      database: process.env.ll_yourSql_database || 'litelifting',
      connectionLimit: process.env.ll_yourSql_connectionLimit || 100,
      debug: process.env.ll_yourSql_debug || true
    }));
  }

  plugInMiddleware(config) {
    if (!config.publicdir) {
      this.router.use('/', (req, res, next) => {
        res.writeHead(200, {
          'Content-Type': 'application/javascript'
        });
        res.end('<H1>Light Lifting</H1>');
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

    if(config.useJwtCookiePasser) {
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
      if(config.useSocketBuddy) {
        console.log('---SOCKET BUDDY');
        this.socketBuddy = require('socket-buddy')({ 
          server: this.secureServer !== null ? this.secureServer : this.server,
          tokenUtil: this.jwtCookiePasser
        });
        this.socketBuddy.init();       
      } else if(config.socketBuddyInstance) {
        this.socketBuddy = config.socketBuddyInstance({ 
          server: this.secureServer !== null ? this.secureServer : this.server,
          tokenUtil: this.jwtCookiePasser
        });
        this.socketBuddy.init();
      }
    
    if(config.useJwtCookiePasser) {
      console.log('---JWT');
      this.jwtCookiePasser.init(
          defaulter(config.jwtCookiePasserConfig || {}, {
          router: this.router,
          urlencodedParser: this.urlencodedParser,
          userService: this.userService,
          loginLogoutHooks: this.socketIOHelper
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
}

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
