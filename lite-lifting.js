'use strict';
class LiteLifting {
  constructor(config) {
    
    const defaultConfig = {
      publicdir: global.__publicdir,
      schema: config.appName,
      port: process.env.ll_port || 8080,
      ip: process.env.ll_ip || "0.0.0.0",
      securePort: process.env.ll_securePort || 443,
      secureIp: process.env.ll_secureIp || "0.0.0.0",
      dbUser: process.env.ll_dbUser || 'root',
      dbSecret: process.env.ll_dbSecret || 'secret',
      dbHost: process.env.ll_dbHost || '127.0.0.1',
      dbPort: process.env.ll_dbPort || '3306',
      jwtSecret: process.env.ll_jwtSecret || [1, 1, 1].map(Math.random).reduce((a, b) => a + '' + b),
      sessionExpiration: (60 * 60 * 24 * 7),
      useHostCookie: undef(process.env.ll_useHostCookie, true),
      useJwtCookiePasser: undef(process.env.ll_useJwtCookiePasser, true),
      useLoggerPlusPlus: undef(process.env.ll_useLoggerPlusPlus, false),
      useNoExtension: undef(process.env.ll_useNoExtension, true),
      userService: config.useDummyUserService && defaultUserService,
      useYouser: undef(process.env.ll_useYouser, true),
      useYourSql: undef(process.env.ll_useYourSql, true),
      useStorming: undef(process.env.ll_useStorming, true),
      routerHooks: [],
      loglevels: ['info', 'warn', 'error']
    };
    defaulter(config, defaultConfig);
    
    this.config = config;
    
    this.configureLoggerPlusPlus(config);
    
    this.loggers = config.loglevels
      .map((level)=> ({ enabled: true, _: console[level], level}))
      .reduce((a, c)=> ({...a, [c.level]: c}),{});
      
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
    
    this.configureYouser(config);

    this.configureJwCookieParser(config);
    
    if(config.publicdir) {
      this.router.use(require('no-extension')(config.publicdir));
      this.router.use(this.express.static(config.publicdir));
    }
  }
  
  log(level, ...msg) {
    (this.loggers[level] && this.loggers[level].enabled) && this.loggers[level]._(...msg);
  }
  
  sync(callBack) {
    if (this.yourSql && this.yourSqlConfig.appSchema && this.yourSqlConfig.createAppSchema) {
      this.yourSql.createDatabase(this.yourSqlConfig.appSchema).then(() => {
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
        this.storming.sync(callBack);
      } else {
        callBack();
      }
    };
  }

  start(callBack) {
    
    if (this.config.useJwtCookiePasser) {
      this.log('debug', '---JWT');
      this.jwtCookiePasser.init(
        defaulter(this.config.jwtCookiePasserConfig || {}, {
          router: this.router,
          urlencodedParser: this.urlencodedParser,
          userService: this.userService,
          loginLogoutHooks: {
            passRawUserInLoginHook: true,
            loginUserHook: (req, mappedUser, token, user) => {
              let sio = this.socketHub;
              if (sio && sio.loginUserHook && typeof sio.loginUserHook === 'function') {
                sio.loginUserHook(req, mappedUser, token, user);
              }
              (this.loginHooks || []).forEach((hook) => {
                hook(req, mappedUser, token, user);
              });
            },
            logoutUserHook: (req) => {
              let sio = this.socketHub;
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
    
    const startHttpServer = (secureAddress, secureAddressErr) => {
      this.server.listen(this.config.port, this.config.ip, () => {
        let address = this.server.address();
        this.log('info', "Server listening at", address.address + ":" + address.port);
        callBack({address, secureAddress, secureAddressErr});
      });
    };
    const startHttpsServer = () => {
      if (this.secureServer) {
        try {
          this.secureServer.listen(this.config.securePort, this.config.secureIp, () => {
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
    startHttpsServer();
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
            cookieName: config.appName,
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
      host: process.env.ll_yourSql_host || this.config.dbHost,
      user: process.env.ll_yourSql_user || this.config.dbUser,
      password: process.env.ll_yourSql_password || this.config.dbSecret,
      database: process.env.ll_yourSql_controlSchema || 'mysql',
      createAppSchema: undef(process.env.ll_yourSql_createAppSchema, true),
      appSchema: process.env.ll_yourSql_appSchema || this.config.schema,
      connectionLimit: process.env.ll_yourSql_connectionLimit || 100,
      debug: process.env.ll_yourSql_debug || false
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
    const entities = LiteLifting.getEntities();
    
    this.storming = require('storming')(defaulter(config.stormingConfig || {},{
        ip: this.yourSqlConfig.host,
        user: this.yourSqlConfig.user,
        password: this.yourSqlConfig.password,
        database: this.yourSqlConfig.appSchema,
        yourSql: this.yourSql,
        entities,
        loadDefaultData: process.env.ll_storming_loadDefaultData
      }));
  }
  
  configureYouser(config) {
    this.userService = config.userService;
    if(this.userService) {
      return;
    }
    
    if (!config.useYouser) {
      return;
    } else if(!this.storming) {
      this.log('error', 'youser requires storming');
      return;
    }
    
    this.userService = new (require('youser'))(defaulter(config.youserConfig || {}, {
      storming: this.storming
    }));
  }
  
  configureJwCookieParser(config) {

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
  }
  
  configureSocketHub({appName, getAlternate, rootHost, getStorming, getInfo}) {
    var SrcString = require('src-string');
    const srcString = new SrcString({
      contentSrc: {
        getEntity: getAlternate
      }
    });
    
    let SocketHub = require('socket-hub');
    let socketHub = new SocketHub({
      appName: appName || this.config.appName,
      server: this.secureServer ? this.secureServer : this.server,
      tokenUtil: this.jwtCookiePasser,
      rootHost,
      storming: this.storming,
      
      subdomainContent: {
        getInfo,
        getStorming,
        getAlternateContent: (context) => srcString.getContent(context),
        getContent: ({subdomain, type}) => {
          const filePath = (type === 'common' ? global.__publicdir : global.__rootdir) + type + '.js';
  		  	console.info(`[${subdomain}] - Loading default exports for ${type}. filePath: ${filePath}`);
  		  	return require(filePath);
        }
      },
    });
    socketHub.init();
    this.socketHub = socketHub;
  }

}

LiteLifting.getEntities = function() {
  const entities = [];
  entities.push(require('./entities/role.js')());
  entities.push(require('./entities/user.js')());
  entities.push(require('./entities/file.js')());
  entities.push(require('./entities/token.js')());
  entities.push(require('./entities/captcha.js')());
  return entities;
};


var undef = (v, o) => v !== undefined ? v : o;
var defaulter = (params, def) => {
  Object.entries(def || {}).forEach((d) => {
    params[d[0]] = undef(params[d[0]], d[1]);
  });
  return params;
};

LiteLifting.defaulter = defaulter;

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
  getUserByUsername: (username, callback) => {
    callback({ id: username, username: username });
  },
  mapUserForJwtToken: (user) => {
    return user;
  }
};

String.prototype.replaceAll = function(search, replacement) {
  let target = this;
  return target.split(search).join(replacement);
};

LiteLifting.schema = (host) => host.replaceAll('-', '__').replaceAll('.', '_');

module.exports = LiteLifting;