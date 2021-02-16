var	path = require('path'),
	events = require('events'),
	util = require('util'),
	express = require('express'),
	ms = require('ms'),
	moment = require('moment'),
	utils = require('lockit-utils'),
	pwd = require('couch-pwd'),
	Mail = require('lockit-sendmail'),
	debug = require('debug')('lockit');

/**
 * Login constructor function.
 *
 * @constructor
 * @param {Object} config
 * @param {Object} adapter
 */
var Login = module.exports = function(cfg, adapter)
{
	if (!(this instanceof Login))
	{
		return new Login(config, adapter);
	}

	this.config = cfg.login;
	this.config.failedLoginAttempts = cfg.failedLoginAttempts;
	this.config.accountLockedTime = cfg.accountLockedTime;
	this.config.failedLoginsWarning = cfg.failedLoginsWarning;
	this.config.mail = cfg;
	this.config.signup = cfg.signup;
	this.config.rerouted = cfg.rerouted;
	this.adapter = adapter;

	var	config = this.config;

	// call super constructor function
	events.EventEmitter.call(this);

	// set default routes
	this.loginRoute = config.route || '/login';
	this.logoutRoute = config.logoutRoute || '/logout';

	// change URLs if REST is active
	if (config.rest)
	{
		this.loginRoute = '/' + config.rest + this.loginRoute;
		this.logoutRoute = '/' + config.rest + this.logoutRoute;
	}

	// two-factor authentication route
	this.twoFactorRoute = this.loginRoute + (config.twoFactorRoute || '/twofactor');

	var router = express.Router();
	router.get(this.loginRoute, this.getLogin.bind(this));
	router.post(this.loginRoute, this.postLogin.bind(this));
	router.post(this.twoFactorRoute, this.postTwoFactor.bind(this));
	router.get(this.logoutRoute, this.getLogout.bind(this));
	this.router = router;
};

util.inherits(Login, events.EventEmitter);



/**
 * Response handler
 *
 * @param {Object} err
 * @param {String} view
 * @param {Object} user
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
Login.prototype.sendResponse = function(err, view, user, json, redirect, req, res, next)
{
	var	config = this.config;

	this.emit((config.eventmsg || config.route), err, view, user, res);
	
	if(config.handleResponse)
	{
		// do not handle the route when REST is active
		if(config.rest)
		{
			if(err)
			{
				res.status(403).json(err);
			}
			else if(config.rerouted)
			{
				config.rerouted = undefined;
				if(config.signup.rest)
				{
					res.json(json);
				}
				else
				{
					next();
				}
			}
			else
			{
				res.json(json);
			}
		}
		else
		{
			// custom or built-in view
			var	resp = {
					title: config.title || 'Login',
					basedir: req.app.get('views')
				};
				
			if(err)
			{
				resp.error = err.message;
			}
			else if(req.query && req.query.error)
			{
				resp.error = decodeURIComponent(req.query.error);
			}
			
			if(view)
			{
				var	file = path.resolve(path.normalize(resp.basedir + '/' + view));
				res.render(view, Object.assign(resp, json));
			}
			else if(redirect)
			{
				res.redirect(redirect);
			}
			else
			{
				res.status(404).send('<p>No file has been set for this view path in the Lockit.login configuration.</p><p>Please make sure you set a valid file path for "login.views.login".</p>');
			}
		}
	}
	else
	{
		next(err);
	}
};



/**
 * GET /login route handling function.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
Login.prototype.getLogin = function(req, res, next)
{
	var	config = this.config,
		// save redirect url
		suffix = req.query.redirect ? '?redirect=' + encodeURIComponent(req.query.redirect) : '';
	
	this.sendResponse(undefined, config.views.login, undefined, {action:this.loginRoute + suffix, result:true}, undefined, req, res, next);
};



/**
 * POST /login route handling function.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
Login.prototype.postLogin = function(req, res, next)
{
	var	adapter = this.adapter,
		config = this.config,
		that = this,
		login = req.body.login,
		password = req.body.password,
		suffix = req.query.redirect ? '?redirect=' + encodeURIComponent(req.query.redirect) : '';

	// check for valid inputs
	if (!login || !password)
	{
		that.sendResponse({message:'Please enter your email/username and password'}, config.views.login, undefined, {login:login,password:password,action:that.loginRoute + suffix, result:true}, undefined, req, res, next);
	}
	else
	{
		// check if login is a name or an email address

		// regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L4
		var	EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/,
			query = EMAIL_REGEXP.test(login) ? 'email' : 'name',
			basequery = {};

		// Custom for our app
		if (res.locals && res.locals.basequery)
		{
			basequery = res.locals.basequery;
		}

		// find user in db
		adapter.find(query, login, function(err, user)
			{
				if (err)
				{
					next(err);
				}
				else if (!user)
				{
					that.sendResponse({message:'Invalid user or password'}, config.views.login, undefined, {login:login,password:password,action:that.loginRoute + suffix, result:true}, undefined, req, res, next);
				}
				else
				{
					// check for invalidated account
					if (user.accountInvalid)
					{
						that.sendResponse({message:'The account is invalid'}, config.views.login, user, {login:login,password:password,action:that.loginRoute + suffix, result:true}, undefined, req, res, next);
					}
					else if (user.accountLocked && new Date(user.accountLockedUntil) > new Date())
					{
						that.sendResponse({message:'The account is temporarily locked'}, config.views.login, user, {login:login,password:password,action:that.loginRoute + suffix, result:true}, undefined, req, res, next);
					}
					else
					{
						// if user comes from couchdb it has an 'iterations' key
						if (user.iterations)
						{
							pwd.iterations(user.iterations);
						}

						// compare credentials with data in db
						pwd.hash(password, user.salt, function(err, hash)
							{
								if (err)
								{
									next(err);
								}
								else
								{
									if (hash !== user.derived_key)
									{
										// set the default error message
										var errorMessage = 'Invalid user or password';

										// increase failed login attempts
										user.failedLoginAttempts += 1;

										// lock account on too many login attempts (defaults to 5)
										if (user.failedLoginAttempts >= config.failedLoginAttempts)
										{
											user.accountLocked = true;

											// set locked time to 20 minutes (default value)
											var timespan = ms(config.accountLockedTime);
											user.accountLockedUntil = moment().add(timespan, 'ms').toDate();

											errorMessage = 'Invalid user or password. Your account is now locked for ' + config.accountLockedTime;
										}
										else if (user.failedLoginAttempts >= config.failedLoginsWarning)
										{
											// show a warning after 3 (default setting) failed login attempts
											errorMessage = 'Invalid user or password. Your account will be locked soon.';
										}

										// save user to db
										adapter.update(user, function(err, user)
											{
												if (err)
												{
													next(err);
												}
												else
												{
													that.sendResponse({message:errorMessage}, config.views.login, user, {login:login,password:password,action:that.loginRoute + suffix, result:true}, undefined, req, res, next);
												}
											});
									}
									else if(user.twoFactorEnabled && config.views.twoFactor && user.email.length && EMAIL_REGEXP.test(user.email))
									{
										// Two-factor has been enabled
										// send email with change email link
										var	mail = new Mail(Object.assign(config.mail, that)),
											emailto,
											usr = JSON.parse(JSON.stringify(user));

										// Send token
										mail.twoFactor(user.name, user.email, utils.generate(usr.salt), function(err, response)
											{
												if(err)
												{
													next(err);
												}
												else
												{
													that.sendResponse(undefined, config.views.twoFactor, usr, {email:user.email,result:true}, undefined, req, res, next);
												}
											});
									}
									else
									{
										// looks like password is correct

										// shift tracking values
										var now = new Date();

										// update previous login time and ip
										user.previousLoginTime = user.currentLoginTime || now;
										user.previousLoginIp = user.currentLoginIp || req.ip;

										// save login time
										user.currentLoginTime = now;
										user.currentLoginIp = req.ip;

										// user is now logged in
										user.loggedIn = true;

										// set failed login attempts to zero but save them in the session
										res.locals.user = JSON.parse(JSON.stringify(user));

										//req.user.failedLoginAttempts = user.failedLoginAttempts;
										user.failedLoginAttempts = 0;
										user.accountLocked = false;

										// save user to db
										adapter.update(user, function(err, user)
											{
												if (err)
												{
													next(err);
												}
												else
												{
													that.sendResponse(undefined, undefined, user, {result:true}, req.query.redirect || config.completionRoute, req, res, next);
												}
											});
									}
								}
							});
					}
				}
			}, basequery);
	}
};



/**
 * POST /login/two-factor.
 *
 * Verify provided token using time-based one-time password.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
Login.prototype.postTwoFactor = function(req, res, next)
{
	var	config = this.config,
		adapter = this.adapter,
		loginRoute = this.loginRoute,
		that = this,
		token = req.body.token || '',
		email = req.body.email,
		suffix = req.query.redirect ? '?redirect=' + encodeURIComponent(req.query.redirect) : '';

	// Custom for our app
	var basequery = {};
	if (res.locals && res.locals.basequery)
	{
		basequery = res.locals.basequery;
	}

	// get user from db
	adapter.find('email', email, function(err, user)
		{
			if(err)
			{
				next(err);
			}
			else if(user)
			{
				if(utils.verify(token, user.salt))
				{
					that.sendResponse(undefined, undefined, user, {result:true}, req.query.redirect || config.completionRoute, req, res, next);
				}
				else
				{
					res.locals.user = undefined;

					// destroy the session
					utils.destroy(req, function()
						{
							if(suffix.length)
							{
								suffix += '&';
							}
							else
							{
								suffix = '?';
							}
							
							suffix += 'error=' + encodeURIComponent('The authorization code is invalid');
							
							that.sendResponse(undefined, undefined, undefined, undefined, loginRoute + suffix, req, res, next);			
						});
				}
			}
			else
			{
				next();
			}
		}, basequery);
};



/**
 * GET /logout route handling function.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
Login.prototype.getLogout = function(req, res, next)
{
	var	config = this.config,
		adapter = this.adapter,
		that = this,
		user = res.locals.user;

	var basequery = {};
	if (res.locals && res.locals.basequery)
	{
		basequery = res.locals.basequery;
	}

	adapter.find('name', user.name, function(err, user)
		{
			if (err)
			{
				next(err);
			}
			else if(user)
			{
				user.loggedIn = false;
				adapter.update(user, function(err, user)
					{
						if (err)
						{
							next(err);
						}
						else
						{
							res.locals.user = undefined;

							// destroy the session
							utils.destroy(req, function()
								{
									that.sendResponse(undefined, config.views.loggedOut, user, {title:config.title || 'Logged Out',result:true}, undefined, req, res, next);			
								});
						}
					});
			}
			else
			{
				next();
			}
		}, basequery);
};
