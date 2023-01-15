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

	this.config = cfg;
	this.adapter = adapter;
	var	config = this.config;

	// call super constructor function
	events.EventEmitter.call(this);

	// set default routes
	this.loginRoute = config.login.route || '/login';
	this.twoFactorRoute = config.login.twoFactorRoute || '/twofactor';
	this.logoutRoute = config.login.logoutRoute || '/logout';

	this.login = this.loginRoute.replace(/\W/g,'');
	this.logout = this.logoutRoute.replace(/\W/g,'');
	this.title = this.login && this.login[0].toUpperCase() + this.login.slice(1);

	// change URLs if REST is active
	if (config.rest)
	{
		this.loginRoute = config.rest.route + this.loginRoute;
		this.twoFactorRoute = config.rest.route + this.twoFactorRoute;
		this.logoutRoute = config.rest.route + this.logoutRoute;
	}

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

	this.emit((config.login.eventMessage || 'Login'), err, view, user, res);
	
	if(config.login.handleResponse)
	{
		// do not handle the route when REST is active
		if(config.rest || req.query.rest)
		{
			if(err)
			{
				// Duplicate to make it easy for REST
				// response handlers to detect
				if(!err.error)
				{
					err.error = err.message;
				}
				res.json(err);
			}
			else
			{
				if(redirect)
				{
					json.redirect = redirect;
				}
				res.json(json);
			}
		}
		else
		{
			// custom or built-in view
			var	resp = {
					title: config.login.title || this.title,
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
	
	this.sendResponse(undefined, config.login.views.login, undefined, {action:this.loginRoute + suffix,view:this.login}, undefined, req, res, next);
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
		login = req.body.name,
		password = req.body.password,
		suffix = req.query.redirect ? '?redirect=' + encodeURIComponent(req.query.redirect) : '';

	// check for valid inputs
	if (!login || !password)
	{
		that.sendResponse({message:'Please enter your email/username and password'}, config.login.views.login, undefined, {login:login,password:password,action:that.loginRoute + suffix,view:that.login}, undefined, req, res, next);
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
		adapter.find(query, login, basequery, function(err, user)
			{
				if (err)
				{
					next(err);
				}
				else if (!user)
				{
					if(config.login.signupUnknown && config.signup.route)
					{
						that.sendResponse({message:'The user name <b>' + login + '</b> doesn\'t exist!', redirect:config.signup.route}, undefined, user, undefined, undefined, req, res, next);
					}
					else
					{
						that.sendResponse({message:'The user name <b>' + login + '</b> doesn\'t exist!'}, config.login.views.login, undefined, {login:login,password:password,action:that.loginRoute + suffix,view:that.login}, undefined, req, res, next);
					}
				}
				else
				{
					// check for invalidated account
					if (user.accountInvalid)
					{
						that.sendResponse({message:'The account is invalid'}, config.login.views.login, user, {login:login,password:password,action:that.loginRoute + suffix,view:that.login}, undefined, req, res, next);
					}
					else if (user.accountLocked && new Date(user.accountLockedUntil) > new Date())
					{
						that.sendResponse({message:'The account is temporarily locked'}, config.login.views.login, user, {login:login,password:password,action:that.loginRoute + suffix,view:that.login}, undefined, req, res, next);
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
										var	errorMessage = config.login.errorMessage !== undefined ? config.login.errorMessage : 'Invalid password',
											warningflag,
											redirectflag;

										// increase failed login attempts
										user.failedLoginAttempts += 1;

										// lock account on too many login attempts (defaults to 5)
										if (user.failedLoginAttempts >= config.failedLoginAttempts)
										{
											user.accountLocked = true;

											// set locked time to 20 minutes (default value)
											var timespan = ms(config.accountLockedTime);
											user.accountLockedUntil = moment().add(timespan, 'ms').toDate();

											errorMessage = 'Invalid password. Your account is now locked for ' + config.accountLockedTime;
											warningflag = true;
											redirectflag = '/';
										}
										else if (user.failedLoginAttempts >= config.failedLoginsWarning)
										{
											// show a warning after 3 (default setting) failed login attempts
											errorMessage = 'Invalid password. Your account will be locked soon.';
											warningflag = true;
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
													that.sendResponse({message:errorMessage, warning:warningflag, redirect:redirectflag}, config.login.views.login, user, {login:login,password:password,action:that.loginRoute + suffix, userupdated:true,view:that.login}, undefined, req, res, next);
												}
											});
									}
									else if(user.twoFactorEnabled && config.login.views.twoFactor && user.email.length && EMAIL_REGEXP.test(user.email))
									{
										// Two-factor has been enabled
										// send email with change email link
										var	mail = new Mail(config),
											emailto,
											usr = JSON.parse(JSON.stringify(user)),										
											token = utils.generate(user.salt, {time: 300});

										if(process.env.NODE_ENV === 'production')
										{
											// Send token
											mail.twoFactor(user.name, user.email, token, function(err, response)
												{
													if(err)
													{
														that.sendResponse(err, config.login.views.route, user, {view:that.login}, undefined, req, res, next);
													}
													else
													{
														that.sendResponse(undefined, undefined, usr, {email:user.email,view:'twofactor'}, config.login.twoFactorRoute, req, res, next);
													}
												});
										}
										else
										{
											debug('--------------------');
											debug('token:', token);
											debug('--------------------');
											that.sendResponse(undefined, undefined, usr, {email:user.email,view:'twofactor'}, config.login.twoFactorRoute, req, res, next);
										}
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
													if(config.login.completionRoute)
													{
														if(typeof config.login.completionRoute === 'function')
														{
															config.login.completionRoute(user, req, res, function(err, req, res)
																{
																	if(err)
																	{
																		next(err);
																	}
																	else
																	{
																		that.sendResponse(undefined, undefined, user, {userupdated:true,completed:true}, req.query.redirect || '/', req, res, next);
																	}
																});
														}
														else
														{
															that.sendResponse(undefined, undefined, user, {userupdated:true,completed:true}, config.login.completionRoute, req, res, next);
														}
													}
													else
													{
														that.sendResponse(undefined, undefined, user, {userupdated:true,completed:true}, req.query.redirect || '/', req, res, next);
													}
												}
											});
									}
								}
							});
					}
				}
			});
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
		name = req.body.name,
		EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/,
		query = EMAIL_REGEXP.test(name) ? 'email' : 'name',
		suffix = req.query.redirect ? '?redirect=' + encodeURIComponent(req.query.redirect) : '';

	// Custom for our app
	var basequery = {};
	if (res.locals && res.locals.basequery)
	{
		basequery = res.locals.basequery;
	}

	// get user from db
	adapter.find(query, name, basequery, function(err, user)
		{
			if(err)
			{
				next(err);
			}
			else if(user)
			{
				if(utils.verify(token, user.salt, {time: 300}))
				{
					// token is valid

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
								if(config.login.completionRoute)
								{
									if(typeof config.login.completionRoute === 'function')
									{
										config.login.completionRoute(user, req, res, function(err, req, res)
											{
												if(err)
												{
													next(err);
												}
												else
												{
													that.sendResponse(undefined, undefined, user, {userupdated:true,completed:true}, req.query.redirect || '/', req, res, next);
												}
											});
									}
									else
									{
										that.sendResponse(undefined, undefined, user, {userupdated:true,completed:true}, config.login.completionRoute, req, res, next);
									}
								}
								else
								{
									that.sendResponse(undefined, undefined, user, {userupdated:true,completed:true}, req.query.redirect || '/', req, res, next);
								}
							}
						});
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
							
							that.sendResponse(undefined, undefined, undefined, {title:config.login.title || that.title,completed:true,view:that.logout}, config.login.route + suffix, req, res, next);			
						});
				}
			}
			else
			{
				next();
			}
		});
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

	debug('getLogout');

	if(user)
	{
		adapter.find('name', user.name, basequery, function(err, user)
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
										that.sendResponse(undefined, config.login.views.loggedOut, user, {title:config.login.titleLogout || that.titleLogout,userupdated:true,completed:true,view:that.logout}, undefined, req, res, next);			
									});
							}
						});
				}
				else
				{
					res.redirect(that.loginRoute);
				}
			});
	}
	else
	{
		res.redirect(that.loginRoute);
	}
};
