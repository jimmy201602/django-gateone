#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       Copyright 2013 Liftoff Software Corporation
#
# For license information see LICENSE.txt

# Meta
__version__ = '1.2.0'
__version_info__ = (1, 2, 0)
__license__ = "AGPLv3" # ...or proprietary (see LICENSE.txt)
__license_info__ = {
    "AGPLv3": {
        "product": "gateone",
        "users": 0, # 0 being unlimited
        "customer": "Unsupported",
        "version": __version__,
        "license_format": "1.0",
    }
}
__author__ = 'Dan McDougall <daniel.mcdougall@liftoffsoftware.com>'
__commit__ = "20160618135724" # Gets replaced by git (holds the date/time)

# NOTE: Docstring includes reStructuredText markup for use with Sphinx.
__doc__ = ''''''

# Standard library modules
import os
import sys
import re
import io
import logging
import time
import socket
import pty
import atexit
import ssl
import hashlib
import copy
from functools import partial
from datetime import datetime, timedelta
try:
    from urlparse import urlparse
except ImportError: # Python 3.X
    from urllib import parse as urlparse

# This is used as a way to ensure users get a friendly message about missing
# dependencies:
MISSING_DEPS = []

tornado_version = "" # Placeholder in case Tornado import fails below

# 3rd party modules
# Technically setuptools isn't part of Python's stdlib:
from pkg_resources import resource_filename, resource_string, resource_exists
from pkg_resources import resource_listdir, iter_entry_points
# Tornado modules (yeah, we use all this stuff)
try:
    import tornado.httpserver
    import tornado.ioloop
    import tornado.options
    import tornado.web
    import tornado.log
    import tornado.auth
    import tornado.template
    import tornado.netutil
    from tornado.websocket import WebSocketHandler, WebSocketClosedError
    from tornado.escape import json_decode
    from tornado.options import options
    from tornado import locale
    from tornado import version as tornado_version
    from tornado import version_info as tornado_version_info
except (ImportError, NameError):
    pass

from applications.utils import getsettings

# Our own modules
SESSIONS = getsettings('SESSIONS', dict())
PERSIST = getsettings('PERSIST', dict())

#from gateone import SESSIONS, PERSIST
#from gateone.auth.authentication import NullAuthHandler, KerberosAuthHandler
#from gateone.auth.authentication import GoogleAuthHandler, APIAuthHandler
#from gateone.auth.authentication import CASAuthHandler, PAMAuthHandler
#from gateone.auth.authentication import SSLAuthHandler
#from gateone.auth.authorization import require, authenticated, policies
from applications.auth.authorization import applicable_policies
from applications.async import MultiprocessRunner, ThreadedRunner
from applications.utils import generate_session_id, mkdir_p, touch, noop
from applications.utils import gen_self_signed_ssl, entry_point_files
from applications.utils import merge_handlers, none_fix, convert_to_timedelta, short_hash
from applications.utils import json_encode, recursive_chown, ChownError, get_or_cache
from applications.utils import write_pid, read_pid, remove_pid, drop_privileges
from applications.utils import check_write_permissions, valid_hostname
from applications.utils import total_seconds, MEMO, bind
from applications.configuration import apply_cli_overrides, define_options, SettingsError
from applications.configuration import get_settings
from applications.onoff import OnOffMixin

#replace tornado websocket handler
from channels.generic.websockets import WebsocketConsumer
from channels.sessions import channel_session,channel_and_http_session,http_session
from channels import Group

from itertools import izip



from django.core import signing

#from applications.app_terminal import TerminalApplication
# Setup our base loggers (these get overwritten in main())
from applications.log import go_logger, LOGS
logger = go_logger(None)
auth_log = go_logger('gateone.auth')
msg_log = go_logger('gateone.message')
client_log = go_logger('gateone.client')

# Setup the locale functions before anything else
locale.set_default_locale('en_US')
server_locale = None # Replaced with the actual server locale object in __main__
def _(string):
    """
    Wraps server_locale.translate so we don't get errors if loading a locale
    fails (or we output a message before it is initialized).
    """
    if server_locale:
        return server_locale.translate(string)
    else:
        return string


# Globals
CMD = None # Will be overwritten by options.command
TIMEOUT = timedelta(days=5) # Gets overridden by options.session_timeout
# SESSION_WATCHER be replaced with a tornado.ioloop.PeriodicCallback that
# watches for sessions that have timed out and takes care of cleaning them up.
SESSION_WATCHER = None
CLEANER = None # Log and leftover session data cleaner PeriodicCallback
FILE_CACHE = {}
APPLICATIONS = {}
PLUGINS = {}
PLUGIN_HOOKS = {} # Gives plugins the ability to hook into various things.

# Secondary locale setup
#locale_dir = resource_filename('gateone', '/i18n')
#locale.load_gettext_translations(locale_dir, 'gateone')
# NOTE: The locale gets set in __main__

def cleanup_user_logs():
    """
    Cleans up all user logs (everything in the user's 'logs' directory and
    subdirectories that ends in 'log') older than the `user_logs_max_age`
    setting.  The log directory is assumed to be:

        *user_dir*/<user>/logs

    ...where *user_dir* is whatever Gate One happens to have configured for
    that particular setting.
    """
    logging.debug("cleanup_user_logs()")
    disabled = timedelta(0) # If the user sets user_logs_max_age to "0"
    settings = get_settings(options.settings_dir)
    user_dir = settings['*']['gateone']['user_dir']
    if 'user_dir' in options: # NOTE: options is global
        user_dir = options.user_dir
    default = "30d"
    max_age_str = settings['*']['gateone'].get('user_logs_max_age', default)
    if 'user_logs_max_age' in list(options):
        max_age_str = options.user_logs_max_age
    max_age = convert_to_timedelta(max_age_str)
    def descend(path):
        """
        Descends *path* removing logs it finds older than `max_age` and calls
        :func:`descend` on any directories.
        """
        for fname in os.listdir(path):
            log_path = os.path.join(path, fname)
            if os.path.isdir(log_path):
                descend(log_path)
                continue
            if not log_path.endswith('log'):
                continue
            mtime = time.localtime(os.stat(log_path).st_mtime)
            # Convert to a datetime object for easier comparison
            mtime = datetime.fromtimestamp(time.mktime(mtime))
            if datetime.now() - mtime > max_age:
                # The log is older than max_age, remove it
                logger.info(_("Removing log due to age (>%s old): %s" % (
                    max_age_str, log_path)))
                os.remove(log_path)
    if max_age != disabled:
        for user in os.listdir(user_dir):
            logs_path = os.path.abspath(os.path.join(user_dir, user, 'logs'))
            if not os.path.exists(logs_path):
                # Nothing to do
                continue
            descend(logs_path)

def cleanup_old_sessions():
    """
    Cleans up old session directories inside the `session_dir`.  Any directories
    found that are older than the `auth_timeout` (global gateone setting) will
    be removed.  The modification time is what will be checked.
    """
    logging.debug("cleanup_old_sessions()")
    disabled = timedelta(0) # If the user sets auth_timeout to "0"
    settings = get_settings(options.settings_dir)
    expiration_str = settings['*']['gateone'].get('auth_timeout', "14d")
    expiration = convert_to_timedelta(expiration_str)
    if expiration != disabled:
        for session in os.listdir(options.session_dir):
            # If it's in the SESSIONS dict it's still valid for sure
            if session not in SESSIONS:
                if len(session) != 45:
                    # Sessions are always 45 characters long.  This check allows
                    # us to skip the 'broadcast' file which also lives in the
                    # session_dir.  Why not just check for 'broacast'?  Just in
                    # case we put something else there in the future.
                    continue
                session_path = os.path.join(options.session_dir, session)
                mtime = time.localtime(os.stat(session_path).st_mtime)
                # Convert to a datetime object for easier comparison
                mtime = datetime.fromtimestamp(time.mktime(mtime))
                if datetime.now() - mtime > expiration:
                    import shutil
                    from applications.utils import kill_session_processes
                    # The log is older than expiration, remove it and kill any
                    # processes that may be remaining.
                    kill_session_processes(session)
                    logger.info(_(
                        "Removing old session files due to age (>%s old): %s" %
                        (expiration_str, session_path)))
                    shutil.rmtree(session_path, ignore_errors=True)

def clean_up():
    """
    Regularly called via the `CLEANER` `~torando.ioloop.PeriodicCallback`, calls
    `cleanup_user_logs` and `cleanup_old_sessions`.

    .. note::

        How often this function gets called can be controlled by adding a
        `cleanup_interval` setting to 10server.conf ('gateone' section).
    """
    cleanup_user_logs()
    cleanup_old_sessions()

def policy_send_user_message(cls, policy):
    """
    Called by :func:`gateone_policies`, returns True if the user is
    authorized to send messages to other users and if applicable, all users
    (broadcasts).
    """
    error_msg = _("You do not have permission to send messages to %s.")
    try:
        upn = cls.f_args[0]['upn']
    except (KeyError, IndexError):
        # send_user_message got bad *settings*.  Deny
        return False
    # TODO: Add a mechanism that allows users to mute other users here.
    if upn == 'AUTHENTICATED':
        cls.error = error_msg % "all users at once"
    else:
        cls.error = error_msg % upn
    return policy.get('send_user_messages', True)

def policy_broadcast(cls, policy):
    """
    Called by :func:`gateone_policies`, returns True if the user is
    authorized to broadcast messages using the
    :meth:`ApplicationWebSocket.broadcast` method.  It makes this determination
    by checking the `['gateone']['send_broadcasts']` policy.
    """
    cls.error = _("You do not have permission to broadcast messages.")
    return policy.get('send_broadcasts', False) # Default deny

def policy_list_users(cls, policy):
    """
    Called by :func:`gateone_policies`, returns True if the user is
    authorized to retrieve a list of the users currently connected to the Gate
    One server via the :meth:`ApplicationWebSocket.list_server_users` method.
    It makes this determination by checking the `['gateone']['list_users']`
    policy.
    """
    cls.error = _("You do not have permission to list connected users.")
    return policy.get('list_users', True)

def gateone_policies(cls):
    """
    This function gets registered under 'gateone' in the
    :attr:`ApplicationWebSocket.security` dict and is called by the
    :func:`require` decorator by way of the :class:`policies` sub-function. It
    returns True or False depending on what is defined in the settings dir and
    what function is being called.

    This function will keep track of and place limits on the following:

        * Who can send messages to other users (including broadcasts).
        * Who can retrieve a list of connected users.
    """
    instance = cls.instance # ApplicationWebSocket instance
    function = cls.function # Wrapped function
    #f_args = cls.f_args     # Wrapped function's arguments
    #f_kwargs = cls.f_kwargs # Wrapped function's keyword arguments
    policy_functions = {
        'send_user_message': policy_send_user_message,
        'broadcast': policy_broadcast,
        'list_server_users': policy_list_users
    }
    user = instance.current_user
    policy = applicable_policies('gateone', user, instance.ws.policies)
    if not policy: # Empty RUDict
        return True # A world without limits!
    if function.__name__ in policy_functions:
        return policy_functions[function.__name__](cls, policy)
    return True # Default to permissive if we made it this far

@atexit.register # I love this feature!
def kill_all_sessions(timeout=False):
    """
    Calls all 'kill_session_callbacks' attached to all `SESSIONS`.

    If *timeout* is ``True``, emulate a session timeout event in order to
    *really* kill any user sessions (to ensure things like dtach processes get
    killed too).
    """
    logging.debug(_("Killing all sessions..."))
    for session in list(SESSIONS.keys()):
        if timeout:
            if "timeout_callbacks" in SESSIONS[session]:
                if SESSIONS[session]["timeout_callbacks"]:
                    for callback in SESSIONS[session]["timeout_callbacks"]:
                        callback(session)
        else:
            if "kill_session_callbacks" in SESSIONS[session]:
                if SESSIONS[session]["kill_session_callbacks"]:
                    for callback in SESSIONS[session]["kill_session_callbacks"]:
                        callback(session)

def timeout_sessions():
    """
    Loops over the SESSIONS dict killing any sessions that haven't been used
    for the length of time specified in *TIMEOUT* (global).  The value of
    *TIMEOUT* can be set in 10server.conf or specified on the command line via
    the *session_timeout* value.

    Applications and plugins can register functions to be called when a session
    times out by attaching them to the user's session inside the `SESSIONS`
    dict under 'timeout_callbacks'.  The best place to do this is inside of the
    application's `authenticate()` function or by attaching them to the
    `go:authenticate` event.  Examples::

        # Imagine this is inside an application's authenticate() method:
        sess = SESSIONS[self.ws.session]
        # Pretend timeout_session() is a function we wrote to kill stuff
        if timeout_session not in sess["timeout_session"]:
            sess["timeout_session"].append(timeout_session)

    .. note::

        This function is meant to be called via Tornado's
        :meth:`~tornado.ioloop.PeriodicCallback`.
    """
    disabled = timedelta(0) # If the user sets session_timeout to "0"
    # Commented because it is a bit noisy.  Uncomment to debug this mechanism.
    #if TIMEOUT != disabled:
        #logging.debug("timeout_sessions() TIMEOUT: %s" % TIMEOUT)
    #else :
        #logging.debug("timeout_sessions() TIMEOUT: disabled")
    try:
        if not SESSIONS: # Last client has timed out
            logger.info(_("All user sessions have terminated."))
            global SESSION_WATCHER
            if SESSION_WATCHER:
                SESSION_WATCHER.stop() # Stop ourselves
                SESSION_WATCHER = None # So authenticate() will know to start it
        for session in list(SESSIONS.keys()):
            if "last_seen" not in SESSIONS[session]:
                # Session is in the process of being created.  We'll check it
                # the next time timeout_sessions() is called.
                continue
            if SESSIONS[session]["last_seen"] == 'connected':
                # Connected sessions do not need to be checked for timeouts
                continue
            if TIMEOUT == disabled or \
                datetime.now() > SESSIONS[session]["last_seen"] + TIMEOUT:
                # Kill the session
                logger.info(_("{session} timeout.".format(session=session)))
                if "timeout_callbacks" in SESSIONS[session]:
                    if SESSIONS[session]["timeout_callbacks"]:
                        for callback in SESSIONS[session]["timeout_callbacks"]:
                            callback(session)
                del SESSIONS[session]
    except Exception as e:
        logger.error(_(
            "Exception encountered in timeout_sessions(): {exception}".format(
                exception=e)
        ))
        import traceback
        traceback.print_exc(file=sys.stdout)

def broadcast_message(args=sys.argv, message=""):
    """
    Broadcasts a given *message* to all users in Gate One.  If no message is
    given `sys.argv` will be parsed and everything after the word 'broadcast'
    will be broadcast.
    """
    if '--help' in args or len(args) < 1:
        print("Usage: gateone broadcast 'Your message here.'")
        sys.exit(1)
    prefs = get_settings(options.settings_dir)
    broadcast_file = os.path.join(options.session_dir, 'broadcast')
    broadcast_file = prefs['*']['gateone'].get(
        'broadcast_file', broadcast_file) # If set
    with io.open(broadcast_file, 'w') as b:
        if not message:
            for message in args:
                if isinstance(message, bytes):
                    message = message.decode('utf-8')
                logging.info(_("Broadcasting %s to all users") % repr(message))
                b.write(message)

# Classes
class StaticHandler(tornado.web.StaticFileHandler):
    """
    An override of :class:`tornado.web.StaticFileHandler` to ensure that the
    Access-Control-Allow-Origin header gets set correctly.  This is necessary in
    order to support embedding Gate One into other web-based applications.

    .. note::

        Gate One performs its own origin checking so header-based access
        controls at the client are unnecessary.
    """
    def initialize(self, path, default_filename=None, use_pkg=None):
        """
        Called automatically by the Tornado framework when the `StaticHandler`
        class is instantiated; handles the usual arguments with the addition
        of *use_pkg* which indicates that the static file should attempt to be
        retrieved from that package via the `pkg_resources` module instead of
        directly via the filesystem.
        """
        self.root = path
        self.default_filename = default_filename
        self.use_pkg = use_pkg

    def set_extra_headers(self, path):
        """
        Adds the Access-Control-Allow-Origin header to allow cross-origin
        access to static content for applications embedding Gate One.
        Specifically, this is necessary in order to support loading fonts
        from different origins.

        Also sets the 'X-UA-Compatible' header to 'IE=edge' to enforce IE 10+
        into standards mode when content is loaded from intranet sites.
        """
        self.set_header('X-UA-Compatible', 'IE=edge')
        # Allow access to our static content from any page:
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Server', 'GateOne')
        self.set_header('License', __license__)

    def options(self, path=None):
        """
        Replies to OPTIONS requests with the usual stuff (200 status, Allow
        header, etc).  Since this is just the static file handler we don't
        include any extra information.
        """
        self.set_status(200)
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Allow', 'HEAD,GET,POST,OPTIONS')
        self.set_header('Server', 'GateOne')
        self.set_header('License', __license__)

    def validate_absolute_path(self, root, absolute_path):
        """
        An override of
        :meth:`tornado.web.StaticFileHandler.validate_absolute_path`;

        Validate and returns the given *absolute_path* using `pkg_resources`
        if ``self.use_pkg`` is set otherwise performs a normal filesystem
        validation.
        """
        # We have to generate the real absolute path in this method since the
        # Tornado devs--for whatever reason--decided that get_absolute_path()
        # must be a classmethod (we need access to self.use_pkg).
        if self.use_pkg:
            if not resource_exists(self.use_pkg, absolute_path):
                raise HTTPError(404)
            return resource_filename(self.use_pkg, absolute_path)
        return super(
            StaticHandler, self).validate_absolute_path(root, absolute_path)

class BaseHandler(tornado.web.RequestHandler):
    """
    A base handler that all Gate One RequestHandlers will inherit methods from.

    Provides the :meth:`get_current_user` method, sets default headers, and
    provides a default :meth:`options` method that can be used for monitoring
    purposes and also for enumerating useful information about this Gate One
    server (see below for more info).
    """
    def set_default_headers(self):
        """
        An override of :meth:`tornado.web.RequestHandler.set_default_headers`
        (which is how Tornado wants you to set default headers) that
        adds/overrides the following headers:

            :Server: 'GateOne'
            :X-UA-Compatible: 'IE=edge' (forces IE 10+ into Standards mode)
        """
        # Force IE 10 into Standards Mode:
        self.set_header('X-UA-Compatible', 'IE=edge')
        self.set_header('Server', 'GateOne')
        self.set_header('License', __license__)

    def get_current_user(self):
        """Tornado standard method--implemented our way."""
        # NOTE: self.current_user is actually an @property that calls
        #       self.get_current_user() and caches the result.
        expiration = self.settings.get('auth_timeout', "14d")
        # Need the expiration in days (which is a bit silly but whatever):
        expiration = (
            float(total_seconds(convert_to_timedelta(expiration)))
            / float(86400))
        user_json = self.get_secure_cookie(
            "gateone_user", max_age_days=expiration)
        if user_json:
            user = json_decode(user_json)
            user['ip_address'] = self.request.remote_ip
            if user and 'upn' not in user:
                return None
            return user

    def options(self, path=None):
        """
        Replies to OPTIONS requests with the usual stuff (200 status, Allow
        header, etc) but also includes some useful information in the response
        body that lists which authentication API features we support in
        addition to which applications are installed.  The response body is
        conveniently JSON-encoded:

        .. ansi-block::

            \x1b[1;34muser\x1b[0m@modern-host\x1b[1;34m:~ $\x1b[0m curl -k \
            -X OPTIONS https://gateone.company.com/ | python -mjson.tool
              % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                             Dload  Upload   Total   Spent    Left  Speed
            100   158  100   158    0     0   6793      0 --:--:-- --:--:-- --:--:--  7181
            {
                "applications": [
                    "File Transfer",
                    "Terminal",
                    "X11"
                ],
                "auth_api": {
                    "hmacs": [
                        "HMAC-SHA1",
                        "HMAC-SHA256",
                        "HMAC-SHA384",
                        "HMAC-SHA512"
                    ],
                    "versions": [
                        "1.0"
                    ]
                }
            }

        .. note::

            The 'Server' header does not supply the version information.  This
            is intentional as it amounts to an unnecessary information
            disclosure.  We don't need to make an attacker's job any easier.
        """
        settings = get_settings(options.settings_dir)
        enabled_applications = settings['*']['gateone'].get(
            'enabled_applications', [])
        if not enabled_applications:
            # List all installed apps
            for app in APPLICATIONS:
                enabled_applications.append(app.name.lower())
        self.set_status(200)
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Allow', 'HEAD,GET,POST,OPTIONS')
        self.set_header('License', __license__)
        features_dict = {
            "auth_api": {
                'versions': ['1.0'],
                'hmacs': [
                    'HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512']
            },
            "applications": enabled_applications
        }
        self.write(features_dict)

class HTTPSRedirectHandler(BaseHandler):
    """
    A handler to redirect clients from HTTP to HTTPS.  Only used if
    `https_redirect` is True in Gate One's settings.
    """
    def get(self):
        """Just redirects the client from HTTP to HTTPS"""
        port = self.settings['port']
        url_prefix = self.settings['url_prefix']
        host = self.request.headers.get('Host', 'localhost')
        self.redirect(
            'https://%s:%s%s' % (host, port, url_prefix))


class GOApplication(OnOffMixin):
    """
    The base from which all Gate One Applications will inherit.  Applications
    are expected to be written like so::

        class SomeApplication(GOApplication):
            def initialize(self):
                "Called when the Application is instantiated."
                initialize_stuff()
                # Here's some good things to do in an initialize() function...
                # Register a policy-checking function:
                self.ws.security.update({'some_app': policy_checking_func})
                # Register some WebSocket actions (note the app:action naming convention)
                self.ws.actions.update({
                    'some_app:do_stuff': self.do_stuff,
                    'some_app:do_other_stuff': self.do_other_stuff
                })
            def open(self):
                "Called when the connection is established."
                # Setup whatever is necessary for session tracking and whatnot.
            def authenticate(self):
                "Called when the user *successfully* authenticates."
                # Here's the best place to instantiate things, send the user
                # JavaScript/CSS files, and similar post-authentication details.
            def on_close(self):
                "Called when the connection is closed."
                # This is a good place to halt any background/periodic operations.

    GOApplications will be automatically imported into Gate One and registered
    appropriately as long as they follow the following conventions:

        * The application and its module(s) should live inside its own directory inside the 'applications' directory.  For example, `/opt/gateone/applications/some_app/some_app.py`
        * Subclasses of `GOApplication` must be added to an `apps` global (list) inside of the application's module(s) like so: `apps = [SomeApplication]` (usually a good idea to put that at the very bottom of the module).

    .. note::

        All .py modules inside of the application's main directory will be
        imported even if they do not contain or register a `GOApplication`.

    .. tip::

        You can add command line arguments to Gate One by calling
        :func:`tornado.options.define` anywhere in your application's global
        namespace.  This works because the :func:`~tornado.options.define`
        function registers options in Gate One's global namespace (as
        `tornado.options.options`) and Gate One imports application modules
        before it evaluates command line arguments.
    """
    # You'll want to override these values in your own app:
    info = {
        'name': "Unknown App",
        'description': (
            "The application developer has yet to provide a description.")
    }
    # NOTE: The above 'info' dict will be sent to the client.
    # NOTE: The icon value will be replaced with the actual icon data.
    def __init__(self, ws):
        #print 'ws',ws
        self.ws = ws # WebSocket instance
        self.current_user = ws.current_user
        # Setup some shortcuts to make things more natural and convenient
        self.write_message = ws.write_message
        self.write_binary = ws.write_binary
        self.render_and_send_css = ws.render_and_send_css
        self.render_style = ws.render_style
        self.send_css = ws.send_css
        self.send_js = ws.send_js
        self.close = ws.close
        self.security = ws.security
        self.request = ws.request#transfer th request
        self.settings = ws.settings
        self.io_loop = tornado.ioloop.IOLoop.current()
        self.cpu_async = CPU_ASYNC
        self.io_async = IO_ASYNC

    def __repr__(self):
        return "GOApplication: %s" % self.__class__

    def __str__(self):
        return self.info['name']

    def initialize(self):
        """
        Called by :meth:`ApplicationWebSocket.open` after __init__().
        GOApplications can override this function to perform their own actions
        when the Application is initialized (happens just before the WebSocket
        is opened).
        """
        pass

    def open(self):
        """
        Called by :meth:`ApplicationWebSocket.open` after the WebSocket is
        opened.  GOApplications can override this function to perform their own
        actions when the WebSocket is opened.
        """
        pass

    def on_close(self):
        """
        Called by :meth:`ApplicationWebSocket.on_close` after the WebSocket is
        closed.  GOApplications can override this function to perform their own
        actions when the WebSocket is closed.
        """
        pass

    def add_handler(self, pattern, handler, **kwargs):
        """
        Adds the given *handler* (`tornado.web.RequestHandler`) to the Tornado
        Application (`self.ws.application`) to handle URLs matching *pattern*.
        If given, *kwargs* will be added to the `tornado.web.URLSpec` when the
        complete handler is assembled.

        .. note::

            If the *pattern* does not start with the configured `url_prefix` it
            will be automatically prepended.
        """
        logging.debug("Adding handler: (%s, %s)" % (pattern, handler))
        url_prefix = self.ws.settings['url_prefix']
        if not pattern.startswith(url_prefix):
            if pattern.startswith('/'):
                # Get rid of the / (it will be in the url_prefix)
                pattern = pattern.lstrip('/')
        spec = tornado.web.URLSpec(pattern, handler, kwargs)
        # Why the Tornado devs didn't give us a simple way to do this is beyond
        # me.
        self.ws.application.handlers[0][1].append(spec)

    def add_timeout(self, timeout, func):
        """
        A convenience function that calls the given *func* after *timeout* using
        ``self.io_loop.add_timeout()`` (which uses
        :meth:`tornado.ioloop.IOLoop.add_timeout`).

        The given *timeout* may be a `datetime.timedelta` or a string compatible
        with `utils.convert_to_timedelta` such as, "5s" or "10m".
        """
        if isinstance(timeout, basestring):
            timeout = convert_to_timedelta(timeout)
        self.io_loop.add_timeout(timeout, func)

class ApplicationWebSocket(WebsocketConsumer, OnOffMixin):
    """
    The main WebSocket interface for Gate One, this class is setup to call
    WebSocket 'actions' which are methods registered in `self.actions`.
    Methods that are registered this way will be exposed and directly callable
    over the WebSocket.
    """
    instances = set()
    # These three attributes handle watching files for changes:
    watched_files = {}     # Format: {<file path>: <modification time>}
    file_update_funcs = {} # Format: {<file path>: <function called on update>}
    file_watcher = None    # Will be replaced with a PeriodicCallback
    prefs = {} # Gets updated with every call to initialize()
    http_user = True
    http_user_and_session = True
    channel_session = True
    channel_session_user = True    
    def __init__(self,  message, **kwargs):
        #print message
        #print 'initialize the websocket'
        self.actions = {
            'go:ping': self.pong,
            'go:log': self.log_message,
            'go:authenticate': self.authenticate,
            'go:get_theme': self.get_theme,
            'go:enumerate_themes': self.enumerate_themes,
            'go:file_request': self.file_request,
            'go:cache_cleanup': self.cache_cleanup,
            'go:send_user_message': self.send_user_message,
            'go:broadcast': self.broadcast,
            'go:list_users': self.list_server_users,
            'go:get_locations': self.get_locations,
            'go:set_location': self.set_location,
            'go:set_locales': self.set_locales,
            'go:set_dimensions': self.set_dimensions,
            'go:license_info': self.license_info,
            'go:debug': self.debug,
        }
        # Setup some instance-specific loggers that we can later update with
        # more metadata
        self.io_loop = tornado.ioloop.IOLoop.current()
        self.logger = go_logger(None)
        self.sync_log = go_logger('gateone.sync')
        self.msg_log = go_logger('gateone.message')
        self.auth_log = go_logger('gateone.auth')
        self.client_log = go_logger('gateone.client')
        self._events = {}
        self.user_locales = []
        self.session = None # Just a placeholder; gets set in authenticate()
        self.locations = {} # Just a placeholder; gets set in authenticate()
        self.location = "default" # Just a placeholder; gets set in authenticate()
        # This is used to keep track of used API authentication signatures so
        # we can prevent replay attacks.
        self.prev_signatures = []
        self.origin_denied = True # Only allow valid origins
        self.file_cache = FILE_CACHE # So applications and plugins can reference
        self.persist = PERSIST # So applications and plugins can reference
        if 'theme_mtimes' not in self.persist:
            # Track theme file modification times so we can be more efficient
            self.persist['theme_mtimes'] = {}
        self.apps = [] # Gets filled up by self.initialize()
        # The security dict stores applications' various policy functions
        self.security = {}
        self.container = ""
        self.prefix = ""
        self.latency_count = 12 # Starts at 12 so the first ping is logged
        self.pinger = None # Replaced with a PeriodicCallback inside open()
        self.timestamps = [] # Tracks/averages client latency
        self.latency = 0 # Keeps a running average
        self.checked_origin = False
        WebsocketConsumer.__init__(self, message, **kwargs)
        #print '__init__'
        #self.initialize()
        #print 'self.initialize'
        #ApplicationWebSocket.__init__(self, message, **kwargs)
        #print 'ApplicationWebSocket __init__'

    @classmethod
    def file_checker(cls):
        """
        A `Tornado.IOLoop.PeriodicCallback` that regularly checks all files
        registered in the `ApplicationWebSocket.watched_files` dict for changes.

        If changes are detected the corresponding function(s) in
        `ApplicationWebSocket.file_update_funcs` will be called.
        """
        #logging.debug("file_checker()") # Noisy so I've commented it out
        if not SESSIONS:
            # No connected sessions; no point in watching files
            cls.file_watcher.stop()
            # Also remove the broadcast file so we know to start up the
            # file_watcher again if a user connects.
            session_dir = options.session_dir
            broadcast_file = os.path.join(session_dir, 'broadcast') # Default
            broadcast_file = cls.prefs['*']['gateone'].get(
                'broadcast_file', broadcast_file) # If set, use that
            del cls.watched_files[broadcast_file]
            del cls.file_update_funcs[broadcast_file]
            os.remove(broadcast_file)
        for path, mtime in list(cls.watched_files.items()):
            if not os.path.exists(path):
                # Someone deleted something they shouldn't have
                logger.error(_(
                    "{path} has been removed.  Removing from file "
                    "checker.".format(path=path)))
                del cls.watched_files[path]
                del cls.file_update_funcs[path]
                continue
            current_mtime = os.stat(path).st_mtime
            if current_mtime == mtime:
                continue
            try:
                cls.watched_files[path] = current_mtime
                cls.file_update_funcs[path]()
            except Exception as e:
                logger.error(_(
                    "Exception encountered trying to execute the file update "
                    "function for {path}...".format(path=path)))
                logger.error(e)
                if options.logging == 'debug':
                    import traceback
                    traceback.print_exc(file=sys.stdout)

    @classmethod
    def watch_file(cls, path, func):
        """
        A classmethod that registers the given file *path* and *func* in
        `ApplicationWebSocket.watched_files` and
        `ApplicationWebSocket.file_update_funcs`, respectively.  The given
        *func* will be called (by `ApplicationWebSocket.file_checker`) whenever
        the file at *path* is modified.
        """
        logging.debug("watch_file('{path}', {func}())".format(
            path=path, func=func.__name__))
        cls.watched_files.update({path: os.stat(path).st_mtime})
        cls.file_update_funcs.update({path: func})

    @classmethod
    def load_prefs(cls):
        """
        Loads all of Gate One's settings from `options.settings_dir` into
        ``cls.prefs``.

        .. note::

            This ``classmethod`` gets called automatically whenever a change is
            detected inside Gate One's ``settings_dir``.
        """
        logger.info(_(
            "Settings have been modified.  Reloading from %s"
            % options.settings_dir))
        prefs = get_settings(options.settings_dir)
        # Only overwrite our settings if everything is proper
        if 'gateone' not in prefs['*']:
            # NOTE: get_settings() records its own errors too
            logger.info(_("Settings have NOT been loaded."))
            return
        cls.prefs = prefs
        # Reset the memoization dict so that everything using
        # applicable_policies() gets the latest & greatest settings
        MEMO.clear()
        # Also update __license_info__ so folks don't have to restart Gate One
        # when installing a new license:
        licenses = prefs.get('*', {}).get('licenses', {})
        if licenses:
            validate_licenses(licenses)
        else: # Ensure the default license is applied (if license removed)
            __license_info__.clear()
            __license_info__["AGPLv3"] = {
                "product": "gateone",
                "users": 0, # 0 being unlimited
                "customer": "Unsupported",
                "version": __version__,
                "license_format": "1.0",
            }

    @classmethod
    def broadcast_file_update(cls):
        """
        Called when there's an update to the `broadcast_file` (e.g.
        `<session_dir>/broadcast`); broadcasts its contents to all connected
        users.  The message will be displayed via the
        :js:meth:`GateOne.Visual.displayMessage` function at the client and can
        be formatted with HTML.  For this reason it is important to strictly
        control write access to the broadcast file.

        .. note::

            Under normal circumstances only root (or the owner of the
            gateone.py process) can enter and/or write to files inside
            Gate One's `session_dir` directory.

        The path to the broadcast file can be configured via the
        `broadcast_file` setting which can be placed anywhere under the
        'gateone' application/scope (e.g. inside 10server.conf).  The setting
        isn't there by default but you can simply add it if you wish:

        .. code-block:: javascript

            "broadcast_file": "/whatever/path/you/want/broadcast"

        .. tip::

            Want to broadcast a message to all the users currently connected to
            Gate One?  Just `sudo echo "your message" > /tmp/gateone/broadcast`.
        """
        session_dir = options.session_dir
        broadcast_file = os.path.join(session_dir, 'broadcast')
        broadcast_file = cls.prefs['*']['gateone'].get(
            'broadcast_file', broadcast_file)
        with io.open(broadcast_file) as f:
            message = f.read()
        if message:
            message = _("(Broadcast) %s") % message.rstrip()
            metadata = {'clients': []}
            for instance in cls.instances:
                try: # Only send to users that have authenticated
                    user = instance.current_user
                except AttributeError:
                    continue
                user_info = {
                    'upn': user['upn'],
                    'ip_address': user['ip_address']
                }
                metadata['clients'].append(user_info)
            msg_log.info("Broadcast %s" % message, metadata=metadata)
            message_dict = {'go:user_message': message}
            cls._deliver(message_dict, upn="AUTHENTICATED")
            io.open(broadcast_file, 'w').write(u'') # Empty it out

    def initialize(self, apps=None,message=None, **kwargs):
        """
        This gets called by the Tornado framework when `ApplicationWebSocket` is
        instantiated.  It will be passed the list of *apps* (Gate One
        applications) that are assigned inside the :class:`GOApplication`
        object.  These :class:`GOApplication`s will be instantiated and stored
        in `self.apps`.

        These *apps* will be mutated in-place so that `self` will refer to the
        current instance of :class:`ApplicationWebSocket`.  Kind of like a
        dynamic mixin.
        """
        logging.debug('ApplicationWebSocket.initialize(%s)' % apps)
        # Make sure we have all prefs ready for checking
        cls = ApplicationWebSocket
        cls.prefs = get_settings(getsettings('settings_dir',os.path.join(getsettings('BASE_DIR'),'conf.d')))
        #print 'initialize cls prefix',self.prefs
        #sel.settings example
        """
        {u'dtach': True, 'version': None, u'locale': u'en_US', u'address': u'', u'pam_service': u'login', u'syslog_facility': u'daemon', 'cookie_secret': u'ZTQyZTZhYjQxZmVjNDI2M2E3MWZiYmMyOWViZDA5ZGZlM', u'enable_unix_socket': False, u'port': 10443, u'uid': u'1000', u'url_prefix': u'/', u'user_dir': u'/home/jimmy/Desktop/GateOne/users', 'settings_dir': '/home/jimmy/Desktop/GateOne/conf.d', u'unix_socket_mode': u'0600', u'multiprocessing_workers': None, u'certificate': u'/home/jimmy/Desktop/GateOne/ssl/certificate.pem', u'log_rotate_interval': 1, u'log_to_stderr': None, u'log_rotate_when': u'midnight', u'gid': u'1000', u'pid_file': u'/home/jimmy/Desktop/GateOne/gateone.pid', 'command': None, 'gzip': True, u'pam_realm': u'jimmy-linux', 'login_url': u'/auth', 'configure': False, u'sso_service': u'HTTP', 'cli_overrides': [], u'https_redirect': False, u'auth': None, 'api_keys': '', u'disable_ssl': False, u'ca_certs': None, u'cache_dir': u'/home/jimmy/Desktop/GateOne/cache', u'syslog_session_logging': False, u'user_logs_max_age': u'30d', u'sso_keytab': None, u'api_timestamp_window': datetime.timedelta(0, 30), 'static_url_prefix': u'/static/', u'log_rotate_mode': u'size', u'log_file_num_backups': 10, u'logging': u'info', u'embedded': False, u'origins': [u'localhost:10443', u'127.0.0.1:10443', u'jimmy-linux:10443', u'127.0.1.1:10443'], u'session_logging': True, u'keyfile': u'/home/jimmy/Desktop/GateOne/ssl/keyfile.pem', u'session_dir': u'/home/jimmy/Desktop/GateOne/sessions', 'static_url': '/home/jimmy/Desktop/GateOne/gateone/static', u'ssl_auth': u'none', u'log_file_max_size': 100000000, u'session_timeout': u'5d', u'sso_realm': None, u'debug': False, u'js_init': u'', u'unix_socket_path': u'/tmp/gateone.sock', u'log_file_prefix': u'/home/jimmy/Desktop/GateOne/logs/gateone.log'}
        """
        cache_dir = getsettings('cache_dir',os.path.join(getsettings('BASE_DIR'), 'cache'))
        if not os.path.exists(cache_dir):
            mkdir_p(cache_dir)
        #PLUGIN_HOOKS example
        """
         {'gateone.plugins.editor': {'WebSocket': {'go:get_editor_mode': <function get_editor_mode at 0x7fec2b339b90>}}}
        """
        for plugin_name, hooks in PLUGIN_HOOKS.items():
            if 'Events' in hooks:
                for event, callback in hooks['Events'].items():
                    self.on(event, bind(callback, self))
            if 'WebSocket' in hooks:
                # Apply the plugin's WebSocket commands
                for ws_action, func in hooks['WebSocket'].items():
                    self.actions.update({ws_action: bind(func, self)})
        self.on("go:authenticate", self.send_extra)
        # Setup some actions to take place after the user authenticates
        # Send our plugin .js and .css files to the client
        send_plugin_static_files = partial(
            self.send_plugin_static_files, 'go_plugins')
        self.on("go:authenticate", send_plugin_static_files)
        # Tell the client about any existing locations where applications may be
        # storing things like terminal instances and whatnot:
        self.on("go:authenticate", self.get_locations)
        # This is so the client knows what applications it can use:
        self.on("go:authenticate", self.list_applications)
        # This starts up the PeriodicCallback that watches sessions for timeouts
        # and cleans them up (if not already started):
        self.on("go:authenticate", self._start_session_watcher)
        # This starts up the PeriodicCallback that watches and cleans up old
        # user logs (anything in gateone/users/<user>/logs):
        self.on("go:authenticate", self._start_cleaner)
        # This starts up the file watcher PeriodicCallback:
        self.on("go:authenticate", self._start_file_watcher)
        # This ensures that sessions will timeout immediately if session_timeout
        # is set to 0:
        self.on("go:close", timeout_sessions)
        if not apps:
            return
        for app in apps:
            instance = app(self)
            self.apps.append(instance)
            logging.debug("Initializing %s" % instance)
            if hasattr(instance, 'initialize'):
                instance.initialize(message=message)

    def send_extra(self):
        """
        Sends any extra JS/CSS files placed in Gate One's 'static/extra'
        directory.  Can be useful if you want to use Gate One's file
        synchronization and caching capabilities in your app.

        .. note::

            You may have to create the 'static/extra' directory before putting
            files in there.
        """
        extra_path = resource_filename('gateone', 'static/extra')
        if not resource_exists('gateone', '/static/extra'):
            return # Nothing to do
        for f in resource_listdir('gateone', '/static/extra'):
            filepath = resource_filename('gateone', '/static/extra/%s' % f)
            if filepath.endswith('.js'):
                self.send_js(filepath, force=True)
            elif filepath.endswith('.css'):
                self.send_css(filepath, force=True)

    def allow_draft76(self):
        """
        By overriding this function we're allowing the older version of the
        WebSockets protocol.  As long as communications happens over SSL there
        shouldn't be any security concerns with this.  This is mostly to support
        iOS Safari.
        """
        return True

    def get_current_user(self):
        """
        Mostly identical to the function of the same name in MainHandler.  The
        difference being that when API authentication is enabled the WebSocket
        will expect and perform its own auth of the client.
        """
        expiration = self.settings.get('auth_timeout', "14d")
        # Need the expiration in days (which is a bit silly but whatever):
        expiration = (
            float(total_seconds(convert_to_timedelta(expiration)))
            / float(86400))
        user_json = self.get_secure_cookie(
            "gateone_user", max_age_days=expiration)
        if not user_json:
            if not self.settings['auth']:
                # This can happen if the user's browser isn't allowing
                # persistent cookies (e.g. incognito mode)
                return {'upn': 'ANONYMOUS', 'session': generate_session_id()}
            return None
        user = json_decode(user_json)
        user['ip_address'] = self.request.remote_ip
        return user

    def write_binary(self, message):
        """
        Writes the given *message* to the WebSocket in binary mode (opcode
        0x02).  Binary WebSocket messages are handled differently from regular
        messages at the client (they use a completely different 'action'
        mechanism).  For more information see the JavaScript developer
        documentation.
        """
        self.write_message(message, binary=True)

    def check_origin(self, origin):
        #this function is overwrite for tornado request header check. It won't be invoked by applicationwebsocket.
        """
        Checks if the given *origin* matches what's been set in Gate One's
        "origins" setting (usually in 10server.conf).  The *origin* will first
        be checked for an exact match in the "origins" setting but if that fails
        each valid origin will be evaluated as a regular expression (if it's not
        a valid hostname) and the given *origin* will be checked against that.

        Returns ``True`` if *origin* is valid.

        .. note::

            If '*' is in the "origins" setting (anywhere) all origins will be
            allowed.
        """
        print 'origin',origin
        logging.debug("check_origin(%s)" % origin)
        self.checked_origin = True
        valid = False
        parsed_origin = urlparse(origin)
        self.origin = parsed_origin.netloc.lower()
        host = self.request.headers.get("Host")
        if self.origin == host: # Reality check: Do we care?
            # If the origin matches the "Host" header it means that the user is
            # legitimately accessing Gate One directly.  We really only need to
            # worry about origins if the connection is coming from some external
            # site (e.g. to prevent spear phishing attacks; XSS and whatnot).
            return True # Origin check successful; no need to continue
        if 'origins' in self.settings.get('cli_overrides', ''):
            # If given on the command line, always use those origins
            valid_origins = self.settings['origins']
        else:
            # Why have this separate?  So you can change origins on-the-fly by
            # modifying 10server.conf (or whatever other conf you put it in).
            valid_origins = self.prefs['*']['gateone'].get('origins', [])
        if '*' in valid_origins:
            valid = True
        elif self.origin in valid_origins:
            valid = True
        if not valid:
            # Treat the list of valid origins as regular expressions
            for check_origin in valid_origins:
                if valid_hostname(check_origin):
                    continue # Valid hostnames aren't regular expressions
                match = re.match(check_origin, self.origin)
                if match:
                    valid = True
                    break
        if not valid:
            logging.error("Origin check failed for: %s" % origin)
        return valid

    def open(self, message):
        """
        Called when a new WebSocket is opened.  Will deny access to any
        origin that is not defined in `self.settings['origin']`.  Also sends
        any relevant localization data (JavaScript) to the client and calls the
        :meth:`open` method of any and all enabled Applications.

        This method kicks off the process that sends keepalive pings/checks to
        the client (A `~tornado.ioloop.PeriodicCallback` set as `self.pinger`).

        This method also sets the following instance attributes:

            * `self.client_id`: Unique identifier for this instance.
            * `self.base_url`: The base URL (e.g. https://foo.com/gateone/) used to access Gate One.

        Triggers the `go:open` event.

        .. note::

            `self.settings` comes from the Tornado framework and includes most
            command line arguments and the settings from the `settings_dir` that
            fall under the "gateone" scope.  It is not the same thing as
            `self.prefs` which includes *all* of Gate One's settings (including
            settings for other applications and scopes).
        """
        #print 'websocket opened'
        cls = ApplicationWebSocket
        cls.instances.add(self)
        #print 'websocket opened self.prefx',self.prefs
        #if hasattr(self, 'set_nodelay'):
            ## New feature of Tornado 3.1 that can reduce latency:
            #self.set_nodelay(True)
        client_address = message.http_session.get('gateone_user',None)['ip_address']
        #print client_address
        logging.debug("open() origin: %s" % client_address)
        self.origin_denied = False
        # client_id is unique to the browser/client whereas session_id is unique
        # to the user.  It isn't used much right now but it will be useful in
        # the future once more stuff is running over WebSockets.
        self.client_id = message.http_session.get('session',None)
        self.base_url = "{protocol}://{host}:{port}{url_prefix}".format(
            protocol=message.http_session.get('gateone_user',None)['protocol'],
            host=client_address,
            port=getsettings('port',8000),#self.settings['port']
            url_prefix=getsettings('url_prefix','/'))#self.settings['url_prefix']
        user = self.current_user(message)
        # NOTE: self.current_user will call self.get_current_user() and set
        # self._current_user the first time it is used.
        policy = applicable_policies("gateone", user, self.prefs)
        #print 'policy',policy
        #policy example
        """
        {
            "*": {
                "gateone": {
                    "uid": "1000", 
                    "locale": "en_US", 
                    "user_logs_max_age": "30d", 
                    "pam_service": "login", 
                    "syslog_facility": "daemon", 
                    "js_init": "", 
                    "cookie_secret": "iqy3so83+l8=m^p=-0t2po)(h#+r%gmqcfgz7kj7biux)+t#ow", 
                    "enable_unix_socket": false, 
                    "session_timeout": "5d", 
                    "port": 8000, 
                    "url_prefix": "/", 
                    "user_dir": "/home/jimmy/Desktop/GateOne/users", 
                    "unix_socket_mode": "0600", 
                    "log_rotate_mode": "size", 
                    "certificate": "/home/jimmy/Desktop/GateOne/ssl/certificate.pem", 
                    "log_rotate_interval": 1, 
                    "log_to_stderr": null, 
                    "log_rotate_when": "midnight", 
                    "gid": "1000", 
                    "pid_file": "/home/jimmy/Desktop/GateOne/gateone.pid", 
                    "pam_realm": "jimmy-VirtualBox", 
                    "sso_service": "HTTP", 
                    "https_redirect": false, 
                    "auth": "none", 
                    "api_keys": {
                        "ZDRhMTA1ZjIwZDY2NDc3N2I4ZmZlNzQzM2ZiMTUxN2M4N": "YTA4ZWYzZjYzNWE5NDIyMmExMTZiZDE3MzdhNTk1NWY0M"
                    }, 
                    "disable_ssl": false, 
                    "ca_certs": null, 
                    "cache_dir": "/home/jimmy/Desktop/GateOne/cache", 
                    "address": "", 
                    "logging": "info", 
                    "multiprocessing_workers": null, 
                    "log_file_num_backups": 10, 
                    "sso_keytab": null, 
                    "origins": [
                        "localhost:10443", 
                        "127.0.0.1:10443", 
                        "jimmy-VirtualBox:10443", 
                        "127.0.1.1:10443"
                    ], 
                    "embedded": false, 
                    "unix_socket_path": "/tmp/gateone.sock", 
                    "ssl_auth": "none", 
                    "log_file_max_size": 100000000, 
                    "session_dir": "/home/jimmy/Desktop/GateOne/sessions", 
                    "sso_realm": null, 
                    "debug": false, 
                    "api_timestamp_window": "30s", 
                    "keyfile": "/home/jimmy/Desktop/GateOne/ssl/keyfile.pem", 
                    "log_file_prefix": "/home/jimmy/Desktop/GateOne/logs/gateone.log"
                }, 
                "terminal": {
                    "commands": {
                        "SSH": {
                            "command": "/bin/bash"
                        }
                    }, 
                    "environment_vars": {
                        "TERM": "xterm-256color"
                    }, 
                    "dtach": true, 
                    "default_command": "SSH", 
                    "syslog_session_logging": false, 
                    "session_logging": true, 
                    "enabled_filetypes": "all"
                }
            }
        }
        """
        blacklisted = policy.get('blacklist', False)
        if blacklisted:
            auth_log.info(_(
                '{"ip_address": "%s"} Access Denied (blacklisted).'))
            blacklist_msg = (
                _("Your IP address (%s) has been blacklisted")
                % client_address)
            message = {'go:blacklisted': blacklist_msg}
            self.write_message()
            self.close() # Close the WebSocket
            return
        metadata = {'ip_address': client_address}
        #print 'client_address',client_address
        self.origin = str(client_address + ':' + getsettings('port', '8000'))
        if user and 'upn' in user:
            # Update our loggers to include the user metadata
            metadata['upn'] = user['upn']
            # NOTE: NOT using self.auth_log() here on purpose:
            auth_log.info( # Use global auth_log so we're not redundant
                _("WebSocket opened (%s %s) via origin %s.") % (
                    user['upn'], client_address, self.origin))
        else:
            # NOTE: NOT using self.auth_log() here on purpose:
            auth_log.info(_(
                '{"ip_address": "%s"} WebSocket opened (unknown user).')
            % client_address)
        # NOTE: These get updated with more metadata inside of authenticate():
        self.logger = go_logger(None, **metadata)
        self.sync_log = go_logger('gateone.sync', **metadata)
        self.auth_log = go_logger('gateone.auth', **metadata)
        self.msg_log = go_logger('gateone.message', **metadata)
        self.client_log = go_logger('gateone.client', **metadata)
        if user and 'upn' not in user: # Invalid user info
            # NOTE: NOT using self.auth_log() here on purpose:
            auth_log.error(_(
                '{"ip_address": "%s"} Unauthenticated WebSocket attempt.'
                ) % client_address)
            # In case this is a legitimate client that simply had its auth info
            # expire/go bad, tell it to re-auth by calling the appropriate
            # action on the other side.
            message = {'go:reauthenticate': True}
            self.write_message(message)
            self.close() # Close the WebSocket
        # NOTE: By getting the prefs with each call to open() we make
        #       it possible to make changes inside the settings dir without
        #       having to restart Gate One (just need to wait for users to
        #       eventually re-connect or reload the page).
        # NOTE: Why store prefs in the class itself?  No need for redundancy.
        if 'cache_dir' not in cls.prefs['*']['gateone']:
            # Set the cache dir to a default if not set in the prefs
            cache_dir = self.settings['cache_dir']
            cls.prefs['*']['gateone']['cache_dir'] = cache_dir
            if self.settings['debug']:
                # Clean out the cache_dir every page reload when in debug mode
                for fname in os.listdir(cache_dir):
                    filepath = os.path.join(cache_dir, fname)
                    os.remove(filepath)
        # NOTE: This is here so that the client will have all the necessary
        # strings *before* the calls to various init() functions.
        self.send_js_translation()
        additional_files = [
            'gateone_utils_extra.js',
            'gateone_visual_extra.js',
            'gateone_input.js',
            'gateone_misc.js',
            'doT.js' # For simple HTML templates
        ]
        for js_file in additional_files:
            path = os.path.join(getsettings('BASE_DIR'), 'static')
            path = os.path.join(path, js_file)#get js path
            self.send_js(path)
        for app in self.apps:
            if hasattr(app, 'open'):
                app.open(self.client_id, '127.0.0.1:8000', '127.0.0.1') # Call applications' open() functions (if any)
        # Ping the client every 5 seconds so we can keep track of latency and
        # ensure firewalls don't close the connection.
        def send_ping():
            try:
                self.ping(str(int(time.time() * 1000)).encode('utf-8'))
            except (WebSocketClosedError, AttributeError):
                # Connection closed
                self.pinger.stop()
                del self.pinger
        send_ping()
        interval = 5000 # milliseconds
        self.pinger = tornado.ioloop.PeriodicCallback(send_ping, interval)
        self.pinger.start()
        self.trigger("go:open")

    def on_message(self, message):
        """
        Called when we receive a message from the client.  Performs some basic
        validation of the message, decodes it (JSON), and finally calls an
        appropriate WebSocket action (registered method) with the message
        contents.
        """
        # This is super useful when debugging:
        print repr(message)
        logging.debug("message: %s" % repr(message))
        if self.origin_denied:
            self.auth_log.error(_("Message rejected due to invalid origin."))
            self.close() # Close the WebSocket
        message_obj = None
        try:
            message_obj = json_decode(message) # JSON FTW!
            if not isinstance(message_obj, dict):
                self.write_message(_("'Error: Message bust be a JSON dict.'"))
                return
        except ValueError: # We didn't get JSON
            self.write_message(_("'Error: We only accept JSON here.'"))
            return
        if message_obj:
            for key, value in message_obj.items():
                if key in self.actions:
                    try:
                        if value is None:
                            self.actions[key]()
                        else:
                            # Try, try again
                            self.actions[key](value)
                    except (KeyError, TypeError, AttributeError) as e:
                        import traceback
                        for frame in traceback.extract_tb(sys.exc_info()[2]):
                            fname, lineno, fn, text = frame
                        self.logger.error(
                           _("Error in WebSocket action, %s: %s (%s line %s)") %
                           (key, e, fname, lineno))
                        if self.settings['logging'] == 'debug':
                            traceback.print_exc(file=sys.stdout)
                else:
                    self.logger.error(
                        _("Client sent unknown WebSocket action: %s") % key)

    def on_close(self):
        """
        Called when the client terminates the connection.  Also calls the
        :meth:`on_close` method of any and all enabled Applications.

        Triggers the `go:close` event.
        """
        logging.debug("on_close()")
        ApplicationWebSocket.instances.discard(self)
        user = self.current_user
        client_address = self.request.remote_ip
        if user and user['session'] in SESSIONS:
            if self.client_id in SESSIONS[user['session']]['client_ids']:
                SESSIONS[user['session']]['client_ids'].remove(self.client_id)
            # This check is so we don't accidentally timeout a user's session if
            # the server has session_timeout=0 and the user still has a browser
            # connected at a different location:
            if not SESSIONS[user['session']]['client_ids']:
                # Update 'last_seen' with a datetime object for accuracy
                SESSIONS[user['session']]['last_seen'] = datetime.now()
        if user and 'upn' in user:
            self.auth_log.info(
                _("WebSocket closed (%s %s).") % (user['upn'], client_address))
        else:
            self.auth_log.info(_("WebSocket closed (unknown user)."))
        if self.pinger:
            self.pinger.stop()
        # Call applications' on_close() functions (if any)
        for app in self.apps:
            if hasattr(app, 'on_close'):
                app.on_close()
        self.trigger("go:close")

    def on_pong(self, timestamp):
        """
        Records the latency of clients (from the server's perspective) via a
        log message.

        .. note::

            This is the ``pong`` specified in the WebSocket protocol itself.
            The `pong` method is a Gate One-specific implementation.
        """
        self.latency_count += 1
        latency = int(time.time() * 1000) - int(timestamp)
        if latency < 0:
            return # Something went wrong; skip this one
        self.timestamps.append(latency)
        if len(self.timestamps) > 10:
            self.timestamps.pop(0)
        self.latency = sum(self.timestamps)/len(self.timestamps)
        if self.latency_count > 12: # Only log once a minute
            self.latency_count = 0
            #self.logger.info(_("WebSocket Latency: {0}ms").format(self.latency))

    def pong(self, timestamp):
        """
        Attached to the `go:ping` WebSocket action; responds to a client's
        ``ping`` by returning the value (*timestamp*) that was sent.  This
        allows the client to measure the round-trip time of the WebSocket.

        .. note::

            This is a WebSocket action specific to Gate One. It
        """
        message = {'go:pong': timestamp}
        self.write_message(json_encode(message))
        
    #@require(policies('gateone'))
    def log_message(self, log_obj):
        """
        Attached to the `go:log` WebSocket action; logs the given *log_obj* via
        :meth:`ApplicationWebSocket.client_log`.  The *log_obj* should be a
        dict (JSON object, really) in the following format::

            {
                "level": "info", # Optional
                "message": "Actual log message here"
            }

        If a "level" is not given the "info" level will be used.

        *Supported Levels:* "info", "error", "warning", "debug", "fatal",
        "critical".

        .. note::

            The "critical" and "fatal" log levels both use the
            `logging.Logger.critical` method.
        """
        if not self.current_user:
            return # Don't let unauthenticated users log messages.
            # NOTE:  We're not using the authenticated() check here so we don't
            # end up logging a zillion error messages when an unauthenticated
            # user's client has debug logging enabled.
        if "message" not in log_obj:
            return # Nothing to do
        log_obj["level"] = log_obj.get("level", "info") # Default to "info"
        loggers = {
            "info": self.client_log.info,
            "warning": self.client_log.warning,
            "error": self.client_log.error,
            "debug": self.client_log.debug,
            "fatal": self.client_log.critical, # Python doesn't use "fatal"
            "critical": self.client_log.critical,
        }
        if isinstance(log_obj["message"], bytes):
            log_msg = log_obj["message"]
        else:
            log_msg = log_obj["message"].encode('utf-8')
        loggers[log_obj["level"].lower()](
            "Client Logging: {0}".format(log_msg))

    def api_auth(self, auth_obj):
        """
        If the *auth_obj* dict validates, returns the user dict and sets
        ``self.current_user``.  If it doesn't validate, returns ``False``.

        This function also takes care of creating the user's directory if it
        does not exist and creating/updating the user's 'session' file (which
        just stores metadata related to their session).

        Example usage::

            auth_obj = {
                'api_key': 'MjkwYzc3MDI2MjhhNGZkNDg1MjJkODgyYjBmN2MyMTM4M',
                'upn': 'joe@company.com',
                'timestamp': '1323391717238',
                'signature': <gibberish>,
                'signature_method': 'HMAC-SHA1',
                'api_version': '1.0'
            }
            result = self.api_auth(auth_obj)

        .. seealso:: :ref:`api-auth` documentation.

        Here's a rundown of the required *auth_obj* parameters:

            :api_key:
                The first half of what gets generated when you run
                ``gateone --new_api_key`` (the other half is the secret).
            :upn:
                The userPrincipalName (aka username) of the user being
                authenticated.
            :timestamp:
                A 13-digit "time since the epoch" JavaScript-style timestamp.
                Both integers and strings are accepted.
                Example JavaScript: ``var timestamp = new Date().getTime()``
            :signature:
                The HMAC signature of the combined *api_key*, *upn*, and
                *timestamp*; hashed using the secret associated with the given
                *api_key*.
            :signature_method:
                The hashing algorithm used to create the *signature*.  Currently
                this must be one of "HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA384",
                or "HMAC-SHA512"
            :api_version:
                Which version of the authentication API to use when performing
                authentication.  Currently the only supported version is '1.0'.

        .. note::

            Any additional key/value pairs that are included in the *auth_obj*
            will be assigned to the ``self.current_user`` object.  So if you're
            embedding Gate One and wish to associate extra metadata with the
            user you may do so via the API authentication process.
        """
        from applications.utils import create_signature
        reauth = {'go:reauthenticate': True}
        api_key = auth_obj.get('api_key', None)
        if not api_key:
            self.auth_log.error(_(
                'API AUTH: Invalid API authentication object (missing api_key).'
            ))
            self.write_message(json_encode(reauth))
            return False
        upn = str(auth_obj['upn'])
        timestamp = str(auth_obj['timestamp']) # str in case integer
        signature = auth_obj['signature']
        signature_method = auth_obj['signature_method']
        api_version = auth_obj['api_version']
        supported_hmacs = {
            'HMAC-SHA1': hashlib.sha1,
            'HMAC-SHA256': hashlib.sha256,
            'HMAC-SHA384': hashlib.sha384,
            'HMAC-SHA512': hashlib.sha512,
        }
        if signature_method not in supported_hmacs:
            self.auth_log.error(
                _('API AUTH: Unsupported API auth ' 'signature method: %s')
                % signature_method)
            self.write_message(json_encode(reauth))
            return False
        hmac_algo = supported_hmacs[signature_method]
        if api_version != "1.0":
            self.auth_log.error(
                _('API AUTH: Unsupported API version: %s') % api_version)
            self.write_message(json_encode(reauth))
            return False
        try:
            secret = self.settings['api_keys'][api_key]
        except KeyError:
            self.auth_log.error(_(
                'API AUTH: API Key not found.'))
            self.write_message(json_encode(reauth))
            return False
# TODO: Make API version 1.1 that signs *all* attributes--not just the known ones
        # Check the signature against existing API keys
        sig_check = create_signature(
            secret, api_key, upn, timestamp, hmac_algo=hmac_algo)
        if sig_check != signature:
            self.auth_log.error(_('API AUTH: Signature check failed.'))
            self.auth_log.error(_('Got signature: {0}, expected: {1}').format(
                repr(signature), repr(sig_check)))
            self.write_message(json_encode(reauth))
            return False
        # Everything matches (great!) so now we do due diligence
        # by checking the timestamp against the
        # api_timestamp_window setting and whether or not we've
        # already used it (to prevent replay attacks).
        if signature in self.prev_signatures:
            self.auth_log.error(_(
                "API AUTH: replay attack detected!  User: "
                "%s, Remote IP: %s, Origin: %s" % (
                upn, self.request.remote_ip, self.origin)))
            message = {'go:notice': _(
                'API AUTH: Replay attack detected!  This '
                'event has been logged.')}
            self.write_message(json_encode(message))
            return
        window = self.settings.get('api_timestamp_window',timedelta(seconds=30))
        then = datetime.fromtimestamp(int(timestamp)/1000)
        time_diff = datetime.now() - then
        if time_diff > window:
            self.auth_log.error(_(
                "API AUTH: Authentication failed due to an expired auth "
                "object.  If you just restarted the server this is "
                "normal (users just need to reload the page).  If "
                " this problem persists it could be a problem with "
                "the server's clock (either this server or the "
                "server(s) embedding Gate One)."
            ))
            message = {'go:notice': _(
                'AUTH FAILED: Authentication object timed out. '
                'Try reloading this page (F5).')}
            self.write_message(json_encode(message))
            message = {'go:notice': _(
                'AUTH FAILED: If the problem persists after '
                'reloading this page please contact your server'
                ' administrator to notify them of the issue.')}
            self.write_message(json_encode(message))
            return False
        logging.debug(_("API Authentication Successful"))
        self.prev_signatures.append(signature) # Prevent replays
        # Attach any additional provided keys/values to the user
        # object so applications embedding Gate One can use
        # them in their own plugins and whatnot.
        user = {}
        known_params = [
            'api_key',
            'api_version',
            'timestamp',
            'signature',
            'signature_method'
        ]
        for key, value in auth_obj.items():
            if key not in known_params:
                user[key] = value
        # user dicts need a little extra attention for IPs...
        user['ip_address'] = self.request.remote_ip
        # Force-set the current user:
        self._current_user = user
        # Make a directory to store this user's settings/files/logs/etc
        user_dir = os.path.join(self.settings['user_dir'], user['upn'])
        if not os.path.exists(user_dir):
            self.logger.info(_("Creating user directory: %s" % user_dir))
            mkdir_p(user_dir)
            os.chmod(user_dir, 0o770)
        session_file = os.path.join(user_dir, 'session')
        if os.path.exists(session_file):
            with io.open(session_file) as f:
                session_data = f.read()
            user['session'] = json_decode(session_data)['session']
        else:
            user['session'] = generate_session_id()
            session_info_json = json_encode(user)
            with io.open(session_file, 'w') as f:
                # Save it so we can keep track across multiple clients
                f.write(session_info_json)
        return user
    
    def authenticate(self, settings):
        """
        Authenticates the client by first trying to use the 'gateone_user'
        cookie or if Gate One is configured to use API authentication it will
        use *settings['auth']*.  Additionally, it will accept
        *settings['container']* and *settings['prefix']* to apply those to the
        equivalent properties (`self.container` and `self.prefix`).

        If *settings['url']* is provided it will be used to update
        `self.base_url` (so that we can correct for situations where Gate One
        is running behind a reverse proxy with a different protocol/URL than
        what the user used to connect).

        .. note::

            'container' refers to the element on which Gate One was initialized
            at the client (e.g. `#gateone`).  'prefix' refers to the string that
            will be prepended to all Gate One element IDs when added to the web
            page (to avoid namespace conflicts).  Both these values are only
            used when generating CSS templates.

        If *settings['location']* is something other than 'default' all new
        application instances will be associated with the given (string) value.
        These applications will be treated separately so they can exist in a
        different browser tab/window.

        Triggers the `go:authenticate` event.
        """
        cls = ApplicationWebSocket
        logging.debug("authenticate(): %s" % settings)
        # Make sure the client is authenticated if authentication is enabled
        reauth = {'go:reauthenticate': True}
        user = self.current_user # Just a shortcut to keep lines short
        # Apply the container/prefix settings (if present)
        self.container = settings.get('container', self.container)
        self.prefix = settings.get('prefix', self.prefix)
        # Update self.base_url if a url was given
        url = settings.get('url', None)
        if url:
            orig_base_url = self.base_url
            parsed = urlparse(url)
            port = parsed.port
            if not port:
                port = 443
                if parsed.scheme == 'http':
                    port = 80
            self.base_url = "{protocol}://{host}:{port}{url_prefix}".format(
                protocol=parsed.scheme,
                host=parsed.hostname,
                port=port,
                url_prefix=parsed.path)
            if orig_base_url != self.base_url:
                self.logger.info(_(
                    "Proxy in use: Client URL differs from server."))
        auth_method = self.settings.get('auth', None)
        if auth_method and auth_method != 'api':
            # Regular, non-API authentication
            if settings['auth']:
                # Try authenticating with the given (encrypted) 'auth' value
                expiration = self.settings.get('auth_timeout', "14d")
                expiration = (
                    float(total_seconds(convert_to_timedelta(expiration)))
                    / float(86400))
                try:
                    auth_data = self.get_secure_cookie("gateone_user",
                        value=settings['auth'], max_age_days=expiration)
                except TypeError:
                    self.auth_log.error(_(
                        "Received strange data when performing "
                        "authentication.  Did you forget to set 'api' in "
                        "20authentication.conf?"))
                    return
                # NOTE:  This will override whatever is in the cookie.
                # Why?  Because we'll eventually transition to not using cookies
                if auth_data:
                    # Force-set the current user
                    self._current_user = json_decode(auth_data)
                    # Add/update the user's IP address
                    self._current_user['ip_address'] = self.request.remote_ip
                    user = self.current_user
            try:
                if not user:
                    self.auth_log.error(_("Unauthenticated WebSocket attempt."))
                    # This usually happens when the cookie_secret gets changed
                    # resulting in "Invalid cookie..." errors.  If we tell the
                    # client to re-auth the problem should correct itself.
                    self.write_message(json_encode(reauth))
                    return
                elif user and user['upn'] == 'ANONYMOUS':
                    self.auth_log.error(_("Unauthenticated WebSocket attempt."))
                    # This can happen when a client logs in with no auth type
                    # configured and then later the server is configured to use
                    # authentication.  The client must be told to re-auth:
                    self.write_message(json_encode(reauth))
                    return
            except KeyError: # 'upn' wasn't in user
                # Force them to authenticate
                self.write_message(json_encode(reauth))
                #self.close() # Close the WebSocket
        elif auth_method and auth_method == 'api':
            if 'auth' in list(settings.keys()):
                print("auth settings: %s" % repr(settings['auth']))
                if not isinstance(settings['auth'], dict):
                    settings['auth'] = json_decode(settings['auth'])
                user = self.api_auth(settings['auth'])
                if not user:
                    # The api_auth() function takes care of logging/notification
                    return
        else: # Anonymous auth
            # Double-check there isn't a user set in the cookie (i.e. we have
            # recently changed Gate One's settings).  If there is, force it
            # back to ANONYMOUS.
            if settings['auth']:
                cookie_data = None
                if isinstance(settings['auth'], basestring):
                    # The client is trying to authenticate using the
                    # 'gateone_user' parameter in localStorage.
                    # Authenticate/decode the encoded auth info
                    expiration = self.settings.get('auth_timeout', "14d")
                    expiration = (
                        float(total_seconds(convert_to_timedelta(expiration)))
                        / float(86400))
                    cookie_data = self.get_secure_cookie("gateone_user",
                        value=settings['auth'], max_age_days=expiration)
                    # NOTE: The above doesn't actually touch any cookies
                else:
                    # Someone is attempting to perform API-based authentication
                    # but this server isn't configured with 'auth = "api"'.
                    # Let's be real user-friendly and point out this mistake
                    # with a helpful error message...
                    self.auth_log.error(_(
                        "Client tried to use API-based authentication but this "
                        "server is configured with 'auth = \"{0}\"'.  Did you "
                        "forget to set '\"auth\": \"api\"' in the settings?"
                        ).format(self.settings['auth']))
                    message = {'go:notice': _(
                        "AUTHENTICATION ERROR: Server is not configured to "
                        "perform API-based authentication.  Did someone forget "
                        "to set '\"auth\": \"api\"' in the settings?")}
                    self.write_message(json_encode(message))
                    return
                if cookie_data:
                    user = json_decode(cookie_data)
            if not user:
                # Generate a new session/anon user
                # Also store/update their session info in localStorage
                user = {
                    'upn': 'ANONYMOUS',
                    'session': generate_session_id()
                }
                encoded_user = self.create_signed_value(
                    'gateone_user', tornado.escape.json_encode(user))
                session_message = {'go:gateone_user': encoded_user}
                self.write_message(json_encode(session_message))
                self._current_user['ip_address'] = self.request.remote_ip
                self._current_user = user
            if user['upn'] != 'ANONYMOUS':
                # Gate One server's auth config probably changed
                self.write_message(json_encode(reauth))
                return
        if self.current_user and 'session' in self.current_user:
            self.session = self.current_user['session']
        else:
            self.auth_log.error(_("Authentication failed for unknown user"))
            message = {'go:notice': _('AUTHENTICATION ERROR: User unknown')}
            self.write_message(json_encode(message))
            self.write_message(json_encode(reauth))
            return
        # Locations are used to differentiate between different tabs/windows
        self.location = settings.get('location', 'default')
        # Update our loggers to include the user metadata
        metadata = {
            'upn': user['upn'],
            'ip_address': self.request.remote_ip,
            'location': self.location
        }
        self.logger = go_logger(None, **metadata)
        self.sync_log = go_logger('gateone.sync', **metadata)
        self.auth_log = go_logger('gateone.auth', **metadata)
        self.msg_log = go_logger('gateone.message', **metadata)
        self.client_log = go_logger('gateone.client', **metadata)
        # NOTE: NOT using self.auth_log() here on purpose (this log message
        # should stay consistent for easier auditing):
        log_msg = _(
            u"User {upn} authenticated successfully via origin {origin} "
            u"(location {location}).").format(
                upn=user['upn'],
                origin=self.origin,
                location=self.location)
        auth_log.info(log_msg)
        # This check is to make sure there's no existing session so we don't
        # accidentally clobber it.
        if self.session not in SESSIONS:
            # Start a new session:
            SESSIONS[self.session] = {
                'client_ids': [self.client_id],
                'last_seen': 'connected',
                'user': self.current_user,
                'kill_session_callbacks': [
                    partial(self.send_message,
                        _("Please wait while the server is restarted..."))
                ],
                'timeout_callbacks': [],
                # Locations are virtual containers that indirectly correlate
                # with browser windows/tabs.  The point is to allow things like
                # opening/moving applications/terminals in/to new windows/tabs.
                'locations': {self.location: {}}
            }
        else:
            SESSIONS[self.session]['last_seen'] = 'connected'
            SESSIONS[self.session]['client_ids'].append(self.client_id)
            if self.location not in SESSIONS[self.session]['locations']:
                SESSIONS[self.session]['locations'][self.location] = {}
        # A shortcut:
        self.locations = SESSIONS[self.session]['locations']
        # Call applications' authenticate() functions (if any)
        for app in self.apps:
            # Set the current user for convenient access
            app.current_user = self.current_user
            if hasattr(app, 'authenticate'):
                app.authenticate()
        # This is just so the client has a human-readable point of reference:
        message = {'go:set_username': self.current_user['upn']}
        self.write_message(json_encode(message))
        self.trigger('go:authenticate')
        # Perform a license check
        users = ApplicationWebSocket._list_connected_users()
        user_count = 0
        for user in users:
            if not user: # Broadcast/unauthenticated clients don't count
                continue
            user_count += 1
        max_users = 0
        # Figure out how many users we'll allow by adding up all the licenses
        for license, data in __license_info__.items():
            if data['product'] == 'gateone':
                if data['users'] == 0: # Unlimited
                    return # Nothing to check
                max_users += data['users']
        if user_count > max_users:
            logging.error(
                _("Licensed user limit {max_users} exceeded: {user_count} "
                  "connected users").format(
                    max_users=max_users, user_count=user_count))

    def _start_session_watcher(self, restart=False):
        """
        Starts up the `SESSION_WATCHER` (assigned to that global)
        :class:`~tornado.ioloop.PeriodicCallback` that regularly checks for user
        sessions that have timed out via the :func:`timeout_sessions` function
        and cleans them up (shuts down associated processes).

        The interval in which it performs this check is controlled via the
        `session_timeout_check_interval` setting. This setting is not included
        in Gate One's 10server.conf by default but can be added if needed to
        override the default value of 30 seconds.  Example:

        .. code-block:: javascript

            {
                "*": {
                    "gateone": {
                        "session_timeout_check_interval": "30s"
                    }
                }
            }
        """
        global SESSION_WATCHER
        if not SESSION_WATCHER or restart:
            interval = self.prefs['*']['gateone'].get(
                'session_timeout_check_interval', "30s") # 30s default
            td = convert_to_timedelta(interval)
            interval = total_seconds(td) * 1000 # milliseconds
            SESSION_WATCHER = tornado.ioloop.PeriodicCallback(
                timeout_sessions, interval)
            SESSION_WATCHER.start()

    def _start_cleaner(self):
        """
        Starts up the `CLEANER` (assigned to that global)
        `~tornado.ioloop.PeriodicCallback` that regularly checks for and
        deletes expired user logs (e.g. terminal session logs or anything in the
        `<user_dir>/<user>/logs` dir) and old session directories via the
        :func:`cleanup_user_logs` and :func:`cleanup_old_sessions` functions.

        The interval in which it performs this check is controlled via the
        `cleanup_interval` setting. This setting is not included in Gate One's
        10server.conf by default but can be added if needed to override the
        default value of 5 minutes.  Example:

        .. code-block:: javascript

            {
                "*": {
                    "gateone": {
                        "cleanup_interval": "5m"
                    }
                }
            }
        """
        global CLEANER
        if not CLEANER:
            default_interval = 5*60*1000 # 5 minutes
            # NOTE: This interval isn't in the settings by default because it is
            # kind of obscure.  No reason to clutter things up.
            interval = self.prefs['*']['gateone'].get(
                'cleanup_interval', default_interval)
            td = convert_to_timedelta(interval)
            interval = ((
                td.microseconds +
                (td.seconds + td.days * 24 * 3600) *
                10**6) / 10**6) * 1000
            CLEANER = tornado.ioloop.PeriodicCallback(clean_up, interval)
            CLEANER.start()

    def _start_file_watcher(self):
        """
        Starts up the :attr:`ApplicationWebSocket.file_watcher`
        `~tornado.ioloop.PeriodicCallback` (which regularly calls
        :meth:`ApplicationWebSocket.file_checker` and immediately starts it
        watching the broadcast file for changes (if not already watching it).

        The path to the broadcast file defaults to '*settings_dir*/broadcast'
        but can be changed via the 'broadcast_file' setting.  This setting is
        not included in Gate One's 10server.conf by default but can be added if
        needed to overrided the default value.  Example:

        .. code-block:: javascript

            {
                "*": {
                    "gateone": {
                        "broadcast_file": "/some/path/to/broadcast"
                    }
                }
            }

        .. tip::

            You can send messages to all users currently connected to the Gate
            One server by writing text to the broadcast file.  Example:
            `sudo echo "Server will be rebooted as part of regularly scheduled
            maintenance in 5 minutes.  Pleas save your work." >
            /tmp/gateone/broadcast`

        The interval in which it performs this check is controlled via the
        `file_check_interval` setting. This setting is not included in
        Gate One's 10server.conf by default but can be added if needed to
        override the default value of 5 seconds.  Example:

        .. code-block:: javascript

            {
                "*": {
                    "gateone": {
                        "file_check_interval": "5s"
                    }
                }
            }
        """
        cls = ApplicationWebSocket
        broadcast_file = os.path.join(self.settings['session_dir'], 'broadcast')
        broadcast_file = self.prefs['*']['gateone'].get(
            'broadcast_file', broadcast_file)
        if broadcast_file not in cls.watched_files:
            # No broadcast file means the file watcher isn't running
            touch(broadcast_file)
            interval = self.prefs['*']['gateone'].get(
                'file_check_interval', "5s")
            td = convert_to_timedelta(interval)
            interval = ((
                td.microseconds +
                (td.seconds + td.days * 24 * 3600) *
                10**6) / 10**6) * 1000
            cls.watch_file(broadcast_file, cls.broadcast_file_update)
            io_loop = tornado.ioloop.IOLoop.current()
            cls.file_watcher = tornado.ioloop.PeriodicCallback(
                cls.file_checker, interval, io_loop=io_loop)
            cls.file_watcher.start()
        if options.settings_dir not in cls.watched_files:
            cls.watch_file(options.settings_dir, cls.load_prefs)

    def list_applications(self):
        """
        Sends a message to the client indiciating which applications and
        sub-applications are available to the user.

        .. note::

            What's the difference between an "application" and a
            "sub-application"?  An "application" is a `GOApplication` like
            `app_terminal.TerminalApplication` while a "sub-application" would
            be something like "SSH" or "nethack" which runs inside the parent
            application.
        """
        policy = applicable_policies("gateone", self.current_user, self.prefs)
        enabled_applications = policy.get('enabled_applications', [])
        enabled_applications = [a.lower() for a in enabled_applications]
        applications = []
        if not enabled_applications: # Load all apps
            for app in self.apps: # Use the app's name attribute
                info_dict = app.info.copy() # Make a copy so we can change it
                applications.append(info_dict)
        else:
            for app in self.apps: # Use the app's name attribute
                info_dict = app.info.copy() # Make a copy so we can change it
                if info_dict['name'].lower() in enabled_applications:
                    applications.append(info_dict)
        applications = sorted(applications, key=lambda k: k['name'])
        message = {'go:applications': applications}
        self.write_message(json_encode(message))

    #@require(policies('gateone'))
    def set_location(self, location):
        """
        Attached to the `go:set_location` WebSocket action.  Sets
        ``self.location`` to the given value.

        This mechanism can be used by applications embedding Gate One to
        create/control groups of application resources (e.g. terminals) that
        each reside in unique virtual 'locations'.  Use this function to change
        locations on-the-fly without having to re-authenticate the user.

        .. note::

            If this location is new, ``self.locations[*location*]`` will be
            created automatically.
        """
        if location not in self.locations:
            self.locations[location] = {}
        self.location = location
        self.trigger("go:set_location", location)
    
    #@require(authenticated(), policies('gateone'))
    def get_locations(self):
        """
        Attached to the `go:get_locations` WebSocket action.  Sends a message to
        the client (via the `go:locations` WebSocket action) with a dict
        containing location information for the connected user.
        """
        location_data = {}
        for location, apps in self.locations.items():
            location_data[location] = {}
            for name, values in apps.items():
                location_data[location][name] = {}
                for item, vals in values.items():
                    # This would be something like:
                    #  location     name     item     metadata
                    # {'default': {'terminal' {1: {'title': 'foo'}}}}
                    location_data[location][name][item] = {}
                    title = vals.get('title', 'Unknown')
                    location_data[location][name][item]['title'] = title
                    command = vals.get('command', 'Unknown')
                    location_data[location][name][item]['command'] = command
                    created = vals.get('created', 'Unknown')
                    if not isinstance(created, str):
                        # Convert it to a JavaScript-style timestamp
                        created = int(time.mktime(created.timetuple())) * 1000
                    location_data[location][name][item]['created'] = created
        message = {'go:locations': location_data}
        self.write_message(message)
        self.trigger("go:get_locations")
    
    #@require(policies('gateone'))
    def set_dimensions(self, dimensions):
        """
        Attached to the `go:set_dimensions` WebSocket action.  Sets
        ``self.dimensions`` to the given *dimensions* which should be a dict::

            {
                "width": 1366,
                "height": 768,
                "workspace_width": 1337,
                "workspace_height": 768
            }

        .. note::

            The idea behind this mechanism is to give applications (e.g. X11) a
            means to know how big things are at the client so it can size things
            correctly before sending them to the client.
        """
        self.dimensions = dimensions
        self.trigger("go:set_dimensions", dimensions)

    def render_style(self, style_path, force=False, **kwargs):
        """
        Renders the CSS template at *style_path* using *kwargs* and returns the
        path to the rendered result.  If the given style has already been
        rendered the existing cache path will be returned.

        If *force* is ``True`` the stylesheet will be rendered even if it
        already exists (cached).

        This method also cleans up older versions of the same rendered template.
        """
        cache_dir = self.settings['cache_dir']
        if not isinstance(cache_dir, str):
            cache_dir = cache_dir.decode('utf-8')
        if not isinstance(style_path, str):
            style_path = style_path.decode('utf-8')
        mtime = os.stat(style_path).st_mtime
        shortened_path = short_hash(style_path)
        rendered_filename = 'rendered_%s_%s' % (shortened_path, int(mtime))
        rendered_path = os.path.join(cache_dir, rendered_filename)
        if not os.path.exists(rendered_path) or force:
            style_css = self.render_string(
                style_path,
                **kwargs
            )
            # NOTE: Tornado templates are always rendered as bytes.  That is why
            # we're using 'wb' below...
            with io.open(rendered_path, 'wb') as f:
                f.write(style_css)
            # Remove older versions of the rendered template if present
            for fname in os.listdir(cache_dir):
                if fname == rendered_filename:
                    continue
                elif shortened_path in fname:
                    # Older version present.
                    # Remove it (and it's minified counterpart).
                    os.remove(os.path.join(cache_dir, fname))
        return rendered_path

    def get_theme(self, settings):
        """
        Sends the theme stylesheets matching the properties specified in
        *settings* to the client.  *settings* must contain the following:

            * **container** - The element Gate One resides in (e.g. 'gateone')
            * **prefix** - The string being used to prefix all elements (e.g. 'go\_')
            * **theme** - The name of the CSS theme to be retrieved.

        .. note::

            This will send the theme files for all applications and plugins that
            have a matching stylesheet in their 'templates' directory.
        """
        self.logger.debug('get_theme(%s)' % settings)
        send_css = self.prefs['*']['gateone'].get('send_css', True)
        if not send_css:
            if not hasattr('logged_css_message', self):
                self.logger.info(_(
                    "send_css is false; will not send JavaScript."))
            # So we don't repeat this message a zillion times in the logs:
            self.logged_css_message = True
            return
        self.sync_log.info('Sync Theme: %s' % settings['theme'])
        use_client_cache = self.prefs['*']['gateone'].get(
            'use_client_cache', True)
        go_url = settings['go_url'] # Used to prefix the url_prefix
        if not go_url.endswith('/'):
            go_url += '/'
        container = settings["container"]
        prefix = settings["prefix"]
        theme = settings["theme"]
        template_args = dict(
            container=container,
            prefix=prefix,
            url_prefix=go_url,
            embedded=self.settings['embedded']
        )
        out_dict = {'files': []}
        theme_mtimes = self.persist['theme_mtimes']
        cache_dir = self.settings['cache_dir']
        theme_file = "%s.css" % theme
        theme_relpath = '/templates/themes/%s' % theme_file
        theme_path = resource_filename('gateone', theme_relpath)
        cached_theme_path = os.path.join(cache_dir, theme_file)
        filename_hash = hashlib.md5(theme_file.encode('utf-8')).hexdigest()[:10]
        theme_files = []
        theme_files.append(theme_path)
        mtime = os.stat(theme_path).st_mtime
        modifications = False
        if theme_path not in theme_mtimes or mtime != theme_mtimes[theme_path]:
            theme_mtimes[theme_path] = mtime
            modifications = True
        # Now enumerate all applications/plugins looking for their own
        # implementations of this theme (must have same name)...
        # Find plugin's theme-specific CSS files:
        for ep in iter_entry_points(group='go_plugins'):
            try:
                exists = resource_exists(ep.module_name, theme_relpath)
            except ImportError: # Plugin has an issue or has been removed
                continue
            if exists:
                theme_path = resource_filename(ep.module_name, theme_relpath)
                theme_files.append(theme_path)
                mtime = os.stat(theme_path).st_mtime
                if (theme_path not in theme_mtimes
                    or mtime != theme_mtimes[theme_path]):
                    theme_mtimes[theme_path] = mtime
                    modifications = True
        # Find application's theme-specific CSS files:
        for ep in iter_entry_points(group='go_applications'):
            try:
                exists = resource_exists(ep.module_name, theme_relpath)
            except ImportError: # Plugin has an issue or has been removed
                continue
            if exists:
                theme_path = resource_filename(ep.module_name, theme_relpath)
                theme_files.append(theme_path)
                mtime = os.stat(theme_path).st_mtime
                if (theme_path not in theme_mtimes
                    or mtime != theme_mtimes[theme_path]):
                    theme_mtimes[theme_path] = mtime
                    modifications = True
            # Find application plugin's theme-specific CSS files
            entry_point = 'go_%s_plugins' % ep.name
            for plugin_ep in iter_entry_points(group=entry_point):
                try:
                    exists = resource_exists(
                        plugin_ep.module_name, theme_relpath)
                except ImportError: # Plugin has an issue or has been removed
                    continue
                if exists:
                    theme_path = resource_filename(
                        plugin_ep.module_name, theme_relpath)
                    theme_files.append(theme_path)
                    mtime = os.stat(theme_path).st_mtime
                    if (theme_path not in theme_mtimes
                        or mtime != theme_mtimes[theme_path]):
                        theme_mtimes[theme_path] = mtime
                        modifications = True
        # Grab the modification times for each theme file
        if modifications or not os.path.exists(cached_theme_path):
            logging.debug(_(
                "Modification to theme file detected.  "
                "Theme will be recreated."))
            # Combine the theme files into one
            rendered_theme_files = []
            template_loaders = tornado.web.RequestHandler._template_loaders
            # This wierd little bit empties Tornado's template cache:
            for web_template_path in template_loaders:
                template_loaders[web_template_path].reset()
            for template_file in theme_files:
                rendered_path = self.render_style(
                    template_file, **template_args)
                rendered_theme_files.append(rendered_path)
            new_theme_path = os.path.join(cache_dir, theme_file+'.new')
            with io.open(new_theme_path, 'wb') as f:
                for path in rendered_theme_files:
                    f.write(io.open(path, 'rb').read())
            os.rename(new_theme_path, cached_theme_path)
        mtime = os.stat(cached_theme_path).st_mtime
        if self.settings['debug']:
            # This makes sure that the files are always re-downloaded
            mtime = time.time()
        kind = 'css'
        out_dict['files'].append({
            'filename': theme_file,
            'hash': filename_hash,
            'mtime': mtime,
            'kind': kind,
            'element_id': 'theme'
        })
        self.file_cache[filename_hash] = {
            'filename': theme_file,
            'kind': kind,
            'path': cached_theme_path,
            'mtime': mtime,
            'element_id': 'theme'
        }
        if use_client_cache:
            message = {'go:file_sync': out_dict}
            self.write_message(message)
        else:
            self.file_request(
                filename_hash, use_client_cache=use_client_cache)

    def cache_cleanup(self, message):
        """
        Attached to the `go:cache_cleanup` WebSocket action; rifles through the
        given list of *message['filenames']* from the client and sends a
        `go:cache_expired` WebSocket action to the client with a list of files
        that no longer exist in `self.file_cache` (so it can clean them up).
        """
        logging.debug("cache_cleanup(%s)" % message)
        filenames = message['filenames']
        kind = message['kind']
        expired = []
        for filename_hash in filenames:
            if filename_hash not in self.file_cache:
                expired.append(filename_hash)
        if not expired:
            logging.debug(_(
                "No expired %s files at client %s" %
                (kind, self.request.remote_ip)))
            return
        logging.debug(_(
            "Requesting deletion of expired files at client %s: %s" % (
            self.request.remote_ip, filenames)))
        message = {'go:cache_expired': message}
        self.write_message(message)
        # Also clean up stale files in the cache while we're at it
        newest_files = {}
        for filename_hash, file_obj in list(self.file_cache.items()):
            filename = file_obj['filename']
            if filename not in newest_files:
                newest_files[filename] = file_obj
                newest_files[filename]['filename_hash'] = filename_hash
            if file_obj['mtime'] > newest_files[filename]['mtime']:
                # Delete then replace the stale one
                stale_hash = newest_files[filename]['filename_hash']
                del self.file_cache[stale_hash]
                newest_files[file_obj['filename']] = file_obj
            if file_obj['mtime'] < newest_files[filename]['mtime']:
                del self.file_cache[filename_hash] # Stale

    def file_request(self, files_or_hash, use_client_cache=True):
        """
        Attached to the `go:file_request` WebSocket action; minifies, caches,
        and finally sends the requested file to the client.  If
        *use_client_cache* is `False` the client will be instructed not to cache
        the file.  Example message from the client requesting a file:

        .. code-block:: javascript

            GateOne.ws.send(JSON.stringify({
                'go:file_request': {'some_file.js'}}));

        .. note:: In reality 'some_file.js' will be a unique/unguessable hash.

        Optionally, *files_or_hash* may be given as a list or tuple and all the
        requested files will be sent.

        Files will be cached after being minified until a file is modified or
        Gate One is restarted.

        If the `slimit` module is installed JavaScript files will be minified
        before being sent to the client.

        If the `cssmin` module is installed CSS files will be minified before
        being sent to the client.
        """
        self.sync_log.debug(
            "file_request(%s, use_client_cache=%s)" % (
                files_or_hash, use_client_cache))
        if isinstance(files_or_hash, (list, tuple)):
            for filename_hash in files_or_hash:
                self.file_request(
                    filename_hash, use_client_cache=use_client_cache)
            return
        else:
            filename_hash = files_or_hash
        if filename_hash not in self.file_cache:
            error_msg = _('File Request Error: File not found ({0})').format(
                filename_hash)
            self.logger.warning(error_msg)
            out_dict = {
                'result': error_msg,
                'filename': filename_hash
            }
            self.write_message({'go:load_js': out_dict})
            return
        # Get the file info out of the file_cache so we can send it
        path = self.file_cache[filename_hash]['path']
        filename = self.file_cache[filename_hash]['filename']
        kind = self.file_cache[filename_hash]['kind']
        out_dict = {'result': 'Success', 'hash': filename_hash}
        out_dict.update(self.file_cache[filename_hash])
        del out_dict['path'] # Don't want the client knowing this
        url_prefix = self.settings['url_prefix']
        self.sync_log.info(_("Sending: {0}").format(filename))
        cache_dir = self.settings['cache_dir']
        def send_file(result):
            """
            Adds our minified data to the out_dict and sends it to the
            client.  Also adds sourceURL comments if possible.
            """
            out_dict['data'] = result
            if kind == 'js':
                source_url = None
                if 'gateone/applications/' in path:
                    application = path.split('applications/')[1].split('/')[0]
                    if 'plugins' in path:
                        static_path = path.split("%s/plugins/" % application)[1]
                        # e.g. /terminal/ssh/static/
                        source_url = "%s%s/%s" % (
                            url_prefix, application, static_path)
                    else:
                        static_path = path.split("%s/static/" % application)[1]
                        source_url = "%s%s/static/%s" % (
                            url_prefix, application, static_path)
                elif 'gateone/plugins/' in path:
                    plugin_name = path.split(
                        'gateone/plugins/')[1].split('/')[0]
                    static_path = path.split("%s/static/" % plugin_name)[1]
                    source_url = "%splugins/%s/static/%s" % (
                        url_prefix, plugin_name, static_path)
                if source_url:
                    out_dict['data'] += "\n//# sourceURL={source_url}\n".format(
                        source_url=source_url)
                message = {'go:load_js': out_dict}
            elif kind == 'css':
                out_dict['css'] = True # So loadStyleAction() knows what to do
                message = {'go:load_style': out_dict}
            elif kind == 'theme':
                out_dict['theme'] = True
                message = {'go:load_theme': out_dict}
            elif kind == 'html':
                out_dict['html'] = True
                message = {'go:cache_file': out_dict}
            else:
                message = {'go:cache_file': out_dict}
            try:
                self.write_message(message)
            except (WebSocketClosedError, AttributeError):
                pass # WebSocket closed before we got a chance to send this
        logging.debug("file_request() for: %s" % filename)
        if self.settings['debug']:
            result = get_or_cache(cache_dir, path, minify=False)
            send_file(result)
        else:
            # NOTE: We disable memoization below because get_or_cache() does its
            # own check to see if processing the file is necessary.
            CPU_ASYNC.call(get_or_cache, cache_dir, path,
                           minify=True, callback=send_file, memoize=False)

    def send_file(self, filepath, kind='misc', **metadata):
        """
        Tells the client to perform a sync of the file at the given *filepath*.
        The *kind* should only be one of 'html' or 'misc' for HTML templates
        and everything else, respectively.

        Any additional keyword arguments provided via *metadata* will be
        stored in the client-side fileCache database.

        .. note:: This kind of file sending *always* uses the client-side cache.
        """
        if not os.path.exists(filepath):
            self.sync_log.error(_("File does not exist: {0}").format(filepath))
            return
        cache_dir = self.settings['cache_dir']
        mtime = os.stat(filepath).st_mtime
        filename = os.path.split(filepath)[1]
        filepath_hash = hashlib.md5(filepath.encode('utf-8')).hexdigest()[:10]
        # Store the file info in the file_cache just in case we need to
        # reference the original (non-rendered) path later:
        self.file_cache[filepath_hash] = {
            'filename': filename,
            'kind': kind,
            'path': filepath,
            'mtime': mtime
        }
        if metadata:
            self.file_cache[filepath_hash].update(**metadata)
        file_dict = {
            'filename': filename,
            'hash': filepath_hash,
            'mtime': mtime,
            'kind': kind
        }
        out_dict = {'files': [file_dict]}
        message = {'go:file_sync': out_dict}
        self.write_message(message)

    def send_js_or_css(self, paths_or_fileobj, kind, element_id=None,
            requires=None, media="screen", filename=None, force=False):
        """
        Initiates a file synchronization of the given *paths_or_fileobj* with
        the client to ensure it has the latest version of the file(s).

        The *kind* argument must be one of 'js' or 'css' to indicate JavaScript
        or CSS, respectively.

        Optionally, *element_id* may be provided which will be assigned to the
        <script> or <style> tag that winds up being created (only works with
        single files).

        Optionally, a *requires* string or list/tuple may be given which will
        ensure that the given file gets loaded after any dependencies.

        Optionally, a *media* string may be provided to specify the 'media='
        value when creating a <style> tag to hold the given CSS.

        Optionally, a *filename* string may be provided which will be used
        instead of the name of the actual file when file synchronization occurs.
        This is useful for multi-stage processes (e.g. rendering templates)
        where you wish to preserve the original filename.  Just be aware that
        if you do this the given *filename* must be unique.

        If *force* is ``True`` the file will be synchronized regardless of the
        'send_js' or 'send_css' settings in your global Gate One settings.

        .. note:

            If the slimit module is installed it will be used to minify the JS
            before being sent to the client.
        """
        if kind == 'js' and not force:
            send_js = self.prefs['*']['gateone'].get('send_js', True)
            #print 'send_js',send_js
            #print 'self.prefs',self.prefs
            if not send_js:
                if not hasattr('logged_js_message', self):
                    self.logger.info(_(
                        "send_js is false; will not send JavaScript."))
                # So we don't repeat this message a zillion times in the logs:
                self.logged_js_message = True
                return
        elif kind == 'css' and not force:
            send_css = self.prefs['*']['gateone'].get('send_css', True)
            if not send_css:
                if not hasattr('logged_css_message', self):
                    self.logger.info(_("send_css is false; will not send CSS."))
                # So we don't repeat this message a zillion times in the logs:
                self.logged_css_message = True
        use_client_cache = self.prefs['*']['gateone'].get(
            'use_client_cache', True)
        if requires and not isinstance(requires, (tuple, list)):
            requires = [requires] # This makes the logic simpler at the client
        if isinstance(paths_or_fileobj, (tuple, list)):
            out_dict = {'files': []}
            for file_obj in paths_or_fileobj:
                if isinstance(file_obj, basestring):
                    path = file_obj
                    if not filename:
                        filename = os.path.split(path)[1]
                else:
                    file_obj.seek(0) # Just in case
                    path = file_obj.name
                    if not filename:
                        filename = os.path.split(file_obj.name)[1]
                self.sync_log.info(
                    "Sync Check: {filename}".format(filename=filename))
                mtime = os.stat(path).st_mtime
                filename_hash = hashlib.md5(
                    filename.encode('utf-8')).hexdigest()[:10]
                self.file_cache[filename_hash] = {
                    'filename': filename,
                    'kind': kind,
                    'path': path,
                    'mtime': mtime,
                    'element_id': element_id,
                    'requires': requires,
                    'media': media # NOTE: Ignored if JS
                }
                if self.settings['debug']:
                    # This makes sure that the files are always re-downloaded
                    mtime = time.time()
                out_dict['files'].append({
                    'filename': filename,
                    'hash': filename_hash,
                    'mtime': mtime,
                    'kind': kind,
                    'requires': requires,
                    'element_id': element_id,
                    'media': media # NOTE: Ignored if JS
                })
            if use_client_cache:
                message = {'go:file_sync': out_dict}
                self.write_message(message)
            else:
                files = [a['filename'] for a in out_dict['files']]
                self.file_request(files, use_client_cache=use_client_cache)
            return # No further processing is necessary
        elif isinstance(paths_or_fileobj, basestring):
            path = paths_or_fileobj
            if not filename:
                filename = os.path.split(path)[1]
        else:
            paths_or_fileobj.seek(0) # Just in case
            path = paths_or_fileobj.name
            if not filename:
                filename = os.path.split(paths_or_fileobj.name)[1]
        self.sync_log.info(
            "Sync check: {filename}".format(filename=filename))
        # NOTE: The .split('.') above is so the hash we generate is always the
        # same.  The tail end of the filename will have its modification date.
        # Cache the metadata for sync
        mtime = os.stat(path).st_mtime
        logging.debug('send_js_or_css(%s) (mtime: %s)' % (path, mtime))
        if not os.path.exists(path):
            self.logger.error(_("send_js_or_css(): File not found: %s" % path))
            return
        # Use a hash of the filename because these names can get quite long.
        # Also, we don't want to reveal the file structure on the server.
        filename_hash = hashlib.md5(
            filename.encode('utf-8')).hexdigest()[:10]
        self.file_cache[filename_hash] = {
            'filename': filename,
            'kind': kind,
            'path': path,
            'mtime': mtime,
            'element_id': element_id,
            'requires': requires,
            'media': media # NOTE: Ignored if JS
        }
        if self.settings()['debug']:
            # This makes sure that the files are always re-downloaded
            mtime = time.time()
        out_dict = {'files': [{
            'filename': filename,
            'hash': filename_hash,
            'mtime': mtime,
            'kind': kind,
            'requires': requires,
            'element_id': element_id,
            'media': media # NOTE: Ignored if JS
        }]}
        #print 'out_dict',out_dict
        if use_client_cache:
            message = {'go:file_sync': out_dict}
            self.write_message(message)
        else:
            files = [a['filename'] for a in out_dict['files']]
            self.file_request(files, use_client_cache=use_client_cache)

    def send_js(self, path, **kwargs):
        """
        A shortcut for ``self.send_js_or_css(path, 'js', **kwargs)``.
        """
        self.send_js_or_css(path, 'js', **kwargs)

    def send_css(self, path, **kwargs):
        """
        A shortcut for ``self.send_js_or_css(path, 'css', **kwargs)``
        """
        self.send_js_or_css(path, 'css', **kwargs)

    def wrap_and_send_js(self, js_path, exports={}, **kwargs):
        """
        Wraps the JavaScript code at *js_path* in a (JavaScript) sandbox which
        exports whatever global variables are provided via *exports* then
        minifies, caches, and sends the result to the client.

        The provided *kwargs* will be passed to the
        `ApplicationWebSocket.send_js` method.

        The *exports* dict needs to be in the following format::

            exports = {
                "global": "export_name"
            }

        For example, if you wanted to use underscore.js but didn't want to
        overwrite the global ``_`` variable (if already being used by a parent
        web application)::

            exports = {"_": "GateOne._"}
            self.wrap_and_send_js('/path/to/underscore.js', exports)

        This would result in the "_" global being exported as "GateOne._".  In
        other words, this is what will end up at the bottom of the wrapped
        JavaScript just before the end of the sandbox:

        .. code-block:: javascript

            window.GateOne._ = _;

        This method should make it easy to include any given JavaScript library
        without having to worry (as much) about namespace conflicts.

        .. note::

            You don't have to prefix your export with 'GateOne'.  You can export
            the global with whatever name you like.
        """
        if not os.path.exists(js_path):
            self.sync_log.error(_("File does not exist: {0}").format(js_path))
            return
        cache_dir = self.settings['cache_dir']
        mtime = os.stat(js_path).st_mtime
        filename = os.path.split(js_path)[1]
        script = {'name': filename}
        filepath_hash = hashlib.md5(
            js_path.encode('utf-8')).hexdigest()[:10]
        # Store the file info in the file_cache just in case we need to
        # reference the original (non-rendered) path later:
        self.file_cache[filepath_hash] = {
            'filename': filename,
            'kind': 'js',
            'path': js_path,
            'mtime': mtime,
        }
        rendered_filename = 'rendered_%s_%s' % (filepath_hash, int(mtime))
        rendered_path = os.path.join(cache_dir, rendered_filename)
        if os.path.exists(rendered_path):
            self.send_js(rendered_path, filename=filename, force=True, **kwargs)
            return
        script['source'] = resource_string('gateone', 'templates/libwrapper.js')
        rendered = self.render_string(
            libwrapper,
            script=script,
            exports=exports
        )
        with io.open(rendered_path, 'wb') as f:
            f.write(rendered)
        self.send_js(rendered_path, filename=filename, force=True, **kwargs)
        # Remove older versions of the rendered template if present
        for fname in os.listdir(cache_dir):
            if fname == rendered_filename:
                continue
            elif filepath_hash in fname:
                # Older version present.
                # Remove it (and it's minified counterpart).
                os.remove(os.path.join(cache_dir, fname))
        return rendered_path

    def render_and_send_css(self,
            css_path, element_id=None, media="screen", **kwargs):
        """
        Renders, caches (in the `cache_dir`), and sends a stylesheet template at
        the given *css_path*.  The template will be rendered with the following
        keyword arguments::

            container = self.container
            prefix = self.prefix
            url_prefix = self.settings['url_prefix']
            **kwargs

        Returns the path to the rendered template.

        .. note::

            If you want to serve Gate One's CSS via a different mechanism
            (e.g. nginx) this functionality can be completely disabled by adding
            `"send_css": false` to gateone/settings/10server.conf
        """
        send_css = self.prefs['*']['gateone'].get('send_css', True)
        if not send_css:
            if not hasattr('logged_css_message', self):
                self.logger.info(_("send_css is false; will not send CSS."))
            # So we don't repeat this message a zillion times in the logs:
            self.logged_css_message = True
            return
        if not os.path.exists(css_path):
            self.sync_log.error(_("File does not exist: {0}").format(css_path))
            return
        cache_dir = self.settings['cache_dir']
        mtime = os.stat(css_path).st_mtime
        filename = os.path.split(css_path)[1]
        filepath_hash = hashlib.md5(css_path.encode('utf-8')).hexdigest()[:10]
        # Store the file info in the file_cache just in case we need to
        # reference the original (non-rendered) path later:
        self.file_cache[filepath_hash] = {
            'filename': filename,
            'kind': 'css',
            'path': css_path,
            'mtime': mtime,
        }
        rendered_filename = 'rendered_%s_%s' % (filepath_hash, int(mtime))
        rendered_path = os.path.join(cache_dir, rendered_filename)
        if os.path.exists(rendered_path):
            self.send_css(rendered_path,
                element_id=element_id, media=media, filename=filename)
            return
        template_loaders = tornado.web.RequestHandler._template_loaders
        # This wierd little bit empties Tornado's template cache:
        for web_template_path in template_loaders:
            template_loaders[web_template_path].reset()
        rendered = self.render_string(
            css_path,
            container=self.container,
            prefix=self.prefix,
            url_prefix=self.settings['url_prefix'],
            **kwargs
        )
        with io.open(rendered_path, 'wb') as f:
            f.write(rendered)
        self.send_css(rendered_path,
            element_id=element_id, media=media, filename=filename)
        # Remove older versions of the rendered template if present
        for fname in os.listdir(cache_dir):
            if fname == rendered_filename:
                continue
            elif filepath_hash in fname:
                # Older version present.
                # Remove it (and it's minified counterpart).
                os.remove(os.path.join(cache_dir, fname))
        return rendered_path

    def send_plugin_static_files(self, entry_point, requires=None):
        """
        Sends all plugin .js and .css files to the client that exist inside the
        /static/ directory for given *entry_point*.  The policies that apply to
        the current user will be used to determine whether and which static
        files will be sent.

        If *requires* is given it will be passed along to `self.send_js()`.

        .. note::

            If you want to serve Gate One's JavaScript via a different mechanism
            (e.g. nginx) this functionality can be completely disabled by adding
            `"send_js": false` to gateone/settings/10server.conf
        """
        logging.debug('send_plugin_static_files(%s)' % entry_point)
        send_js = self.prefs['*']['gateone'].get('send_js', True)
        if not send_js:
            if not hasattr('logged_js_message', self):
                self.logger.info(_(
                    "send_js is false; will not send JavaScript."))
            # So we don't repeat this message a zillion times in the logs:
            self.logged_js_message = True
        send_css = self.prefs['*']['gateone'].get('send_css', True)
        if not send_css:
            if not hasattr('logged_css_message', self):
                self.logger.info(_(
                    "send_css is false; will not send JavaScript."))
            # So we don't repeat this message a zillion times in the logs:
            self.logged_css_message = True
        application = None
        if entry_point == 'go_plugins':
            application = 'gateone'
        else: # Find the application that this belongs to
            for ep in iter_entry_points(group=entry_point):
                if ep.module_name.startswith('gateone.applications'):
                    application = ep.module_name.split('.')[2]
                    break
        policy = applicable_policies(application, self.current_user, self.prefs)
        globally_enabled_plugins = policy.get('enabled_plugins', [])
        # This controls the client-side plugins that will be sent
        allowed_client_side_plugins = policy.get('user_plugins', [])
        # Remove non-globally-enabled plugins from user_plugins (if set)
        if globally_enabled_plugins and allowed_client_side_plugins:
            for p in list(allowed_client_side_plugins):
                if p not in globally_enabled_plugins:
                    del allowed_client_side_plugins[p]
        elif globally_enabled_plugins and not allowed_client_side_plugins:
            allowed_client_side_plugins = globally_enabled_plugins
        # Get the list of plugins
        plugins = entry_point_files(entry_point, allowed_client_side_plugins)
        if send_js:
            for plugin, asset_list in plugins['js'].items():
                for asset in asset_list:
                    js_file_path = resource_filename(plugin, asset)
                    self.send_js(js_file_path, requires=requires)
        if send_css:
            for plugin, asset_list in plugins['css'].items():
                for asset in asset_list:
                    css_file_path = resource_filename(plugin, asset)
                    self.send_css(css_file_path, requires=requires)

# TODO:  Add support for a setting that can control which themes are visible to users.
    def enumerate_themes(self):
        """
        Returns a JSON-encoded object containing the installed themes and text
        color schemes.
        """
        themes = resource_listdir('gateone', '/templates/themes')
        # Just in case other junk wound up in that directory:
        themes = [a for a in themes if a.endswith('.css')]
        themes = [a.replace('.css', '') for a in themes] # Just need the names
        message = {'go:themes_list': {'themes': themes}}
        self.write_message(message)

    def set_locales(self, locales):
        """
        Attached to the 'go:set_locales` WebSocket action; sets
        ``self.user_locales`` to the given *locales* and calls
        `ApplicationWebSocket.send_js_translation` to deliver the best-match
        JSON-encoded translation to the client (if available).

        The *locales* argument may be a string or a list.  If a string,
        ``self.user_locales`` will be set to a list with the given locale as the
        first (and only) item.  If *locales* is a list ``self.user_locales``
        will simply be replaced.
        """
        if isinstance(locales, str):
            locales = [locales]
        self.user_locales = locales
        self.send_js_translation()

    def send_js_translation(self, package='gateone', path=None, locales=None):
        """
        Sends a message to the client containing a JSON-encoded table of strings
        that have been translated to the user's locale.  The translation file
        will be retrieved via the `pkg_resources.resource_string` function using
        the given *package* with a default path (if not given) of,
        '/i18n/{locale}/LC_MESSAGES/gateone_js.json'.  For example::

            self.send_js_translation(package="gateone.plugins.myplugin")

        Would result in the `pkg_resources.resource_string` function being
        called like so::

            path = '/i18n/{locale}/LC_MESSAGES/gateone_js.json'.format(
                locale=locale)
            translation = pkg_resources.resource_string(
                "gateone.plugins.myplugin", path)

        If providing a custom *path* be sure it includes the '{locale}' portion
        so the correct translation will be chosen.  As an example, your plugin
        might store locales inside a 'translations' directory with each locale
        JSON translation file named, '<locale>/myplugin.json'.  The correct
        *path* for that would be: '/translations/{locale}/myplugin.json'

        If no *locales* (may be list or string) is given the
        ``self.user_locales`` variable will be used.

        This method will attempt to find the closest locale if no direct match
        can be found.  For example, if ``locales=="fr"`` the 'fr_FR' locale
        would be used.  If *locales* is a list, the first matching locale will
        be used.

        .. note::

            Translation files must be the result of a
            ``pojson /path/to/translation.po`` conversion.
        """
        from applications.locale import supported_locales
        if not locales:
            locales = self.user_locales
        if not locales: # Use the server's locale
            locales = [self.prefs['*']['gateone'].get('locale')]
        logging.debug("send_js_translation() locales: %s" % locales)
        for locale in locales:
            locale = locale.replace('-', '_') # Example: Converts en-US to en_US
            #return if locale is en_us
            if locale.lower().startswith('en'):
                return # Gate One strings are English by default
            if not path:
                path = '/i18n/{locale}/LC_MESSAGES/gateone_js.json'
            if locale not in supported_locales: # Try next-closest match
                first_part = locale.split('_')[0] # Try the first bit
                for l in supported_locales:
                    if l.lower().startswith(first_part.lower()):
                        locale = l
                        break
            json_translation = path.format(locale=locale)
            if resource_exists(package, json_translation):
                decoded = json_decode(
                    resource_string(package, json_translation))
                message = {'go:register_translation': decoded}
                self.write_message(message)
                return
            logging.debug(_(
                "No matching translation found for locale: %s" % locale))
        self.logger.error(
            _("No translation file could not be found for the given "
              "locales: %s") % locales)

# NOTE: This is not meant to be a chat application.  That'll come later :)
#       The real purpose of send_user_message() and broadcast() are for
#       programmatic use.  For example, when a user shares a terminal and it
#       would be appropriate to notify certain users that the terminal is now
#       available for them to connect.
    #@require(authenticated(), policies('gateone'))
    def send_user_message(self, settings):
        """
        Sends the given *settings['message']* to the given *settings['upn']*.

        if *upn* is 'AUTHENTICATED' all users will get the message.  Example:

        .. code-block:: javascript

            var obj = {"message": "This is a test", "upn": "joe@company.com"}
            GateOne.ws.send(JSON.stringify({"go:send_user_message": obj}));
        """
        if 'message' not in settings:
            self.send_message(_("Error: No message to send."))
            return
        if 'upn' not in settings:
            self.send_message(_("Error: Missing UPN."))
            return
        metadata = {"to": settings["upn"]}
        self.msg_log.info(
            _("User Message: {0}").format(settings["message"]),
            metadata=metadata)
        self.send_message(settings['message'], upn=settings['upn'])
        self.trigger('go:send_user_message', settings)

    def send_message(self, message, session=None, upn=None):
        """
        Sends the given *message* to the client using the `go:user_message`
        WebSocket action at the currently-connected client.

        If *upn* is provided the *message* will be sent to all users with a
        matching 'upn' value.

        If *session* is provided the message will be sent to all users with a
        matching session ID.  This is useful in situations where all users share
        the same 'upn' (i.e. ANONYMOUS).

        if *upn* is 'AUTHENTICATED' all users will get the message.
        """
        message_dict = {'go:user_message': message}
        if upn:
            ApplicationWebSocket._deliver(message_dict, upn=upn)
        elif session:
            ApplicationWebSocket._deliver(message_dict, session=session)
        else: # Just send to the currently-connected client
            self.write_message(message_dict)
        self.trigger('go:send_message', message, upn, session)
    
    #@require(authenticated(), policies('gateone'))
    def broadcast(self, message):
        """
        Attached to the `go:broadcast` WebSocket action; sends the given
        *message* (string) to all connected, authenticated users.  Example
        usage:

        .. code-block:: javascript

            GateOne.ws.send(JSON.stringify({"go:broadcast": "This is a test"}));
        """
        self.msg_log.info("Broadcast: %s" % message)
        from applications.utils import strip_xss # Prevent XSS attacks
        message, bad_tags = strip_xss(message, replacement="entities")
        self.send_message(message, upn="AUTHENTICATED")
        self.trigger('go:broadcast', message)
    
    #@require(authenticated(), policies('gateone'))
    def list_server_users(self):
        """
        Returns a list of users currently connected to the Gate One server to
        the client via the 'go:user_list' WebSocket action.  Only users with the
        'list_users' policy are allowed to execute this action.  Example:

        .. code-block:: javascript

            GateOne.ws.send(JSON.stringify({"go:list_users": null}));

        That would send a JSON message to the client like so::

            {
                "go:user_list": [
                    {"upn": "user@enterprise", "ip_address": "10.0.1.11"},
                    {"upn": "bsmith@enterprise", "ip_address": "10.0.2.15"}
                ]
            }
        """
        users = ApplicationWebSocket._list_connected_users()
        logging.debug('list_server_users(): %s' % repr(users))
        # Remove things that users should not see such as their session ID
        filtered_users = []
        policy = applicable_policies('gateone', self.current_user, self.prefs)
        allowed_fields = policy.get('user_list_fields', False)
        # If not set, just strip the session ID
        if not allowed_fields:
            allowed_fields = ('upn', 'ip_address')
        for user in users:
            if not user: # Broadcast client (view-only situation)
                continue
            user_dict = {}
            for key, value in user.items():
                if key in allowed_fields:
                    user_dict[key] = value
            filtered_users.append(user_dict)
        message = {'go:user_list': filtered_users}
        self.write_message(json_encode(message))
        self.trigger('go:user_list', filtered_users)

    @classmethod
    def _deliver(cls, message, upn="AUTHENTICATED", session=None):
        """
        Writes the given *message* (string) to all users matching *upn* using
        the write_message() function.  If *upn* is not provided or is
        "AUTHENTICATED", will send the *message* to all users.

        Alternatively a *session* ID may be specified instead of a *upn*.  This
        is useful when more than one user shares a UPN (i.e. ANONYMOUS).
        """
        logging.debug("_deliver(%s, upn=%s, session=%s)" %
            (message, upn, session))
        for instance in cls.instances:
            try: # Only send to users that have authenticated
                user = instance.current_user
            except (WebSocketClosedError, AttributeError):
                continue
            if session and user and user.get('session', None) == session:
                instance.write_message(message)
            elif upn == "AUTHENTICATED":
                instance.write_message(message)
            elif user and upn == user.get('upn', None):
                instance.write_message(message)

    @classmethod
    def _list_connected_users(cls):
        """
        Returns a tuple of user objects representing the users that are
        currently connected (and authenticated) to this Gate One server.
        """
        logging.debug("_list_connected_users()")
        out = []
        for instance in cls.instances:
            try: # We only care about authenticated users
                out.append(instance.current_user)
            except AttributeError:
                continue
        return tuple(out)

    def license_info(self):
        """
        Returns the contents of the `__license_info__` dict to the client as
        a JSON-encoded message.
        """
        licenses = copy.deepcopy(__license_info__)
        # Remove the signatures so the license can't be copied by clients
        for license, data in licenses.items():
            if 'signature' in data:
                del data['signature']
                del data['signature_method'] # No need to send this either
            del data['license_format']   # Ditto
        message = {'go:license_info': licenses}
        self.write_message(message)
    
    #@require(authenticated(), policies('gateone'))
    def debug(self):
        """
        Imports Python's Garbage Collection module (gc) and displays various
        information about the current state of things inside of Gate One.

        .. note:: Can only be called from a JavaScript console like so...

        .. code-block:: javascript

            GateOne.ws.send(JSON.stringify({'go:debug': null}));
        """
        # NOTE: Making a debug-specific logger but logging using info() so that
        # the log messages show up even if I don't have logging set to debug.
        # Since this debugging function is only ever called manually there's no
        # need to use debug() logging.
        metadata = {
            'upn': self.current_user['upn'],
            'ip_address': self.request.remote_ip,
            'location': self.location
        }
        debug_logger = go_logger("gateone.debugging", **metadata)
        import gc
        #gc.set_debug(gc.DEBUG_UNCOLLECTABLE|gc.DEBUG_OBJECTS)
        gc.set_debug(
            gc.DEBUG_UNCOLLECTABLE | gc.DEBUG_INSTANCES | gc.DEBUG_OBJECTS)
        # Using pprint for some things below instead of the logger because they
        # just won't look right if they go to the logs.
        from pprint import pprint
        pprint(gc.garbage)
        debug_logger.info("Debug: gc.collect(): %s" % gc.collect())
        pprint(gc.garbage)
        logging.info("SESSIONS:")
        pprint(SESSIONS)
        logging.info("PERSIST:")
        pprint(PERSIST)
        try:
            from pympler import asizeof
            debug_logger.info(
                "Debug: Size of SESSIONS dict: %s" % asizeof.asizeof(SESSIONS))
        except ImportError:
            pass # No biggie
        try:
            # NOTE: For this Heapy stuff to work best you have to make more then
            # one call to this function (just do it at regular intervals).
            from guppy import hpy
            if not hasattr(self, 'hp'):
                self.hp = hpy()
                self.hp.setrelheap() # We only want to track NEW stuff
            logging.info("Heap:")
            h = self.hp.heap()
            logging.info(h)
            # Uncomment this to troubleshoot memory leaks.  If any exist this
            # loop will shine a light on them:
            #print("Heap Details (up to top 10):")
            #for i in range(10):
                #try:
                    #print(h.byrcs[i].byid)
                #except IndexError:
                    #break
        except ImportError:
            pass # Oh well
        
    def connection_groups(self, **kwargs):
        """
        Called to return the list of groups to automatically add/remove
        this connection to/from.
        """
        return ["test"]

    #@channel_session
    def connect(self, message, **kwargs):
        print 'connected'
        self.request(message=message)
        from applications.app_terminal import TerminalApplication
        self.initialize(apps=[TerminalApplication],message=message)
        #print 'connect prefx',self.prefs
        #print message.http_session.items()
        #authenticate user
        
        #print message
        #print message.content
        #status,result = self.cookieconvert(message)
        #print signing.loads(result.get(' gateone_user',None)[1:-1])
        ##print signing.loads()
        #if status:
            #pass
            #print result
            #print result.get('sessionid',None)
            #from django.contrib.sessions.models import Session
            #print Session.objects.filter(session_key=result.get('sessionid',None))[0].get_decoded().get('gateone_user',None)  
            #print result.get('gateone_user',None)
            #print signing.dumps(Session.objects.filter(session_key=result.get('sessionid',None))[0].get_decoded().get('gateone_user',None))
            #print signing.loads()
            #print "eyJ1cG4iOiJqaW1teSIsInNlc3Npb24iOiJaREkwTURaak1UTXlaakptTkRrMFpEazJOV1kyTVRrMVptTmpZV0V6WldZd00iLCJpcF9hZGRyZXNzIjoiMTI3LjAuMC4xIn0:1d8dG8:AV-P9r0_A28jp-ruHMtSpyArNwk"
        #print 'open prefx',self.prefs
        return self.open(message)
    
    #@channel_session
    def receive(self, message, **kwargs):
        print 'receive message',message,kwargs
        return self.on_message(message)

    def disconnect(self, message, **kwargs):
        print 'disconnect websocket',message
        #return self.on_close()
    
    #def send(self, content, close=False):
        #"""
        #Encode the given content as JSON and send it to the client.
        #"""
        #super(JsonWebsocketConsumer, self).send(text=self.encode_json(content), close=close)    
        
    def write_message(self, message,):
        print 'write_message',message
        if isinstance(message, dict):
            message = json_encode(message)
        return self.send(message)
    
    def current_user(self, message):
        user = message.http_session.get('gateone_user',None)
        if user:
            user.pop('protocol')
            return user
        return None
    
    #@channel_session
    def raw_receive(self, message, **kwargs):
        """
        Called when a WebSocket frame is received. Decodes it and passes it
        to receive().
        """
        print 'raw message',message
        if "text" in message:
            self.receive(message, **kwargs)
        #else:
            #self.receive(bytes=message['bytes'], **kwargs)        

    def cookieconvert(self,message):
        headers = message.get('headers',None)
        #default I choose trust client cookies, this is a bug. Afterward i would fix it.
        #data example
        #(True, {'csrftoken': 'HoGOLeWKmgMvz27aXXvssqzuU8qPX57xFT8C7slyfoSSsLgMMaalkfwyksAJe7qa', \
        #' sessionid': 'uo53r2dgfyhj9af8abrebgr8dc046o1s', \
        #' gateone_user': '"eyJ1cG4iOiJqaW1teSIsInNlc3Npb24iOiJaREkwTURaak1UTXlaakptTkRrMFpEazJOV1kyTVRrMVptTmpZV0V6WldZd00iLCJpcF9hZGRyZXNzIjoiMTI3LjAuMC4xIn0:1d8dG8:AV-P9r0_A28jp-ruHMtSpyArNwk"'})
        #from django.contrib.sessions.models import Session
        #print Session.objects.filter(session_key=self.request.session.session_key)[0].get_decoded().get('gateone_user', None)
        #print self.request.session.session_key         
        #print message.user
        #print dir(message)
        #print message.__dict__
        #print message.channel_session.__dict__
        #print type(message.content)        
        try:
            cookies = dict()
            if headers:
                headers = dict(headers)
                cookie = headers.get('cookie',None)
                if cookie:
                    for i in cookie.rsplit(';'):
                        i = iter(i.rsplit('='))
                        cookies.update(dict(izip(i, i)))
        except Exception,e:
            return False,None
        return True,cookies
    
    def raw_connect(self, message, **kwargs):
        """
        Called when a WebSocket connection is opened. Base level so you don't
        need to call super() all the time.
        """
        #print 'raw connect',message.content
        for group in self.connection_groups(**kwargs):
            Group(group, channel_layer=message.channel_layer).add(message.reply_channel)
        self.connect(message, **kwargs)    
    
    def request(self, message=None):
        return message
    
    def settings(self):
        from applications.configuration import define_options
        settings = define_options()
        return define_options()


class ErrorHandler(tornado.web.RequestHandler):
    """
    Generates an error response with status_code for all requests.
    """
    def __init__(self, application, request, status_code):
        tornado.web.RequestHandler.__init__(self, application, request)
        self.set_status(status_code)

    def get_error_html(self, status_code, **kwargs):
        self.set_header('Server', 'GateOne')
        self.set_header('License', __license__)
        self.require_setting("static_url")
        if status_code in [404, 500, 503, 403]:
            filename = os.path.join(
                self.settings['static_url'], '%d.html' % status_code)
            if os.path.exists(filename):
                with io.open(filename, 'rb') as f:
                    data = f.read()
                return data
        import httplib
        return "<html><title>%(code)d: %(message)s</title>" \
           "<body class='bodyErrorPage'>%(code)d: %(message)s</body></html>" % {
               "code": status_code,
               "message": httplib.responses[status_code],
        }

    def prepare(self):
        raise tornado.web.HTTPError(self._status_code)

class GateOneApp(tornado.web.Application):
    def __init__(self, settings, **kwargs):
        """
        Setup our Tornado application...  Everything in *settings* will wind up
        in the Tornado settings dict so as to be accessible under self.settings.
        """
        # Base settings for our Tornado app
        static_url = resource_filename('gateone', '/static')
        tornado_settings = dict(
            cookie_secret=settings['cookie_secret'],
            static_url=static_url,
            static_url_prefix="%sstatic/" % settings['url_prefix'],
            gzip=True,
            login_url="%sauth" % settings['url_prefix']
        )
        # Make sure all the provided settings wind up in self.settings
        for k, v in settings.items():
            tornado_settings[k] = v
        # Setup the configured authentication type
        AuthHandler = NullAuthHandler # Default
        if 'auth' in settings and settings['auth']:
            if settings['auth'] == 'kerberos' and KerberosAuthHandler:
                AuthHandler = KerberosAuthHandler
            elif settings['auth'] == 'pam' and PAMAuthHandler:
                AuthHandler = PAMAuthHandler
            elif settings['auth'] == 'google':
                AuthHandler = GoogleAuthHandler
                if 'google_oauth' not in tornado_settings:
                    logging.error(_(
                        'In order to use Google authentication you must create '
                        'a Google project for your installation and add:\n\t'
                        '{"google_oauth": {"key": "<YOUR CLIENT ID>", "secret":'
                        ' "<YOUR CLIENT SECRET>"}} to your '
                        '20authentication.conf (under the "gateone" section).'))
                    logging.info(_(
                        'To create a Google auth client ID and secret go to: '
                        'https://console.developers.google.com/ and click on '
                        '"APIs and Auth".  Then click "Create New Client ID".'
                        ' Set the "JavaScript Origins" value to your Gate One '
                        'server\'s address and the "Redirect URIs" to https://'
                        '<your Gate One server FQDN>/auth'))
                    logging.info(_(
                        'For example, if your "JavaScript Origins" is: '
                        'https://gateone.example.com/'))
                    logging.info(_(
                        'Your "Redirect URIs" would be: '
                        'https://gateone.example.com/auth'))
                    sys.exit(1)
            elif settings['auth'] == 'cas':
                AuthHandler = CASAuthHandler
            elif settings['auth'] == 'ssl':
                AuthHandler = SSLAuthHandler
            elif settings['auth'] == 'api':
                AuthHandler = APIAuthHandler
            auth_log.info(_("Using %s authentication") % settings['auth'])
        else:
            auth_log.info(_(
                "No authentication method configured. All users will be "
                "ANONYMOUS"))
        docs_path = resource_filename('gateone', '/docs/build/html')
        url_prefix = settings['url_prefix']
        if not url_prefix.endswith('/'):
            # Make sure there's a trailing slash
            url_prefix = "%s/" % url_prefix
        # Make the / optional in the regex so it works with the @addslash
        # decorator.  e.g. "/whatever/" would become "/whatever/?"
        index_regex = "%s?" % url_prefix
        # Setup our URL handlers
        #print 'Applications',APPLICATIONS
        handlers = [
            (index_regex, MainHandler),
            (r"%sws" % url_prefix,
                ApplicationWebSocket, dict(apps=APPLICATIONS)),
            (r"%sauth" % url_prefix, AuthHandler),
            (r"%sdownloads/(.*)" % url_prefix, DownloadHandler),
            #(r"%sdocs/(.*)" % url_prefix, tornado.web.StaticFileHandler, {
                #"path": docs_path,
                #"default_filename": "index.html"
            #})
        ]
        if 'web_handlers' in kwargs:
            for handler_tuple in kwargs['web_handlers']:
                regex = handler_tuple[0]
                handler = handler_tuple[1]
                kwargs = {}
                try:
                    kwargs = handler_tuple[2]
                except IndexError:
                    pass # No kwargs for this handler
                # Make sure the regex is prefix with the url_prefix
                if not regex.startswith(url_prefix):
                    regex = "%s%s" % (url_prefix, regex)
                handlers.append((regex, handler, kwargs))
        # Override the default static handler to ensure the headers are set
        # to allow cross-origin requests.
        handlers.append(
            (r"%sstatic/(.*)" % url_prefix, StaticHandler, {"path": static_url}
        ))
        # Hook up the hooks
        for hooks in PLUGIN_HOOKS.values():
            if 'Web' in hooks:
                # Apply the plugin's Web handlers
                fixed_hooks = []
                if isinstance(hooks['Web'], (list, tuple)):
                    for h in hooks['Web']:
                        # h == (regex, Handler)
                        if not h[0].startswith(url_prefix): # Fix it
                            h = (url_prefix + h[0].lstrip('/'), h[1])
                            fixed_hooks.append(h)
                        else:
                            fixed_hooks.append(h)
                else:
                    if not hooks['Web'][0].startswith(url_prefix): # Fix it
                        hooks['Web'] = (
                            url_prefix + hooks['Web'][0].lstrip('/'),
                            hooks['Web'][1]
                        )
                        fixed_hooks.append(hooks['Web'])
                    else:
                        fixed_hooks.append(hooks['Web'])
                handlers.extend(fixed_hooks)
            if 'Init' in hooks:
                # Call the plugin's initialization functions
                hooks['Init'](tornado_settings)
        # Include JS-only and CSS-only plugins (for logging purposes)
        plugins = set(
            PLUGINS['py'].keys() + PLUGINS['js'].keys() + PLUGINS['css'].keys())
        # NOTE: JS and CSS files are normally sent after the user authenticates
        #       via ApplicationWebSocket.send_plugin_static_files()
        # Add static handlers for all the JS plugins (primarily for source URLs)
        for plugin in plugins:
            name = plugin.split('.')[-1]
            url_path = r"%splugins/%s/static/(.*)" % (url_prefix, name)
            handlers.append((url_path, StaticHandler,
                {"path": '/static/', 'use_pkg': plugin}
            ))
        # This removes duplicate handlers for the same regex, allowing plugins
        # to override defaults:
        handlers = merge_handlers(handlers)
        logger.info(_("Loaded global plugins: %s") % ", ".join(plugins))
        #print handlers
        #print tornado_settings
        tornado.web.Application.__init__(self, handlers, **tornado_settings)

def validate_authobj(args=sys.argv):
    """
    Handles the 'validate_authobj' CLI command.  Takes a JSON object as the only
    argument (must be inside single quotes) and validates the singature using
    the same mechanism as `ApplicationWebSocket.api_auth`.  Example usage:

    .. ansi-block::

        \x1b[1;34muser\x1b[0m@modern-host\x1b[1;34m:~ $\x1b[0m gateone validate_authobj '{"upn": "jdoe@company.com", "signature_method": "HMAC-SHA1", "timestamp": "1409266590093", "signature": "004464e27db90180a4b87b50b00dd77420052b6d", "api_key": "NGQxNTVjZWEzMmM1NDBmNGI5MzYwNTM3ZDY0MzZiNTczY", "api_version": "1.0"}'
        API Authentication Successful!
    """
    from .utils import create_signature
    if '--help' in args or len(args) < 1:
        print("Usage: gateone validate_authobj '<JSON auth object>'")
        sys.exit(1)
    def fail(*messages):
        for msg in messages:
            print("\x1b[1;31mError:\x1b[0m {0}".format(msg))
        print(_("\n\x1b[1;31mAPI Authentication Failed!\x1b[0m"))
    print(_("Checking: %s") % args[0])
    auth_obj = args[0]
    try:
        auth_obj = json_decode(auth_obj)
    except ValueError:
        fail(_("Not valid JSON: %s") % repr(auth_obj))
        sys.exit(2)
    all_settings = get_settings(options.settings_dir)
    go_settings = all_settings['*']['gateone']
    # Validate all required values are present
    required_keys = (
        'api_key', 'api_version', 'signature',
        'signature_method', 'timestamp', 'upn',
    )
    missing_keys = set()
    for key in required_keys:
        if key not in auth_obj:
            missing_keys.add(key)
    if missing_keys:
        fail(_("You appear to be missing the following keys from your JSON "
                "object: %s") % ', '.join(missing_keys))
        sys.exit(2)
    api_keys = go_settings.get('api_keys')
    if not api_keys:
        fail(_("You don't appear to have any API keys configured."),
             _("Tip: You can create them on-demand via: gateone --new_api_key"))
        sys.exit(2)
    api_key = auth_obj['api_key']
    upn = str(auth_obj['upn'])
    timestamp = str(auth_obj['timestamp']) # str in case integer
    signature = auth_obj['signature']
    signature_method = auth_obj['signature_method']
    api_version = auth_obj['api_version']
    if api_key not in api_keys:
        fail(_("The given API key (%s) was not found.") % api_key)
        sys.exit(2)
    secret = api_keys.get(api_key)
    if not secret:
        fail(_("The given API key (%s) has no secret!") % api_key,
             _("Your api_keys setting is probably not in the correct format."),
             _('The correct format is {"api_keys": {"<API key>":"<secret>"}}'),
             _("It is recommended that you run 'gateone --new_api_key' and "
               "modify (or at least look at) the resulting 30api_keys.conf"))
        sys.exit(2)
    supported_hmacs = {
        'HMAC-SHA1': hashlib.sha1,
        'HMAC-SHA256': hashlib.sha256,
        'HMAC-SHA384': hashlib.sha384,
        'HMAC-SHA512': hashlib.sha512,
    }
    if signature_method not in supported_hmacs:
        fail(_('API AUTH: Unsupported API auth signature method: %s')
            % signature_method)
        sys.exit(2)
    hmac_algo = supported_hmacs[signature_method]
    if api_version != "1.0":
        fail(_('API AUTH: Unsupported API version: %s') % api_version)
        sys.exit(2)
    # Everything checked out OK so we can try validating the signature now...
    sig_check = create_signature(
        secret, api_key, upn, timestamp,
        hmac_algo=supported_hmacs[signature_method])
    if sig_check != signature:
        fail(_(
            "The generated signature (%s) does not match what was provided in "
            "the given auth object (%s)") % (sig_check, signature))
        sys.exit(2)
    print("\x1b[1;32mAPI Authentication Successful!\x1b[0m")

def install_license(args=sys.argv):
    """
    Handles the 'install_license' CLI command.  Just installs the license at the
    path given via `sys.argv[1]` (first argument after the 'install_license'
    command).
    """
    if '--help' in args or len(args) < 1:
        print("Usage: {0} /path/to/license.txt".format(sys.argv[0]))
        sys.exit(1)
    import shutil
    # Give it a unique filename in case they're installing more than one
    filename = 'license%s.conf' % datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    install_path = os.path.join(options.settings_dir, filename)
    license_path = os.path.expanduser(args[0]) # In case ~
    license_path = os.path.expandvars(license_path) # In case $HOME (or similar)
    if os.path.exists(install_path):
        yesno = raw_input(_(
            "A license file is already installed.  Are you sure you want to "
            "replace it? (y/n) "))
        if yesno not in ('yes', 'y', 'YES', 'Y'):
            sys.exit(1)
    try:
        shutil.copy(license_path, install_path)
    except PermissionError:
        print("Error: Could not copy license (permission denied).")
        sys.exit(2)
    print("{0} has been installed ({1})".format(license_path, install_path))
    sys.exit(0)

def validate_licenses(licenses):
    """
    Given a *licenses* dict, logs and removes any licenses that have expired or
    have invalid signatures.  It then sets the `__license_info__` global with
    the updated dict.  Example license dict::

        {
            "11252c41-d3cd-45b7-929b-4a3baedcc152": {
                "product": "gateone",
                "customer": "ACME, Inc",
                "users": 250,
                "expires": 1441071222,
                "license_format": "1.0",
                "signature": "<gobbledygook>",
                "signature_method": "secp256k1"
            }
        }

    .. note::

        Signatures will be validated against Liftoff Software's public key.
    """
    # If you wish to defraud Liftoff Software (and your users) in regards to
    # licensing just uncomment this line:
    # return True
    import base64
    try:
        import pyelliptic
    except ImportError:
        logging.error(_(
            "Could not import pyelliptic which is required to validate "
            "licenses.  Please install it:  sudo pip install pyelliptic"))
        logging.error(_(
            "Or you could just download it: "
            "https://github.com/yann2192/pyelliptic"))
        sys.exit(2)
    pubkey = (
        b'\x02\xca\x00 J\xd9\xbb\x16(_ d\x03\xf6\xc2\x9dc\xea]\xef\x19).5?*#.'
        b'\xc6\x9cp\xb0G\x82\xab\x9e\x00 W\xa1t\xc1;\x08\xd78\x97\x1f\xfa\xe4'
        b'\xc7H5\x0f+\xbcG\x8a\xb6\xf6^\xf5N\xdd\xdfm\xe0V\xaar')
    new_licenses = copy.deepcopy(licenses)
    ecc = pyelliptic.ECC(pubkey=pubkey, curve='secp256k1') # Same as Bitcoin
    ignore_keys = ("signature", "signature_method", "license_format")
    for license, data in licenses.items():
        # Signatures are generated/validated using a concatenated string of all
        # keys in the license's dict in lexicographical order.
        combined = ""
        validated = True
        # Make a combined string to validate the signature against:
        for key, value in sorted(data.items()):
            if key in ignore_keys:
                continue
            combined += str(value)
        now = time.time()
        if int(data['expires']) < now:
            logging.error(_(
                "License for '{product}' has expired: {license}").format(
                    product=data['product'], license=license))
            validated = False
        signature = base64.b64decode(data["signature"])
        if validated and not ecc.verify(signature, combined):
            logging.error(_("License has an invalid signature: %s") % license)
            validated = False
        if validated: # Show a helpful warning message about soon-to-expires
            thirty_days_from_now = now + 2592000
            if int(data['expires']) < thirty_days_from_now:
                logging.warning(_(
                    "License for '{product}' will expire in less than 30 days: "
                    "{license}").format(
                        product=data['product'], license=license))
        if not validated:
            del new_licenses[license]
    if new_licenses:
        logging.info("All Gate One licenses are valid and up-to-date.")
        global __license_info__
        __license_info__ = new_licenses

global CPU_ASYNC
global IO_ASYNC
IO_ASYNC = ThreadedRunner()
cores = getsettings('multiprocessing_workers',None)
try:
    cores = int(cores)
except TypeError:
    cores = None
if cores == 0:
    logging.warning(_(
        "Multiprocessing is disabled.  Performance will be sub-optimal."
    ))
    CPU_ASYNC = IO_ASYNC # Use threading instead
else:
    try:
        CPU_ASYNC = MultiprocessRunner(max_workers=cores)
        CPU_ASYNC.call(noop, memoize=False) # Perform a realistic test
    except NotImplementedError:
        # System doesn't support multiprocessing (for whatever reason).
        logging.warning(_(
            "Multiprocessing is not functional on this system.  "
            "Threading for all async calls."))
        CPU_ASYNC = IO_ASYNC # Fall back to using threading