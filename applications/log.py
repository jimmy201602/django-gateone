# -*- coding: utf-8 -*-
#
#       Copyright 2013 Liftoff Software Corporation

# Meta
__license__ = "AGPLv3 or Proprietary (see LICENSE.txt)"
__doc__ = """
.. _log.py:

Logging Module for Gate One
===========================

This module contains a number of pre-defined loggers for use within Gate One:

    ==========  =============================================================
    Name        Description
    ==========  =============================================================
    go_log      Used for logging internal Gate One events.
    auth_log    Used for logging authentication and authorization events.
    msg_log     Used for logging messages sent to/from users.
    ==========  =============================================================

Applications may also use their own loggers for differentiation purposes.  Such
loggers should be prefixed with 'gateone.app.' like so::

    >>> import logging
    >>> logger = logging.getLogger("gateone.app.myapp")

Additional loggers may be defined within a `GOApplication` with additional
prefixing::

    >>> xfer_log = logging.getLogger("gateone.app.myapp.xfer")
    >>> lookup_log = logging.getLogger("gateone.app.myapp.lookup")

.. note::

    This module does not cover session logging within the Terminal application.
    That is a built-in feature of the `termio` module.
"""

import os.path, sys, logging
from applications.utils import mkdir_p
#from tornado.options import options
#from tornado.log import LogFormatter
import socket,logging
from applications.utils import getsettings,convert_to_timedelta,none_fix,locale,gen_self_signed_ssl
try:
    import simplejson as json
except ImportError:
    import json

try:
    import curses  # type: ignore
except ImportError:
    curses = None    

try:
    import colorama
except ImportError:
    colorama = None

def _stderr_supports_color():
    try:
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            if curses:
                curses.setupterm()
                if curses.tigetnum("colors") > 0:
                    return True
            elif colorama:
                if sys.stderr is getattr(colorama.initialise, 'wrapped_stderr',
                                         object()):
                    return True
    except Exception:
        # Very broad exception handling because it's always better to
        # fall back to non-colored logs than to break at startup.
        pass
    return False
    
PY3 = sys.version_info >= (3,)

LOGS = set() # Holds a list of all our log paths so we can fix permissions
# These should match what's in the syslog module (hopefully not platform-dependent)
FACILITIES = {
    'auth': 32,
    'cron': 72,
    'daemon': 24,
    'kern': 0,
    'local0': 128,
    'local1': 136,
    'local2': 144,
    'local3': 152,
    'local4': 160,
    'local5': 168,
    'local6': 176,
    'local7': 184,
    'lpr': 48,
    'mail': 16,
    'news': 56,
    'syslog': 40,
    'user': 8,
    'uucp': 64
}

if PY3:
    unicode_type = str
    basestring_type = str
else:
    # The names unicode and basestring don't exist in py3 so silence flake8.
    unicode_type = unicode  # noqa
    basestring_type = basestring  # noqa
    
_TO_UNICODE_TYPES = (unicode_type, type(None))

def to_unicode(value):
    """Converts a string argument to a unicode string.

    If the argument is already a unicode string or None, it is returned
    unchanged.  Otherwise it must be a byte string and is decoded as utf8.
    """
    if isinstance(value, _TO_UNICODE_TYPES):
        return value
    if not isinstance(value, bytes):
        raise TypeError(
            "Expected bytes, unicode, or None; got %r" % type(value)
        )
    return value.decode("utf-8")

_unicode = to_unicode

def _safe_unicode(s):
    try:
        return _unicode(s)
    except UnicodeDecodeError:
        return repr(s)
    
class LogFormatter(logging.Formatter):
    """Log formatter used in Tornado.

    Key features of this formatter are:

    * Color support when logging to a terminal that supports it.
    * Timestamps on every log line.
    * Robust against str/bytes encoding problems.

    This formatter is enabled automatically by
    `tornado.options.parse_command_line` or `tornado.options.parse_config_file`
    (unless ``--logging=none`` is used).
    """
    DEFAULT_FORMAT = '%(color)s[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d]%(end_color)s %(message)s'
    DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    DEFAULT_COLORS = {
        logging.DEBUG: 4,  # Blue
        logging.INFO: 2,  # Green
        logging.WARNING: 3,  # Yellow
        logging.ERROR: 1,  # Red
    }

    def __init__(self, color=True, fmt=DEFAULT_FORMAT,
                 datefmt=DEFAULT_DATE_FORMAT, colors=DEFAULT_COLORS):
        r"""
        :arg bool color: Enables color support.
        :arg string fmt: Log message format.
          It will be applied to the attributes dict of log records. The
          text between ``%(color)s`` and ``%(end_color)s`` will be colored
          depending on the level if color support is on.
        :arg dict colors: color mappings from logging level to terminal color
          code
        :arg string datefmt: Datetime format.
          Used for formatting ``(asctime)`` placeholder in ``prefix_fmt``.

        .. versionchanged:: 3.2

           Added ``fmt`` and ``datefmt`` arguments.
        """
        logging.Formatter.__init__(self, datefmt=datefmt)
        self._fmt = fmt

        self._colors = {}
        if color and _stderr_supports_color():
            # The curses module has some str/bytes confusion in
            # python3.  Until version 3.2.3, most methods return
            # bytes, but only accept strings.  In addition, we want to
            # output these strings with the logging module, which
            # works with unicode strings.  The explicit calls to
            # unicode() below are harmless in python2 but will do the
            # right conversion in python 3.
            fg_color = (curses.tigetstr("setaf") or
                        curses.tigetstr("setf") or "")
            if (3, 0) < sys.version_info < (3, 2, 3):
                fg_color = unicode_type(fg_color, "ascii")

            for levelno, code in colors.items():
                self._colors[levelno] = unicode_type(curses.tparm(fg_color, code), "ascii")
            self._normal = unicode_type(curses.tigetstr("sgr0"), "ascii")
        else:
            self._normal = ''

    def format(self, record):
        try:
            message = record.getMessage()
            assert isinstance(message, basestring_type)  # guaranteed by logging
            # Encoding notes:  The logging module prefers to work with character
            # strings, but only enforces that log messages are instances of
            # basestring.  In python 2, non-ascii bytestrings will make
            # their way through the logging framework until they blow up with
            # an unhelpful decoding error (with this formatter it happens
            # when we attach the prefix, but there are other opportunities for
            # exceptions further along in the framework).
            #
            # If a byte string makes it this far, convert it to unicode to
            # ensure it will make it out to the logs.  Use repr() as a fallback
            # to ensure that all byte strings can be converted successfully,
            # but don't do it by default so we don't add extra quotes to ascii
            # bytestrings.  This is a bit of a hacky place to do this, but
            # it's worth it since the encoding errors that would otherwise
            # result are so useless (and tornado is fond of using utf8-encoded
            # byte strings whereever possible).
            record.message = _safe_unicode(message)
        except Exception as e:
            record.message = "Bad message (%r): %r" % (e, record.__dict__)

        record.asctime = self.formatTime(record, self.datefmt)

        if record.levelno in self._colors:
            record.color = self._colors[record.levelno]
            record.end_color = self._normal
        else:
            record.color = record.end_color = ''

        formatted = self._fmt % record.__dict__

        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            # exc_text contains multiple lines.  We need to _safe_unicode
            # each line separately so that non-utf8 bytes don't cause
            # all the newlines to turn into '\n'.
            lines = [formatted.rstrip()]
            lines.extend(_safe_unicode(ln) for ln in record.exc_text.split('\n'))
            formatted = '\n'.join(lines)
        return formatted.replace("\n", "\n    ")
    
# Exceptions
class UnknownFacility(Exception):
    """
    Raised if `string_to_syslog_facility` is given a string that doesn't match
    a known syslog facility.
    """
    pass

def define_options():
    """
    Calls `tornado.options.define` for all of Gate One's command-line options.

    If *installed* is ``False`` the defaults will be set under the assumption
    that the user is non-root and running Gate One out of a download/cloned
    directory.
    """
    # NOTE: To test this function interactively you must import tornado.options
    # and call tornado.options.parse_config_file(*some_config_path*).  After you
    # do that the options will wind up in tornado.options.options
    # Simplify the auth option help message
    auths = "none, api, cas, google, ssl"
    #from applications.auth.authentication import PAMAuthHandler, KerberosAuthHandler
    #if KerberosAuthHandler:
        #auths += ", kerberos"
    #if PAMAuthHandler:
        #auths += ", pam"
    ## Simplify the syslog_facility option help message
    #facilities = list(FACILITIES.keys())
    #facilities.sort()
    # Figure out the default origins
    default_origins = [
        'localhost',
        '127.0.0.1',
    ]
    # Used both http and https above to demonstrate that both are acceptable
    try:
        additional_origins = socket.gethostbyname_ex(socket.gethostname())
    except socket.gaierror:
        # Couldn't get any IPs from the hostname
        additional_origins = []
    for host in additional_origins:
        if isinstance(host, str):
            default_origins.append('%s' % host)
        else: # It's a list
            for _host in host:
                default_origins.append('%s' % _host)
    default_origins = ";".join(default_origins)
    settings_base = getsettings('BASE_DIR')
    settings_default = os.path.join(settings_base, 'conf.d')
    settings_dir = settings_default
    if not os.path.isdir(settings_dir):
        mkdir_p(settings_dir)
    port_default = 8000
    log_default = os.path.join(settings_base, 'logs', 'gateone.log')
    user_dir_default = os.path.join(settings_base, 'users')
    pid_default = os.path.join(settings_base, 'pid', 'gateone.pid')
    session_dir_default = os.path.join(settings_base, 'sessions')
    cache_dir_default = os.path.join(settings_base, 'cache')
    ssl_dir = os.path.join(settings_base, 'ssl')
    debug = False
    cookie_secret = getsettings('SECRET_KEY')
    address = ""
    enable_unix_socket = False
    unix_socket_path = "/tmp/gateone.sock"
    unix_socket_mode = "0600"
    disable_ssl = False
    certificate = os.path.join(ssl_dir, "certificate.pem")
    keyfile = os.path.join(ssl_dir, "keyfile.pem")
    ca_certs = None
    ssl_auth = 'none'
    user_dir = user_dir_default 
    uid = str(os.getuid())
    gid = str(os.getgid()) 
    if not os.path.exists(user_dir):
        mkdir_p(user_dir)
        os.chmod(user_dir, 0o770)
    #if uid == 0 and os.getuid() != 0: 
        #if not check_write_permissions(uid, user_dir):
            #recursive_chown(user_dir, uid, gid)
    user_logs_max_age = "30d"
    session_dir = session_dir_default
    if not os.path.exists(session_dir):
        mkdir_p(session_dir)
        os.chmod(session_dir, 0o770)
    #if not check_write_permissions(uid, session_dir):
        #recursive_chown(session_dir, uid, gid)    
    syslog_facility = "daemon"
    session_timeout = "5d"
    new_api_key = False
    auth = "none"
    api_timestamp_window ="30s"
    sso_realm = None
    sso_service = "HTTP"
    pam_realm = os.uname()[1]
    pam_service = "login"
    embedded = False
    js_init = ""
    https_redirect = False
    url_prefix = "/"
    origins = default_origins
    pid_file = pid_default
    api_keys = ""
    combine_js = ""
    combine_css = ""
    combine_css_container = "gateone"
    multiprocessing_workers = None
    configure = False
    login_url ='/auth'
    static_url_prefix = '/static/'
    log_rotate_mode = 'size'
    logging = 'info'
    static_url = os.path.join(settings_base, 'static')
    session_logging = True
    log_file_num_backups = 10
    log_file_prefix = os.path.join(settings_base, 'log')
    if not os.path.exists(log_file_prefix):
        mkdir_p(log_file_prefix)
        os.chmod(log_file_prefix, 0o770)
    #if not check_write_permissions(uid, log_file_prefix):
        #recursive_chown(log_file_prefix, uid, gid)
    if not url_prefix.endswith('/'):
        url_prefix += '/' 
    global TIMEOUT
    TIMEOUT = convert_to_timedelta(session_timeout)
    api_timestamp_window = convert_to_timedelta(api_timestamp_window)
    auth = none_fix(auth)
    # Check to make sure we have a certificate and keyfile and generate fresh
    # ones if not.
    if not disable_ssl:
        if not os.path.exists(keyfile):
            ssl_base = os.path.dirname(keyfile)
            if not os.path.exists(ssl_base):
                mkdir_p(ssl_base)
            gen_self_signed_ssl(path=ssl_base)
        if not os.path.exists(certificate):
            ssl_base = os.path.dirname(certificate)
            gen_self_signed_ssl(path=ssl_base)   
    ssl_auth = ssl_auth.lower()
    log_file_max_size = 100000000
    global _
    global PLUGINS
    global APPLICATIONS
    cli_commands = {'gateone': {}} # CLI commands provided by plugins/apps
    settings = {}    
    global user_locale
    # Default to using the shell's LANG variable as the locale
    try:
        default_locale = os.environ['LANG'].split('.')[0]
    except KeyError: # $LANG isn't set
        default_locale = "en_US"
    #from django.utils.translation import ugettext as _
    #from django.utils.translation import ugettext_lazy as _
    #from django.utils.translation import activate, get_language_info
    #from django.utils.translation import activate
    #from django.utils import translation
    #user_language = 'fr'
    #translation.activate(user_language)    
    #activate('fr')
    #i = get_language_info('de')
    locales = default_locale
    user_locale = getsettings('LANGUAGE_CODE', 'en_US')
    # NOTE: The locale setting above is only for the --help messages.
    # Re-do the locale in case the user supplied something as --locale
    server_locale = locale.get(user_locale)
    _ = server_locale.translate # Also replaces our wrapper so no more .encode()
    # Set our global session timeout    
    https_redirect = False
    syslog_session_logging = False
    sso_keytab = None
    configure = False
    settings.update({
            u'dtach': True,
            'version': None,
            u'locale': locales,
            u'address': address,
            u'pam_service': pam_service,
            u'syslog_facility': syslog_facility,
            'cookie_secret': cookie_secret,
            u'enable_unix_socket': enable_unix_socket,
            u'port': port_default,
            u'uid': str(uid),
            u'url_prefix': url_prefix,
            u'user_dir': user_dir,
            'settings_dir': settings_dir,
            u'unix_socket_mode': unix_socket_mode,
            u'multiprocessing_workers': multiprocessing_workers,
            u'certificate': certificate,
            u'log_rotate_interval': 1,
            u'log_to_stderr': None,
            u'log_rotate_when': u'midnight',
            u'gid': str(gid),
            u'pid_file': pid_file,
            'command': None,
            'gzip': True,
            u'pam_realm': pam_realm,
            'login_url': login_url,
            'configure': configure,
            u'sso_service': sso_service,
            'cli_overrides': [],
            u'https_redirect': https_redirect,
            u'auth': auth,
            'api_keys': api_keys,
            u'disable_ssl': disable_ssl,
            u'ca_certs': ca_certs,
            u'cache_dir': cache_dir_default,
            u'syslog_session_logging': syslog_session_logging,
            u'user_logs_max_age': user_logs_max_age,
            u'sso_keytab': sso_keytab,
            u'api_timestamp_window': api_timestamp_window,
            'static_url_prefix': static_url_prefix,
            u'log_rotate_mode': log_rotate_mode,
            u'log_file_num_backups': log_file_num_backups,
            u'logging': logging,
            u'embedded': embedded,
            u'origins': default_origins,
            u'session_logging': session_logging,
            u'keyfile': keyfile,
            u'session_dir': session_dir,
            'static_url': static_url,
            u'ssl_auth': ssl_auth,
            u'log_file_max_size': log_file_max_size,
            u'session_timeout': TIMEOUT,
            u'sso_realm': sso_realm,
            u'debug': debug,
            u'js_init': js_init,
            u'unix_socket_path': unix_socket_path,
            u'log_file_prefix': os.path.join(log_file_prefix,'django-gateone.log'),
            u'kill': False,#new variable
            u'use_client_cache': True
})
    return settings

class JSONAdapter(logging.LoggerAdapter):
    """
    A `logging.LoggerAdapter` that prepends keyword argument information to log
    entries.  Expects the passed in dict-like object which will be included.
    """
    def process(self, msg, kwargs):
        extra = self.extra.copy()
        if 'metadata' in kwargs:
            extra.update(kwargs.pop('metadata'))
        if extra:
            json_data = json.dumps(extra, sort_keys=True, ensure_ascii=False)
            try:
                line = u'{json_data} {msg}'.format(json_data=json_data, msg=msg)
            except UnicodeDecodeError:
                line = u'{json_data} {msg}'.format(
                    json_data=json_data, msg=repr(msg))
        else:
            line = msg
        return (line, kwargs)

def string_to_syslog_facility(facility):
    """
    Given a string (*facility*) such as, "daemon" returns the numeric
    syslog.LOG_* equivalent.
    """
    if facility.lower() in FACILITIES:
        return FACILITIES[facility.lower()]
    else:
        raise UnknownFacility(
            "%s does not match a known syslog facility" % repr(facility))
    
def go_logger(name, **kwargs):
    """
    Returns a new `logging.Logger` instance using the given *name*
    pre-configured to match Gate One's usual logging output.  The given *name*
    will automatically be prefixed with 'gateone.' if it is not already.  So if
    *name* is 'app.foo' the `~logging.Logger` would end up named
    'gateone.app.foo'.  If the given *name* is already prefixed with 'gateone.'
    it will be left as-is.

    The log will be saved in the same location as Gate One's configured
    `log_file_prefix` using the given *name* with the following convention:

        ``gateone/logs/<modified *name*>.log``

    The file name will be modified like so:

        * It will have the 'gateone' portion removed (since it's redundant).
        * Dots will be replaced with dashes (-).

    Examples::

        >>> auth_logger = go_logger('gateone.auth.terminal')
        >>> auth_logger.info('test1')
        >>> app_logger = go_logger('gateone.app.terminal')
        >>> app_logger.info('test2')
        >>> import os
        >>> os.lisdir('/opt/gateone/logs')
        ['auth.log', 'auth-terminal.log', 'app-terminal.log' 'webserver.log']

    If any *kwargs* are given they will be JSON-encoded and included in the log
    message after the date/metadata like so::

        >>> auth_logger.info('test3', {"user": "bob", "ip": "10.1.1.100"})
        [I 130828 15:00:56 app.py:10] {"user": "bob", "ip": "10.1.1.100"} test3
    """
    logger = logging.getLogger(name)
    if not define_options()['log_file_prefix'] or define_options()['logging'].upper() == 'NONE':
        # Logging is disabled but we still have to return the adapter so that
        # passing metadata to the logger won't throw exceptions
        return JSONAdapter(logger, kwargs)
    preserve = None # Save the stdout handler (because it looks nice =)
    if name == None:
        # root logger; make sure we save the pretty-printing stdout handler...
        for handler in logger.handlers:
            if not isinstance(handler, logging.handlers.RotatingFileHandler):
                preserve = handler
    # Remove any existing handlers on the logger
    logger.handlers = []
    if preserve: # Add back the one we preserved (if any)
        logger.handlers.append(preserve)
    logger.setLevel(getattr(logging, define_options()['logging'].upper()))
    if define_options()['log_file_prefix']:
        if name:
            basepath = os.path.split(define_options()['log_file_prefix'])[0]
            filename = name.replace('.', '-') + '.log'
            path = os.path.join(basepath, filename)
        else:
            path = define_options()['log_file_prefix']
            basepath = os.path.split(define_options()['log_file_prefix'])[0]
        if not os.path.isdir(basepath):
            mkdir_p(basepath)
        LOGS.add(path)
        channel = logging.handlers.RotatingFileHandler(
            filename=path,
            maxBytes=define_options()['log_file_max_size'],
            backupCount=define_options()['log_file_num_backups'])
        #log format bug
        channel.setFormatter(LogFormatter(color=False))
        logger.addHandler(channel)
        #Following code is to redirect log to terminal
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)    
        console.setFormatter(LogFormatter(color=True))        
        logging.getLogger(name).addHandler(console)        
    logger = JSONAdapter(logger, kwargs)
    return logger
