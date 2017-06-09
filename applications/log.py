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

import os.path, sys, logging, json
from applications.utils import mkdir_p
from tornado.options import options
from tornado.log import LogFormatter
import socket
from applications.utils import getsettings,convert_to_timedelta,none_fix,locale

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
    logger = JSONAdapter(logger, kwargs)
    return logger
