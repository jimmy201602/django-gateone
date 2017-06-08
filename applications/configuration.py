# -*- coding: utf-8 -*-
#
#       Copyright 2013 Liftoff Software Corporation

# Meta
__license__ = "AGPLv3 or Proprietary (see LICENSE.txt)"
__doc__ = """
.. _settings.py:

Settings Module for Gate One
============================

This module contains functions that deal with Gate One's options/settings
"""

import os, sys, io, re, socket, tempfile, logging
from pkg_resources import resource_filename, resource_listdir, resource_string
from applications.log import FACILITIES
from applications.log import go_logger
from tornado import locale
from tornado.escape import json_decode
from tornado.options import define, options, Error
from applications.utils import getsettings,check_write_permissions,recursive_chown,convert_to_timedelta,none_fix,gen_self_signed_ssl

# Locale stuff (can't use .locale since .locale uses this module)
# Default to using the environment's locale with en_US fallback
temp_locale = locale.get(os.environ.get('LANG', 'en_US').split('.')[0])
_ = temp_locale.translate
del temp_locale

logger = go_logger(None)
comments_re = re.compile(
    r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
    re.DOTALL | re.MULTILINE
)
trailing_commas_re = re.compile(
    r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')

class SettingsError(Exception):
    """
    Raised when we encounter an error parsing .conf files in the settings dir.
    """
    pass

class RUDict(dict):
    """
    A dict that will recursively update keys and values in a safe manner so that
    sub-dicts will be merged without one clobbering the other.

    .. note::

        This class (mostly) taken from `here
        <http://stackoverflow.com/questions/6256183/combine-two-dictionaries-of-dictionaries-python>`_
    """
    def __init__(self, *args, **kw):
        super(RUDict,self).__init__(*args, **kw)

    def update(self, E=None, **F):
        if E is not None:
            if 'keys' in dir(E) and callable(getattr(E, 'keys')):
                for k in E:
                    if k in self:  # Existing ...must recurse into both sides
                        self.r_update(k, E)
                    else: # Doesn't currently exist, just update
                        self[k] = E[k]
            else:
                for (k, v) in E:
                    self.r_update(k, {k:v})

        for k in F:
            self.r_update(k, {k:F[k]})

    def r_update(self, key, other_dict):
        if isinstance(self[key], dict) and isinstance(other_dict[key], dict):
            od = RUDict(self[key])
            nd = other_dict[key]
            od.update(nd)
            self[key] = od
        else:
            self[key] = other_dict[key]

    def __repr__(self):
        """
        Returns the `RUDict` as indented json to better resemble how it looks in
        a .conf file.
        """
        import json # Tornado's json_encode doesn't do indentation
        return json.dumps(self, indent=4)

    def __str__(self):
        """
        Just returns `self.__repr__()` with an extra newline at the end.
        """
        return self.__repr__() + "\n"

# Utility functions (copied from utils.py so we don't have an import paradox)
def generate_session_id():
    """
    Returns a random, 45-character session ID.  Example:

    .. code-block:: python

        >>> generate_session_id()
        "NzY4YzFmNDdhMTM1NDg3Y2FkZmZkMWJmYjYzNjBjM2Y5O"
        >>>
    """
    import base64, uuid
    from tornado.escape import utf8
    session_id = base64.b64encode(
        utf8(uuid.uuid4().hex + uuid.uuid4().hex))[:45]
    if bytes != str: # Python 3
        return str(session_id, 'UTF-8')
    return session_id

def mkdir_p(path):
    """
    Pythonic version of "mkdir -p".  Example equivalents::

        >>> mkdir_p('/tmp/test/testing') # Does the same thing as...
        >>> from subprocess import call
        >>> call('mkdir -p /tmp/test/testing')

    .. note:: This doesn't actually call any external commands.
    """
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            pass
        else: raise

# Settings and options-related functions
# NOTE:  "options" refer to command line arguments (for the most part) while
# "settings" refers to the .conf files.  "commands" are CLI commmands specified
# via apps and plugins (for the most part).  e.g. termlog, install_license, etc
def print_help(commands):
    """
    Tornado's options.print_help() function with a few minor changes:

        * Help text is not hard wrapped (why did the Tornado devs do that? Ugh).
        * It includes information about Gate One 'commands'.
        * It only prints to stdout.
    """
    import textwrap, fcntl, termios, struct
    renditions = False
    try:
        import curses
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            try:
                curses.setupterm()
                if curses.tigetnum("colors") > 0:
                    renditions = True
            except Exception:
                renditions = False
    except ImportError:
        pass
    def bold(text):
        if renditions:
            return "\x1b[1m%s\x1b[0m" % text
        return text
    print("Usage: %s [OPTIONS]" % sys.argv[0])
    print(bold("\nOptions:\n"))
    rows, columns, hp, wp = struct.unpack('HHHH', fcntl.ioctl(
        0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))
    by_group = {}
    for option in options._options.values():
        by_group.setdefault(option.group_name, []).append(option)
    for filename, o in sorted(by_group.items()):
        if filename:
            print(bold("\n%s options:\n" % os.path.normpath(filename)))
        o.sort(key=lambda option: option.name)
        for option in o:
            prefix = option.name
            if option.metavar:
                prefix += "=" + option.metavar
            description = option.help or ""
            if option.default is not None and option.default != '':
                description += " (default %s)" % option.default
            lines = textwrap.wrap(description, columns - 35)
            if len(prefix) > 30 or len(lines) == 0:
                lines.insert(0, '')
            print("  --%-30s %s" % (prefix, lines[0]))
            for line in lines[1:]:
                print("%-34s %s" % (' ', line))
    print(bold("\nCommands:\n"))
    print("  Usage: %s <command> [OPTIONS]\n" % sys.argv[0])
    commands_description = _(
        "GateOne supports many different CLI 'commands' which can be used "
        "to invoke special functionality provided by plugins and applications "
        "(and application's plugins).  Each command can have it's own options "
        "and most will have a --help function of their own.")
    lines = textwrap.wrap(commands_description, columns)
    for line in lines:
        print("%s %s" % (' ', line))
    print("")
    for module, command_dict in commands.items():
        print(bold("Commands provided by '%s':\n" % module))
        for command, details in sorted(command_dict.items()):
            print("  %-32s %s" % (command, details['description']))
        print("")
    print(bold("Example command usage:\n"))
    print("  %s termlog --help" % sys.argv[0])
    print("") # The oh-so-important whitespace before the prompt
    sys.exit(1)

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
    address = "127.0.0.1"
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
            u'kill': False#new variable
})
    return settings
    
def settings_template(path, **kwargs):
    """
    Renders and returns the Tornado template at *path* using the given *kwargs*.

    .. note:: Any blank lines in the rendered template will be removed.
    """
    from tornado.template import Template
    with io.open(path, mode='r', encoding='utf-8') as f:
        template_data = f.read()
    t = Template(template_data)
    # NOTE: Tornado returns templates as bytes, not unicode.  That's why we need
    # the decode() below...
    rendered = t.generate(**kwargs).decode('utf-8')
    out = ""
    for line in rendered.splitlines():
        if line.strip():
            out += line + "\n"
    return out

def parse_commands(commands):
    """
    Given a list of *commands* (which can include arguments) such as::

        ['ls', '--color="always"', '-lh', 'ps', '--context', '-ef']

    Returns an `OrderedDict` like so::

        OrderedDict([
            ('ls', ['--color="always"', '-ltrh']),
            ('ps', ['--context', '-ef'])
        ])
    """
    try:
        from collections import OrderedDict
    except ImportError: # Python <2.7 didn't have OrderedDict in collections
        from ordereddict import OrderedDict
    out = OrderedDict()
    command = OrderedDict()
    for item in commands:
        if item.startswith('-') or ' ' in item:
            out[command].append(item)
        else:
            command = item
            out[command] = []
    return out

def generate_server_conf(installed=True):
    """
    Generates a fresh settings/10server.conf file using the arguments provided
    on the command line to override defaults.

    If *installed* is ``False`` the defaults will be set under the assumption
    that the user is non-root and running Gate One out of a download/cloned
    directory.
    """
    logger.info(_(
        u"Gate One settings are incomplete.  A new <settings_dir>/10server.conf"
        u" will be generated."))
    auth_settings = {} # Auth stuff goes in 20authentication.conf
    all_setttings = options_to_settings(options) # NOTE: options is global
    settings_path = options.settings_dir
    server_conf_path = os.path.join(settings_path, '10server.conf')
    if os.path.exists(server_conf_path):
        logger.error(_(
            "You have a 10server.conf but it is either invalid (syntax "
            "error) or missing essential settings."))
        sys.exit(1)
    config_defaults = all_setttings['*']['gateone']
    # Don't need this in the actual settings file:
    del config_defaults['settings_dir']
    non_options = [
        # These are things that don't really belong in settings
        'new_api_key', 'help', 'kill', 'config', 'version', 'combine_css',
        'combine_js', 'combine_css_container', 'configure'
    ]
    # Don't need non-options in there either:
    for non_option in non_options:
        if non_option in config_defaults:
            del config_defaults[non_option]
    # Generate a new cookie_secret
    config_defaults['cookie_secret'] = generate_session_id()
    # Separate out the authentication settings
    authentication_options = [
        # These are here only for logical separation in the .conf files
        'api_timestamp_window', 'auth', 'pam_realm', 'pam_service',
        'sso_keytab', 'sso_realm', 'sso_service', 'ssl_auth'
    ]
    # Provide some kerberos (sso) defaults
    auth_settings['sso_realm'] = "EXAMPLE.COM"
    auth_settings['sso_keytab'] = None # Allow /etc/krb5.conf to control it
    for key, value in list(config_defaults.items()):
        if key in authentication_options:
            auth_settings.update({key: value})
            del config_defaults[key]
        if key == 'origins':
            # As a convenience to the user, add any --port to the origins
            if config_defaults['port'] not in [80, 443]:
                for i, origin in enumerate(list(value)):
                    value[i] = "{origin}:{port}".format(
                        origin=origin, port=config_defaults['port'])
    # Make sure we have a valid log_file_prefix
    if config_defaults['log_file_prefix'] == None:
        web_log_dir = os.path.join(os.path.sep, "var", "log", "gateone")
        if installed:
            here = os.path.dirname(os.path.abspath(__file__))
            web_log_dir = os.path.normpath(
                os.path.join(here, '..', '..', 'logs'))
        web_log_path = os.path.join(web_log_dir, 'gateone.log')
        config_defaults['log_file_prefix'] = web_log_path
    else:
        web_log_dir = os.path.split(config_defaults['log_file_prefix'])[0]
    if not os.path.exists(web_log_dir):
        # Make sure the directory exists
        mkdir_p(web_log_dir)
    if not os.path.exists(config_defaults['log_file_prefix']):
        # Make sure the file is present
        io.open(
            config_defaults['log_file_prefix'],
            mode='w', encoding='utf-8').write(u'')
    auth_conf_path = os.path.join(settings_path, '20authentication.conf')
    template_path = resource_filename(
        'gateone', '/templates/settings/generic.conf')
    new_settings = settings_template(
        template_path, settings=config_defaults)
    with io.open(server_conf_path, mode='w') as s:
        s.write(u"// This is Gate One's main settings file.\n")
        s.write(new_settings)
    new_auth_settings = settings_template(
        template_path, settings=auth_settings)
    with io.open(auth_conf_path, mode='w') as s:
        s.write(u"// This is Gate One's authentication settings file.\n")
        s.write(new_auth_settings)

# NOTE: After Gate One 1.2 is officially released this function will be removed:
def convert_old_server_conf():
    """
    Converts old-style server.conf files to the new settings/10server.conf
    format.
    """
    settings = RUDict()
    auth_settings = RUDict()
    terminal_settings = RUDict()
    api_keys = RUDict({"*": {"gateone": {"api_keys": {}}}})
    terminal_options = [ # These are now terminal-app-specific setttings
        'command', 'dtach', 'session_logging', 'session_logs_max_age',
        'syslog_session_logging'
    ]
    authentication_options = [
        # These are here only for logical separation in the .conf files
        'api_timestamp_window', 'auth', 'pam_realm', 'pam_service',
        'sso_realm', 'sso_service', 'ssl_auth'
    ]
    with io.open(options.config) as f:
        # Regular server-wide settings will go in 10server.conf by default.
        # These settings can actually be spread out into any number of .conf
        # files in the settings directory using whatever naming convention
        # you want.
        settings_path = options.settings_dir
        server_conf_path = os.path.join(settings_path, '10server.conf')
        # Using 20authentication.conf for authentication settings
        auth_conf_path = os.path.join(
            settings_path, '20authentication.conf')
        terminal_conf_path = os.path.join(settings_path, '50terminal.conf')
        api_keys_conf = os.path.join(settings_path, '30api_keys.conf')
        # NOTE: Using a separate file for authentication stuff for no other
        #       reason than it seems like a good idea.  Don't want one
        #       gigantic config file for everything (by default, anyway).
        logger.info(_(
            "Old server.conf file found.  Converting to the new format as "
            "%s, %s, and %s" % (
                server_conf_path, auth_conf_path, terminal_conf_path)))
        for line in f:
            if line.startswith('#'):
                continue
            key = line.split('=', 1)[0].strip()
            value = eval(line.split('=', 1)[1].strip())
            if key in terminal_options:
                if key == 'command':
                    # Fix the path to ssh_connect.py if present
                    if 'ssh_connect.py' in value:
                        value = value.replace(
                            '/plugins/', '/applications/terminal/plugins/')
                if key == 'session_logs_max_age':
                    # This is now user_logs_max_age.  Put it in 'gateone'
                    settings.update({'user_logs_max_age': value})
                terminal_settings.update({key: value})
            elif key in authentication_options:
                auth_settings.update({key: value})
            elif key == 'origins':
                # Convert to the new format (a list with no http://)
                origins = value.split(';')
                converted_origins = []
                for origin in origins:
                    # The new format doesn't bother with http:// or https://
                    if origin == '*':
                        converted_origins.append(origin)
                        continue
                    origin = origin.split('://')[1]
                    if origin not in converted_origins:
                        converted_origins.append(origin)
                settings.update({key: converted_origins})
            elif key == 'api_keys':
                # Move these to the new location/format (30api_keys.conf)
                for pair in value.split(','):
                    api_key, secret = pair.split(':')
                    if bytes == str:
                        api_key = api_key.decode('UTF-8')
                        secret = secret.decode('UTF-8')
                    api_keys['*']['gateone']['api_keys'].update(
                        {api_key: secret})
                # API keys can be written right away
                with io.open(api_keys_conf, 'w') as conf:
                    msg = _(
                        u"// This file contains the key and secret pairs "
                        u"used by Gate One's API authentication method.\n")
                    conf.write(msg)
                    conf.write(unicode(api_keys))
            else:
                settings.update({key: value})
        template_path = resource_filename(
            'gateone', '/templates/settings/generic.conf')
        new_settings = settings_template(template_path, settings=settings)
        if not os.path.exists(server_conf_path):
            with io.open(server_conf_path, 'w') as s:
                s.write(_(u"// This is Gate One's main settings file.\n"))
                s.write(new_settings)
        new_auth_settings = settings_template(
            template_path, settings=auth_settings)
        if not os.path.exists(auth_conf_path):
            with io.open(auth_conf_path, 'w') as s:
                s.write(_(
                    u"// This is Gate One's authentication settings file.\n"))
                s.write(new_auth_settings)
        # Terminal uses a slightly different template; it converts 'command'
        # to the new 'commands' format.
        template_path = resource_filename(
            'gateone', '/templates/settings/50terminal.conf')
        new_term_settings = settings_template(
            template_path, settings=terminal_settings)
        if not os.path.exists(terminal_conf_path):
            with io.open(terminal_conf_path, 'w') as s:
                s.write(_(
                    u"// This is Gate One's Terminal application settings "
                    u"file.\n"))
                s.write(new_term_settings)
    # Rename the old server.conf so this logic doesn't happen again
    os.rename(options.config, "%s.old" % options.config)

def apply_cli_overrides(go_settings):
    """
    Updates *go_settings* in-place with values given on the command line.
    """
    # Figure out which options are being overridden on the command line
    arguments = []
    non_options = [
        # These are things that don't really belong in settings
        'new_api_key', 'help', 'kill', 'config', 'combine_js', 'combine_css',
        'combine_css_container', 'version', 'configure'
    ]
    for arg in list(sys.argv)[1:]:
        if not arg.startswith('-'):
            break
        else:
            arguments.append(arg.lstrip('-').split('=', 1)[0])
    go_settings['cli_overrides'] = arguments
    for argument in arguments:
        if argument in non_options:
            continue
        if argument in list(options):
            go_settings[argument] = options[argument]
    # Update Tornado's options from our settings.
    # NOTE: For options given on the command line this step should be redundant.
    for key, value in go_settings.items():
        if key in non_options:
            continue
        if key in list(options):
            if key in ('origins', 'api_keys'):
                # These two settings are special and taken care of elsewhere
                continue
            try:
                setattr(options, key, value)
            except Error:
                if isinstance(value, str):
                    if str == bytes: # Python 2
                        setattr(options, key, unicode(value))
                else:
                    setattr(options, key, str(value))

def remove_comments(json_like):
    """
    Removes C-style comments from *json_like* and returns the result.
    """
    def replacer(match):
        s = match.group(0)
        if s[0] == '/': return ""
        return s
    return comments_re.sub(replacer, json_like)

def remove_trailing_commas(json_like):
    """
    Removes trailing commas from *json_like* and returns the result.
    """
    return trailing_commas_re.sub("}", json_like)

def get_settings(path, add_default=True):
    """
    Reads any and all *.conf files containing JSON (JS-style comments are OK)
    inside *path* and returns them as an :class:`RUDict`.  Optionally, *path*
    may be a specific file (as opposed to just a directory).

    By default, all returned :class:`RUDict` objects will include a '*' dict
    which indicates "all users".  This behavior can be skipped by setting the
    *add_default* keyword argument to `False`.
    """
    settings = RUDict()
    if add_default:
        settings['*'] = {}
    # Using an RUDict so that subsequent .conf files can safely override
    # settings way down the chain without clobbering parent keys/dicts.
    if os.path.isdir(path):
        settings_files = [a for a in os.listdir(path) if a.endswith('.conf')]
        settings_files.sort()
    else:
        if not os.path.exists(path):
            raise IOError(_("%s does not exist" % path))
        settings_files = [path]
    for fname in settings_files:
        # Use this file to update settings
        if os.path.isdir(path):
            filepath = os.path.join(path, fname)
        else:
            filepath = path
        with io.open(filepath, encoding='utf-8') as f:
            # Remove comments
            almost_json = remove_comments(f.read())
            proper_json = remove_trailing_commas(almost_json)
            # Remove blank/empty lines
            proper_json = os.linesep.join([
                s for s in proper_json.splitlines() if s.strip()])
            try:
                settings.update(json_decode(proper_json))
            except ValueError as e:
                # Something was wrong with the JSON (syntax error, usually)
                logging.error(
                    "Error decoding JSON in settings file: %s"
                    % os.path.join(path, fname))
                logging.error(e)
                # Let's try to be as user-friendly as possible by pointing out
                # *precisely* where the error occurred (if possible)...
                try:
                    line_no = int(str(e).split(': line ', 1)[1].split()[0])
                    column = int(str(e).split(': line ', 1)[1].split()[2])
                    for i, line in enumerate(proper_json.splitlines()):
                        if i == line_no-1:
                            print(
                                line[:column] +
                                _(" <-- Something went wrong right here (or "
                                  "right above it)")
                            )
                            break
                        else:
                            print(line)
                    raise SettingsError()
                except (ValueError, IndexError):
                    print(_(
                        "Got an exception trying to display precisely where "
                        "the problem was.  This usually happens when you've "
                        "used single quotes (') instead of double quotes (\")."
                    ))
                    # Couldn't parse the exception message for line/column info
                    pass # No big deal; the user will figure it out eventually
    return settings

def options_to_settings(options):
    """
    Converts the given Tornado-style *options* to new-style settings.  Returns
    an :class:`RUDict` containing all the settings.
    """
    settings = RUDict({'*': {'gateone': {}, 'terminal': {}}})
    # In the new settings format some options have moved to the terminal app.
    # These settings are below and will be placed in the 'terminal' sub-dict.
    terminal_options = [
        'command', 'dtach', 'session_logging', 'session_logs_max_age',
        'syslog_session_logging'
    ]
    non_options = [
        # These are things that don't really belong in settings
        'new_api_key', 'help', 'kill', 'config', 'version', 'configure'
    ]
    for key, value in options.items():
        if key in terminal_options:
            settings['*']['terminal'].update({key: value})
        elif key in non_options:
            continue
        else:
            if key == 'origins':
                #if value == '*':
                    #continue
                # Convert to the new format (a list with no http://)
                origins = value.split(';')
                converted_origins = []
                for origin in origins:
                    if '://' in origin:
                        # The new format doesn't bother with http:// or https://
                        origin = origin.split('://')[1]
                        if origin not in converted_origins:
                            converted_origins.append(origin)
                    elif origin not in converted_origins:
                        converted_origins.append(origin)
                settings['*']['gateone'].update({key: converted_origins})
            elif key == 'api_keys':
                if not value:
                    continue
                # API keys/secrets are now a dict instead of a string
                settings['*']['gateone']['api_keys'] = {}
                for pair in value.split(','):
                    api_key, secret = pair.split(':', 1)
                    if bytes == str: # Python 2
                        api_key = api_key.decode('UTF-8')
                        secret = secret.decode('UTF-8')
                    settings['*']['gateone']['api_keys'].update(
                        {api_key: secret})
            else:
                settings['*']['gateone'].update({key: value})
    return settings

def combine_javascript(path, settings_dir=None):
    """
    Combines all application and plugin .js files into one big one; saved to the
    given *path*.  If given, *settings_dir* will be used to determine which
    applications and plugins should be included in the dump based on what is
    enabled.
    """
    # A couple partials to save some space/typing
    resource = lambda s: resource_string('gateone', s).decode('utf-8')
    resource_fn = lambda s: resource_filename('gateone', s)
    resource_dir = lambda s: resource_listdir('gateone', s)
    if not settings_dir:
        settings_dir = resource_filename('gateone', '/settings')
    all_settings = get_settings(settings_dir)
    enabled_plugins = []
    enabled_applications = []
    if 'gateone' in all_settings['*']:
        # The check above will fail in first-run situations
        enabled_plugins = all_settings['*']['gateone'].get(
            'enabled_plugins', [])
        enabled_applications = all_settings['*']['gateone'].get(
            'enabled_applications', [])
    plugins_dir = resource_fn('/plugins')
    pluginslist = resource_dir('/plugins')
    pluginslist.sort()
    applications_dir = resource_fn('/applications')
    appslist = resource_dir('/applications')
    appslist.sort()
    logger.info(_("Combining all Gate One JavaScript into a single file..."))
    with io.open(path, 'w') as f:
        # Start by adding Gate One's static JS files
        go_static_files = [
            a for a in resource_dir('/static') if a.endswith('.js')]
        # gateone.js must always come first
        go_first = [a for a in go_static_files if a.startswith('gateone')]
        go_first.sort()
        index = go_first.index('gateone.js')
        if index: # Nonzero index means it's not first
            go_first.insert(0, go_first.pop(index)) # Move it to the front
        if 'gateone.min.js' in go_first: # Don't want two copies of gateone.js
            go_first.remove('gateone.min.js')
        go_last = [a for a in go_static_files if not a.startswith('gateone')]
        go_static_files = go_first + go_last
        for filename in go_static_files:
            filepath = '/static/%s' % filename
            logger.info(_("Concatenating: %s") % filepath)
            f.write(resource(filepath) + u'\n')
        # Gate One plugins
        for plugin in pluginslist:
            if enabled_plugins and plugin not in enabled_plugins:
                continue
            plugin_static_path = '/plugins/%s/static' % plugin
            # NOTE: Using resource_filename() here so that it gets unpacked if
            # necessary:
            static_dir = resource_fn(plugin_static_path)
            if os.path.isdir(static_dir):
                filelist = resource_dir(plugin_static_path)
                filelist.sort()
                for filename in filelist:
                    filepath = os.path.join(plugin_static_path, filename)
                    if filename.endswith('.js'):
                        logger.info(_("Concatenating: %s") % filepath)
                        f.write(resource(filepath) + u'\n')
        # Gate One applications
        for application in appslist:
            if enabled_applications:
                # Only export JS of enabled apps
                if application not in enabled_applications:
                    continue
            app_static_path = '/applications/%s/static' % application
            static_dir = resource_fn(app_static_path)
            if os.path.isdir(static_dir):
                filelist = resource_dir(app_static_path)
                filelist.sort()
                for filename in filelist:
                    filepath = os.path.join(app_static_path, filename)
                    if filename.endswith('.js'):
                        logger.info(_("Concatenating: %s") % filepath)
                        f.write(resource(filepath) + u'\n')
            app_settings = all_settings['*'].get(application, None)
            enabled_app_plugins = []
            if app_settings:
                enabled_app_plugins = app_settings.get('enabled_plugins', [])
            app_plugins = '/applications/%s/plugins' % application
            plugins_dir = resource_filename('gateone', app_plugins)
            if os.path.isdir(plugins_dir):
                pluginslist = resource_dir(app_plugins)
                plugin_static_path = app_plugins + '/{plugin}/static'
                pluginslist.sort()
                # Gate One application plugins
                for plugin in pluginslist:
                    # Only export JS of enabled app plugins
                    if enabled_app_plugins:
                        if plugin not in enabled_app_plugins:
                            continue
                    static_path = plugin_static_path.format(plugin=plugin)
                    static_dir = resource_fn(static_path)
                    if os.path.isdir(static_dir):
                        filelist = resource_dir(static_path)
                        filelist.sort()
                        for filename in filelist:
                            filepath = os.path.join(static_path, filename)
                            if filename.endswith('.js'):
                                logger.info(_("Concatenating: %s") % filepath)
                                f.write(resource(filepath) + u'\n')
        f.flush()
    logger.info(_("JavaScript concatenation completed: %s") % path)
    logger.info(_(
        "Don't forget to set '\"send_js\": false' in your 10server.conf to "
        "disable sending of JavaScript"))

def combine_css(path, container, settings_dir=None):
    """
    Combines all application and plugin .css template files into one big one;
    saved to the given *path*.  Templates will be rendered using the given
    *container* as the replacement for templates use of '#{{container}}'.

    If given, *settings_dir* will be used to determine which applications and
    plugins should be included in the dump based on what is enabled.
    """
    # A couple partials to save some space/typing
    resource = lambda s: resource_string('gateone', s).decode('utf-8')
    resource_fn = lambda s: resource_filename('gateone', s)
    resource_dir = lambda s: resource_listdir('gateone', s)
    if container.startswith('#'): # This is just in case (don't want ##gateone)
        container = container.lstrip('#')
    if not settings_dir:
        settings_dir = resource_filename('gateone', '/settings')
    all_settings = get_settings(settings_dir)
    enabled_plugins = []
    enabled_applications = []
    embedded = False
    url_prefix = '/'
    if 'gateone' in all_settings['*']:
        # The check above will fail in first-run situations
        enabled_plugins = all_settings['*']['gateone'].get(
            'enabled_plugins', [])
        enabled_applications = all_settings['*']['gateone'].get(
            'enabled_applications', [])
        embedded = all_settings['*']['gateone'].get('embedded', False)
        url_prefix = all_settings['*']['gateone'].get('url_prefix', False)
    plugins_dir = resource_fn('/plugins')
    pluginslist = resource_dir('/plugins')
    pluginslist.sort()
    applications_dir = resource_fn('/applications')
    appslist = resource_dir('/applications')
    appslist.sort()
    logger.info(_("Combining all Gate One CSS into a single file..."))
    global_themes_dir = resource_fn('/templates/themes')
    themes = resource_dir('/templates/themes')
    theme_writers = {}
    for theme in themes:
        combined_theme_path = "%s_theme_%s" % (
            path.split('.css')[0], theme)
        theme_writers[theme] = io.open(combined_theme_path, 'w')
        theme_relpath = '/templates/themes/' + theme
        themepath = resource_fn(theme_relpath)
        logger.info(_("Concatenating: %s") % theme_relpath)
        theme_writers[theme].write(
            u"\n/* ------ theme_relpath: %s ------ */\n" % theme_relpath)
        theme_writers[theme].write(resource(theme_relpath))
    # NOTE: We skip gateone.css because that isn't used when embedding
    with io.open(path, 'w') as f:
        # Gate One plugins
        for plugin in pluginslist:
            if enabled_plugins and plugin not in enabled_plugins:
                continue
            plugin_theme_path = '/plugins/%s/templates/themes' % plugin
            plugin_css_path = '/plugins/%s/templates' % plugin
            # NOTE: Using resource_filename() here so that it gets unpacked if
            # necessary:
            theme_dir = resource_fn(plugin_theme_path)
            if os.path.isdir(theme_dir):
                filelist = resource_dir(plugin_theme_path)
                filelist.sort()
                for filename in filelist:
                    filepath = os.path.join(plugin_theme_path, filename)
                    if filename.endswith('.css'):
                        logger.info(_("Concatenating: %s") % filepath)
                        theme = os.path.split(filename)[1]
                        theme_writers[theme].write(
                            u"\n/* ------ filepath: %s ------ */\n" % filepath)
                        theme_writers[theme].write(resource(filepath) + u'\n')
            css_dir = resource_fn(plugin_css_path)
            if os.path.isdir(css_dir):
                filelist = resource_dir(css_dir)
                filelist.sort()
                for filename in filelist:
                    filepath = os.path.join(css_dir, filename)
                    if filename.endswith('.css'):
                        logger.info(_("Concatenating: %s") % filepath)
                        f.write(
                            u"\n/* ------ filepath: %s ------ */\n" % filepath)
                        f.write(resource(filepath) + u'\n')
        # Gate One applications
        for application in appslist:
            if enabled_applications:
                # Only export JS of enabled apps
                if application not in enabled_applications:
                    continue
            app_templates_path = '/applications/%s/templates' % application
            app_templates_dir = resource_fn(app_templates_path)
            if os.path.isdir(app_templates_dir):
                filelist = resource_dir(app_templates_path)
                filelist.sort()
                for filename in filelist:
                    filepath = os.path.join(app_templates_path, filename)
                    if filename.endswith('.css'):
                        logger.info(_("Concatenating: %s") % filepath)
                        f.write(
                            u"\n/* ------ filepath: %s ------ */\n" % filepath)
                        f.write(resource(filepath) + u'\n')
            app_themes_path = '/applications/%s/templates/themes' % application
            app_themes_dir = resource_fn(app_themes_path)
            if os.path.isdir(app_themes_dir):
                filelist = resource_dir(app_themes_path)
                filelist.sort()
                for filename in filelist:
                    filepath = os.path.join(app_themes_path, filename)
                    if filename.endswith('.css'):
                        logger.info(_("Concatenating: %s") % filepath)
                        theme = os.path.split(filename)[1]
                        theme_writers[theme].write(
                            u"\n/* ------ filepath: %s ------ */\n" % filepath)
                        theme_writers[theme].write(resource(filepath) + u'\n')
            app_settings = all_settings['*'].get(application, None)
            enabled_app_plugins = []
            if app_settings:
                enabled_app_plugins = app_settings.get('enabled_plugins', [])
            app_plugins = '/applications/%s/plugins' % application
            plugins_dir = resource_filename('gateone', app_plugins)
            if os.path.isdir(plugins_dir):
                # Gate One application plugins
                pluginslist = resource_dir(app_plugins)
                pluginslist.sort()
                plugin_templates_path = app_plugins + '/{plugin}/templates'
                plugin_themes_path = app_plugins + '/{plugin}/templates/themes'
                for plugin in pluginslist:
                    # Only export CSS of enabled app plugins
                    if enabled_app_plugins:
                        if plugin not in enabled_app_plugins:
                            continue
                    templates_path = plugin_templates_path.format(plugin=plugin)
                    templates_dir = resource_fn(templates_path)
                    if os.path.isdir(templates_dir):
                        filelist = resource_dir(templates_path)
                        filelist.sort()
                        for filename in filelist:
                            filepath = os.path.join(templates_path, filename)
                            if filename.endswith('.css'):
                                logger.info(_("Concatenating: %s") % filepath)
                                f.write(
                                    u"\n/* ------ filepath: %s ------ */\n"
                                    % filepath)
                                f.write(resource(filepath) + u'\n')
                    themes_path = plugin_themes_path.format(plugin=plugin)
                    themes_dir = resource_fn(themes_path)
                    if os.path.isdir(themes_dir):
                        filelist = resource_dir(themes_path)
                        filelist.sort()
                        for filename in filelist:
                            filepath = os.path.join(themes_path, filename)
                            if filename.endswith('.css'):
                                logger.info(_("Concatenating: %s") % filepath)
                                theme = os.path.split(filename)[1]
                                theme_writers[theme].write(
                                    u"\n/* ------ filepath: %s ------ */\n"
                                    % filepath)
                                theme_writers[theme].write(
                                    resource(filepath) + u'\n')
        f.flush()
    for writer in theme_writers.values():
        writer.flush()
        writer.close()
    # Now render the templates
    asis = lambda x: x # Used to disable autoescape
    import tornado.template
    loader = tornado.template.Loader(os.path.split(path)[0], autoescape="asis")
    template = loader.load(path)
    css_data = template.generate(
        asis=asis,
        container=container,
        url_prefix=url_prefix,
        embedded=embedded)
    css_data += "\n/* ------ path: %s ------ */\n" % path
    # Overwrite it with the rendered version
    with io.open(path, 'wb') as f:
        f.write(css_data)
    logger.info(_("Non-theme CSS has been combined and saved to: %s" % path))
    for theme in theme_writers.keys():
        combined_theme_path = "%s_theme_%s" % (
            path.split('.css')[0], theme)
        template = loader.load(combined_theme_path)
        css_data = (
            "\n/* ------ combined_theme_path: %s ------ */\n"
            % combined_theme_path)
        css_data += template.generate(
            asis=asis,
            container=container,
            url_prefix=url_prefix,
            embedded=embedded)
        new_css_data = '@charset "UTF-8";\n'
        for line in css_data.split('\n'):
            if '@charset' not in line:
                new_css_data += line + '\n'
        css_data = new_css_data
        with io.open(combined_theme_path, 'wb') as f:
            f.write(css_data)
        logger.info(_(
            "The %s theme CSS has been combined and saved to: %s")
            % (theme.split('.css')[0], combined_theme_path))
    logger.info(_(
        "Don't forget to set '\"send_css\": false' in your 10server.conf to "
        "disable sending of CSS"))
