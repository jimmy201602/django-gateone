# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render,HttpResponse,Http404

# Create your views here.
from django.views.generic import View
from django.shortcuts import render_to_response,HttpResponseRedirect,reverse,redirect
import os
import ast
from django.conf import settings
from applications.utils import generate_session_id,mkdir_p
import tornado
from django.core import signing #encrypted the strings
from django.contrib.auth.views import login,logout
import io
import datetime
import hashlib

def getsettings(name,default=None):
    return getattr(settings, name, default)

class basehttphander(View):
    def user_login(self,request):
        self.request.session.clear_expired()
        if self.request.META.has_key('HTTP_X_FORWARDED_FOR'):  
            ip = self.request.META['HTTP_X_FORWARDED_FOR']
        else:  
            ip = self.request.META['REMOTE_ADDR']
        user = {u'upn': str(self.request.user), u'ip_address': ip}        
        user_dir = os.path.join(getsettings('BASE_DIR'),'users')
        user_dir = os.path.join(user_dir, user['upn'])
        if not os.path.exists(user_dir):
            mkdir_p(user_dir)
            os.chmod(user_dir, 0o700)
        if not self.request.session.get('session',None):
            session_info = {
                'session': generate_session_id()
            }
            session_info.update(user)
            self.request.session['session'] = session_info['session']
            self.request.session['gateone_user'] = session_info    
    def user_logout(self, request, redirect=None):
        if not redirect:
            # Try getting it from the query string
            redirect = self.request.GET.get("redirect", None)
        if redirect:
            return HttpResponse(redirect)
        else:
            return HttpResponse(getsettings('url_prefix','/'))
            
class index(basehttphander):
    def get(self,request):
        hostname = os.uname()[1]
        location = u'default'
        self.user_login(request)
        response = render_to_response('index.html',locals())
        response["Access-Control-Allow-Origin"] = "*"#set django to cros mode
        expiration = getsettings('auth_timeout', 14*86400) #set django user login session time to 14 day
        if not self.request.COOKIES.get('gateone_user',None):
            response.set_cookie("gateone_user",signing.dumps(self.request.session['gateone_user']))
            self.request.session.set_expiry(expiration)
        return response

class auth(basehttphander):
    """
    Only implemented django user login.
    """
    def get(self,request):
        check = self.request.GET.get('check',False)
        if check in ['true','false',False]:#solve ast malformed string exception
            check = {'true':True,'false':False}[str(check).lower()]
        else:
            check = ast.literal_eval(check)
        if self.request.user == 'AnonymousUser':
            user = {'upn': 'ANONYMOUS'}
        else:
            user = {'upn': str(self.request.user)}
        if check and self.request.user.is_authenticated():
            response = HttpResponse(u'authenticated')
            response["Access-Control-Allow-Origin"] = "*"
            response["Server"] = "GateOne"
            return response
        logout_get = self.request.GET.get("logout", None)
        if logout_get:
            logout(request)
            response = HttpResponse('/')
            response.delete_cookie('gateone_user')            
            self.user_logout(request)
            return response
        next_url = self.request.GET.get("next", None)
        if next_url:
            return redirect(next_url)
        return redirect(getsettings('url_prefix','/'))

class DownloadHandler(basehttphander):
    def get(self, request, path, include_body=True):
        session_dir = getsettings('session_dir',os.path.join(getsettings('BASE_DIR'),'sessions'))#default session dir
        user = self.request.session.get('gateone_user')
        if user and 'session' in self.request.session.get('gateone_user'):
            session = user['session']
        else:
            return HttpResponse('User session is not valid')
        filepath = os.path.join(session_dir, session, 'downloads', path)
        abspath = os.path.abspath(filepath)
        if not os.path.exists(abspath):
            return HttpResponse(self.get_error_html(404),status=404)
        if not os.path.isfile(abspath):
            return HttpResponse("%s is not a file" %(path), status=403)
        import stat, mimetypes
        stat_result = os.stat(abspath)
        modified = datetime.datetime.fromtimestamp(stat_result[stat.ST_MTIME])
        response = HttpResponse()
        response["Last-Modified"] = modified
        mime_type, encoding = mimetypes.guess_type(abspath)
        if mime_type:
            response["Content-Type"] = mime_type
        # Set the Cache-Control header to private since this file is not meant
        # to be public.
        response["Cache-Control"] = "private"
        # Add some additional headers
        response['Access-Control-Allow-Origin'] = '*'
        # Check the If-Modified-Since, and don't send the result if the
        # content has not been modified
        ims_value = self.request.META.get('If-Modified-Since',None)
        if ims_value is not None:
            import email.utils
            date_tuple = email.utils.parsedate(ims_value)
            if_since = datetime.datetime.fromtimestamp(time.mktime(date_tuple))
            if if_since >= modified:
                response.status = 304
                return response
        # Finally, deliver the file
        with io.open(abspath, "rb") as file:
            data = file.read()
            hasher = hashlib.sha1()
            hasher.update(data)
            response["Etag"] = '"%s"' % hasher.hexdigest()
            if include_body:
                response.content = data
                response.status = 200
                return response
            else:
                assert self.request.method in ("HEAD","head")
                response["Content-Length"] = len(data)

    def get_error_html(self, status_code, **kwargs):
        if status_code in [404, 500, 503, 403]:
            filename = os.path.join(os.path.join(getsettings('BASE_DIR'),'templates'), '%d.html' % status_code)
            if os.path.exists(filename):
                with io.open(filename, 'r') as f:
                    data = f.read()
                return data
        import httplib
        return "<html><title>%(code)d: %(message)s</title>" \
                "<body class='bodyErrorPage'>%(code)d: %(message)s</body></html>" % {
            "code": status_code,
            "message": httplib.responses[status_code],
        }

class SharedTermHandler(basehttphander):
    """
    Renders shared.html which allows an anonymous user to view a shared
    terminal.
    """
    def get(self, request, share_id=None):
        hostname = os.uname()[1]
        prefs = self.request.GET.get("prefs", None)
        url_prefix = getsettings('url_prefix','/')
        gateone_js = "%sstatic/gateone.js" % url_prefix
        minified_js_abspath = os.path.join(getsettings('BASE_DIR'),'static/gateone.min.js')
        # Use the minified version if it exists
        if os.path.exists(minified_js_abspath):
            gateone_js = "%sgateone.min.js" % getsettings('STATIC_URL')
        return render_to_response('share.html',locals())