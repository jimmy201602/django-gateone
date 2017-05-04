# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render,HttpResponse

# Create your views here.
from django.views.generic import View
from django.shortcuts import render_to_response
import os

class index(View):
    def get(self,request):
        hostname = os.uname()[1]
        location = u'default'
        return render_to_response('index.html',locals())

class auth(View):
    def get(self,request):
        check = self.request.GET.get('check',None)
        if check:
            print check
        else:
            print 'not'
        if self.request.user.is_authenticated():
            print 'authenticated'
        else:
            print 'reauthenticated'
        response = HttpResponse(u'authenticated')
        response["Access-Control-Allow-Origin"] = "*"
        return response