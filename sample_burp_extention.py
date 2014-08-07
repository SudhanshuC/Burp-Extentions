#! /usr/bin/python
# A sample burp extention in python (needs jython) which extracts hostname from the request (Target Tab).
from burp import IBurpExtender
from burp import IMenuItemHandler
import re
import urllib2
class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self.mCallBacks = callbacks
        self.mCallBacks.registerMenuItem("SSL Scan", ArgsDiffMenuItem())

class ArgsDiffMenuItem(IMenuItemHandler):
    def menuItemClicked(self, menuItemCaption, messageInfo):
        print "--- Hostname Extract ---"
        
        if messageInfo:
            # We can do a diff
            request1=HttpRequest(messageInfo[0].getRequest())
            req=request1.request
            host=req[1]    
            print host
            print "DONE"
class HttpRequest:
    def __init__(self, request):
        self.request=request.tostring().splitlines()
