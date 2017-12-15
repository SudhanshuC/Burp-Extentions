# setup Imports
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IScannerCheck
from burp import IScanIssue
from burp import IScannerListener
from burp import IMessageEditorTab

import struct
import sys
import _google_ipaddr_r234

import re

from burp import ITab
from java.awt import FlowLayout
from java.awt import Panel

import csv
import os

import os.path


from shutil import copyfile

path=os.getcwd()
path=path+"/vulnDB.csv"

print "Suggester Suggests...\n\n"

with open('Suggester_Report.csv','wb') as opfile:
    writer = csv.writer(opfile, delimiter=',')
    data = ['*--URL--*', '*--PARAMETER--*', '*--SUGGESTED VULNERABILITY TO TEST--*', '*--SEVERITY--*', '*--REFERENCE LINKS--*']
    writer.writerow(data)
    opfile.close()

def vulncheck(requrl, param_name):
#    print "Checking Parameter"
    with open(path, 'rb') as csvfile:
      vulns=csv.reader(csvfile)
      skip=next(vulns)
      for vuln in vulns:
        pattern = re.compile(vuln[0])
        match = re.search(pattern, param_name.lower())
        if match:
            print "Matched********"
            print "URL:"
            print requrl
            print "Parameter:"+param_name
            print "Vuln Details:"
            print vuln
            print "\n"
            vulndata = [requrl, param_name, vuln[1], vuln[2], vuln[3], '\n']
            check=0
            domain=str(requrl).split("//")[-1].split("/")[0]
            reppath="Suggester_Report"+"-"+domain+".csv"
            if not os.path.isfile(reppath):
                copyfile("Suggester_Report.csv",reppath)
            with open(reppath,'rb') as inpfile:
                reader=csv.reader(inpfile)
                for read in reader:
                    if (str(read[0]) == str(requrl) and str(read[1]) == str(param_name)):
                        check = 1
                if check == 0:
                    with open(reppath,'ab') as oupfile:
                        writer = csv.writer(oupfile, delimiter=',')
                        writer.writerow(vulndata)

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, IScannerListener, IScanIssue, ITab, IMessageEditorTab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Suggester")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.setProxyInterceptionEnabled(False)

        ############################
        # add the custom tab and button to Burp's UI
        self._newpanel = Panel()
        self._newpanel.setLayout(FlowLayout())
        callbacks.customizeUiComponent(self._newpanel)
        callbacks.addSuiteTab(self)

        return


    ### IScannerCheck ###
    def doPassiveScan(self, baseRequestResponse):
#        print "\n"
        analyzedResponse = self.helpers.analyzeResponse(baseRequestResponse.getResponse()) # Returns IResponseInfo
        analyzedRequest = self.helpers.analyzeRequest(baseRequestResponse)
        urlList = analyzedRequest.getUrl()
        paramList = analyzedRequest.getParameters()
        contenttypeList = analyzedRequest.getContentType()

        issues = []

    #    print "\nURL:"
    #    print urlList

        if self._callbacks.isInScope(urlList):
            for param in paramList:
                vulnparam=param.getName()
                vulncheck(urlList, vulnparam)


    #    print "\nCT:"
    #    print contenttypeList

    #    print "-----------------------------------------------"
        return


    def getTabCaption(self):
      '''Name of our tab'''
      return "Suggester"

    def getUiComponent(self):
      '''return our panel'''
      return self._newpanel
