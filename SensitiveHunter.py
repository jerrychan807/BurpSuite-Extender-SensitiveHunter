#!/usr/local/bin/python
# -*- coding:utf-8 -*-
# @Time    : 3/18/2020 11:15 AM
# @Author  : Jerry
# @Desc    : 
# @File    : SensitiveHunter.py

import re

from burp import IBurpExtender
from burp import IProxyListener
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory


class BurpExtender(IBurpExtender, IProxyListener, IMessageEditorTabFactory):
    # implement IBurpExtender
    #
    # register extender callbacks
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sensitive Information Hunter")
        callbacks.registerProxyListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        print 'SHunter by [Jerry]\nBlog: https://jerrychan807.github.io/'
        return

    def createNewInstance(self, controller, editable):
        # implement createNewInstance
        self.SHunterTab = SHunterTab(self, controller, editable)
        return self.SHunterTab

    def processProxyMessage(self, messageIsRequest, messageInfo):
        '''
         在代理时,处理数据包
        :param messageIsRequest: 区分数据包是请求还是回复
        :param messageInfo: is a IHttpRequestResponse object
        :return:
        '''
        # only process response
        if not messageIsRequest:
            messageInfo = messageInfo.getMessageInfo()
            content = messageInfo.getResponse()

            r = self._helpers.analyzeResponse(content)

            headers = content[:r.getBodyOffset()].tostring()

            msg = content[r.getBodyOffset():].tostring()

            if stringIsKey(msg):
                messageInfo.setHighlight('green')

            if stringIsPhone(msg):
                messageInfo.setHighlight('pink')

            if stringIsIdCard(msg):
                messageInfo.setHighlight('pink')

            if stringIsAssets(msg):
                messageInfo.setHighlight('pink')

            if stringIsMy(msg):
                messageInfo.setHighlight('green')


class SHunterTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):

        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return

    def getTabCaption(self):
        return "SHunter"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):  # only show tab in response
        if isRequest:
            return False
        else:
            return True

    def setMessage(self, content, isRequest):
        if content:
            pretty_msg = ''
            phone = stringIsPhone(content)
            idcard = stringIsIdCard(content)
            assets = stringIsAssets(content)
            keys = stringIsKey(content)
            my_keyword = stringIsMy(content)

            if phone:
                pretty_msg += "Find phone:" + phone + '\n'
            if idcard:
                pretty_msg += "Find idcard:" + idcard + '\n'
            if assets:
                pretty_msg += "Find IP Address:" + assets + '\n'
            if keys:
                pretty_msg += "Find Keys:" + keys + '\n'
            if my_keyword:
                pretty_msg += "Find my_keyword:" + my_keyword + '\n'

            self._txtInput.setText(pretty_msg)
        return


def stringIsGps(string):  # check GPS information
    if ("\"longitude\"" in string and "\"latitude\"" in string) or ("\"lat\"" in string and "\"lon\"" in string):
        locations = re.findall(r'\d{2,3}\.\d{3,6}', string)
        for location in locations:
            if 3 < float(location) < 135:
                return location
    return False


def stringIsKey(string):
    # 匹配token或者密码泄露
    key_list = re.findall(
        r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id'
        r'|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email'
        r'|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|apikey|userid|user_id|user-id|appsecret)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
        string, re.M | re.I)
    # TODO:自己添加相关的关键字
    if key_list:
        keys = ','.join(list(set(key_list)))
        return keys
    return False


def stringIsPhone(string):
    iphones = re.findall(
        r'[%"\'< ](?:13[012]\d{8}[%"\'< ]|15[56]\d{8}[%"\'< ]|18[56]\d{8}[%"\'< ]|176\d{8}[%"\'< ]|145\d{8}[%"\'< ]|13[456789]\d{8}[%"\'< ]|147\d{8}[%"\'< ]|178\d{8}[%"\'< ]|15[012789]\d{8}[%"\'< ]|18[23478]\d{8}[%"\'< ]|133\d{8}[%"\'< ]|153\d{8}[%"\'< ]|189\d{8}[%"\'< ])',
        string)
    if iphones:
        iphones = set(iphones)
        iphoneSet = set()
        for i in iphones:
            iphoneSet.add(filter(str.isdigit, i))
        iphones = ','.join(iphoneSet)
        return iphones
    return False


def stringIsMy(string):
    # 个人自定义的关键词
    my_keywords = re.findall(
        r'sourceMappingURL', string)
    if my_keywords:
        my_keywords = set(my_keywords)
        my_keywordSet = set()
        for i in my_keywords:
            my_keywordSet.add(i)
        my_keywords = ','.join(my_keywordSet)
        return my_keywords
    return False


def stringIsAssets(string):
    # TODO:区分内网ip
    assets = re.findall(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', string)
    if assets:
        assetss = set(assets)
        assetsSet = set()
        for i in assets:
            assetsSet.add(i)
        assetss = ','.join(assetsSet)
        return assetss
    return False


def stringIsIdCard(string):
    coefficient = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    parityBit = '10X98765432'
    idcards = re.findall(r'([1-8][1-7]\d{4}[1|2]\d{3}[0|1]\d{1}[1-3]\d{4}[0-9|X|x])', string)
    idcardSet = set()
    if idcards != []:
        for idcard in idcards:
            sumnumber = 0
            for i in range(17):
                sumnumber += int(idcard[i]) * coefficient[i]
            if parityBit[sumnumber % 11] == idcard[-1]:
                idcardSet.add(idcard)
        idcards = ','.join(idcardSet)
        return idcards
    return False
