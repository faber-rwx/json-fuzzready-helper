# Burp Repeater Extension - JSON FuzzReady Helper
# Author: Francesco Oddo

import json
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IContextMenuFactory

result_json = None

# Python generator which recursively parses each JSON element 
# and converts int/boolean types to tamperable string fields. 
# It supports complex hierarchies with multiple nested lists/dicts.
# Based on: https://stackoverflow.com/questions/21028979/recursive-iteration-through-nested-json-for-specific-key-in-python  
def json_field_generator_tamperable(json_input):
    if isinstance(json_input, dict):
      for k in json_input:
          if isinstance(json_input[k], int) or isinstance(json_input[k], unicode):
            json_input[k] = str(json_input[k]).encode("utf-8")
            yield json_input[k]
          elif json_input[k] is None:
          	json_input[k] = str("null").encode("utf-8")
          	yield json_input[k]
          else:
            for child_val in json_field_generator_tamperable(json_input[k]):
              yield child_val
    elif isinstance(json_input, list):
      for item in json_input:
        for item_val in json_field_generator_tamperable(item):
          yield item_val

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    callbacks.setExtensionName('JSON FuzzReady Helper')
    callbacks.registerMessageEditorTabFactory(self)

  def createNewInstance(self, controller, editable): 
    return JSONFuzzreadyHelperTab(self, controller, editable)

class JSONFuzzreadyHelperTab(IMessageEditorTab):
  def __init__(self, extender, controller, editable):
    self._extender = extender
    self._helpers = extender._helpers
    self._editable = editable
    self._txtInput = extender._callbacks.createTextEditor()
    self._txtInput.setEditable(editable)
    return

  def getTabCaption(self):
    return "JSON FuzzReady Helper"

  def getUiComponent(self):
    return self._txtInput.getComponent()

  def isEnabled(self, content, isRequest):
    if isRequest:
      r = self._helpers.analyzeRequest(content)
      body = content[r.getBodyOffset():].tostring()
      if len(body) > 0:
        if body[0] == '{' or body[0] == '[':
          return True
      else:
    	  return False
    else:
      return False

  def setMessage(self, content, isRequest):
    global result_json
    if content is None:
      self._txtInput.setText(None)
      self._txtInput.setEditable(False)
    else:
      r = self._helpers.analyzeRequest(content)

      json_body = content[r.getBodyOffset():].tostring()

      result_json = json.loads(json_body)
      for field in json_field_generator_tamperable(result_json):
        pass

      tamper_json = json.dumps(result_json, indent=4)
      self._txtInput.setText(tamper_json)
      self._txtInput.setEditable(self._editable)

      self._currentMessage = content

    return

  def getMessage(self): 
    if self._txtInput.isTextModified():
      try:
        tamper_json = self._txtInput.getText().tostring()
        data = tamper_json
      except:
        data = self._helpers.bytesToString(self._txtInput.getText())

      r = self._helpers.analyzeRequest(self._currentMessage)
      return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
    else:
      return self._currentMessage

  def isModified(self):
    return self._txtInput.isTextModified()

  def getSelectedData(self):
    return self._txtInput.getSelectedText()