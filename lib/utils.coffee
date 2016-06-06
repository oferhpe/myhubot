fs = require('fs');
request = require('request')
require('request-debug')(request);
opsa = require('opsa')
requestp = (params) ->
  url = params.url
  headers = params.headers or {}
  method = params.method or 'GET'
  jar = params.jar or {}
  form = params.form or {}
  progressCallback = @progressCallback or () ->
  new Promise((resolve, reject) ->
    reqData = {
      uri: url
      headers: headers
      method: method
    }
    if jar
      reqData.jar = jar
    if form
      reqData.form = form
    request reqData, (err, res, body) ->
      progressCallback(err, res, body)
      if err
        return reject(err)
      else if res.statusCode == 200 || res.statusCode == 302 || res.statusCode == 400
        resolve res, body
      else
        err = new Error('Unexpected status code: ' + res.statusCode)
        err.res = res
        return reject(err)
      resolve res, body
      return
    return
  )
getRequestedHost = (res) ->
  res.match[2].replace(/^https?\:\/\//i, "").replace("//", "");
getRequestedAnomaliyType = (res) ->
  res.match[1]
collectAttrs = (resJson, attrGroup, attrCategory, attrTypeFieldName, attrTypeRegex, attrValueField) ->
  attrs = ""
  attrsCount = 0
  uniqueAttrs = {}
  getNewAttr = (labelText)->
    newAttr = labelText.replaceAll(",,", "")
    if(newAttr.lastIndexOf(",") == newAttr.length - 1)
      newAttr = newAttr.substring(0, newAttr.length - 1)
    if (newAttr == "")
      return ""
    attrsCount++
    return "\n>• " + newAttr
  for childProp in resJson[attrGroup]
    for attr in childProp[attrCategory]
      if typeof attr == "string"
        attr = attr.replace(/&#x[0-9]+(.);/g, ',')
        if (!uniqueAttrs[attr])
          uniqueAttrs[attr] = 1
          attrs += getNewAttr(attr)
      else
        if attr[attrTypeFieldName].match(attrTypeRegex)
          attrVal = attr[attrValueField]
          attrVal = attrVal.replace(/&#x[0-9]+(.);/g, ',')
          if (!uniqueAttrs[attrVal])
            uniqueAttrs[attrVal] = 1
            attrs += getNewAttr(attrVal)
  attrs.replace(",", "")
  return attrs
getOneHourAgoTS = () ->
  ONE_HOUR = 60 * 60 * 1000;
  return now - ONE_HOUR
getLinkToHost = (hostName) ->
  encodedQuery = encodeURIComponent('host withkey "' + hostName)
  opsa = require('opsa')
  url = opsa.getUrl() + '/#/logsearchpql?search=' + encodedQuery + '"&start=' + getOneHourAgoTS() + '&end=' + now + '&selectedTimeRange=ONE_HOUR'
  return url
progressCallback = ()->
RegistrationHandler = ()->
  @registeredListeners = {}
  @register = (robot, exp, callback) ->
    if (@registeredListeners[exp])
      return
    else
      @registeredListeners[exp] = 1
    robot.respond exp, callback
  return
getNoDataText = (userRes) ->
  'No data found for host: ' + getRequestedHost(userRes) + "\n"
getDynamicAttrsText = (resultResponse) ->
  resJson = JSON.parse(resultResponse.body)
  dynamicAttrsText = ""
  metricesText = ""
  eventsText = ""
  logsText = ""
  eol = "\n";
  for attrGroup of resJson
    switch attrGroup
      when "anomaly_result"
        continue
      when "opsa_collection_message"
        eventsText += collectAttrs(resJson, attrGroup, "processedResult", "breachType", /^event/, "drillLabel")
        logsText += collectAttrs(resJson, attrGroup, "processedResult", "breachType", /log/gi, "drillLabel")
      else
        metricesText += collectAttrs(resJson, attrGroup, "metricLabels")
  if eventsText != ""
    dynamicAttrsText += "*Events:* " + eventsText + eol
  if logsText != ""
    dynamicAttrsText += "*Logs:* " + logsText + eol
  if metricesText != ""
    dynamicAttrsText += "*Breached Metrices:* " + metricesText + eol
  return dynamicAttrsText
handleNoData = (anoms, userRes) ->
  if (anoms.length == 0)
    userRes.reply getNoDataText(userRes)
deepClone = (obj) ->
  JSON.parse(JSON.stringify(obj))
now = new Date().getTime()
module.exports = {
  requestp,
  getRequestedHost,
  getRequestedAnomaliyType,
  getOneHourAgoTS,
  getLinkToHost,
  RegistrationHandler,
  getDynamicAttrsText,
  handleNoData,
  deepClone,
  now
}
