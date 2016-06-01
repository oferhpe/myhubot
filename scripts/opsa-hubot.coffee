request = require('request')
Properties = require('opsa-api-properties.coffee')
require('request-debug')(request);
########################################################
#                   Opsa API                           #
########################################################
opsaLogin = () ->
  opsaUri = getOpsaUri();
  seqUrl = opsaUri + "/j_security_check"
  xsrfUrl = opsaUri + "/rest/getXSRFToken"
  loginForm =
    j_username: Properties.user
    j_password: Properties.password
  requestp({url: opsaUri}).then ((res) ->
    jar4SecurityRequest = createJar(res, seqUrl, 1)
    requestp({url: seqUrl, jar: jar4SecurityRequest, method: 'POST', form: loginForm}).then ((res) ->
      requestp({url: opsaUri, jar: jar4SecurityRequest}).then ((apiSessionResponse) ->
        jSessionId = getSessionId(apiSessionResponse, 0)
        jar4XSRFRequest = createJar(apiSessionResponse, xsrfUrl)
        requestp({url: xsrfUrl, jar: jar4XSRFRequest}).then((res) ->
          new Promise((resolve, reject) ->
            resolve {xsrfToken: res.body, jSessionId: jSessionId}
          ))
      )
    )
  ), (err) ->
    console.error '%s; %s', err.message, getOpsaUri()
    console.log '%j', err.res.statusCode
    return
########################################################
#                   Utils                              #
########################################################
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
getOpsaUri = ->
  Properties.protocol + "://" + Properties.host + ":" + Properties.port + "/" + Properties.path
getSessionId = (res, cookieIndex) ->
  cookie = res.headers["set-cookie"]
  if typeof cookie == 'undefined'
    return
  firstCookie = cookie[cookieIndex]
  jSessionId = firstCookie.split("=")[1].split(";")[0]
  return jSessionId
generateJar = (jSessionId, url) ->
  jar = request.jar()
  cookie = request.cookie('JSESSIONID=' + jSessionId)
  jar.setCookie cookie, url, (error, cookie) ->
  return jar
createJar = (res, url, cookieIndex) ->
  if !cookieIndex
    cookieIndex = 0
  jSessionId = getSessionId(res, cookieIndex)
  if typeof jSessionId == 'undefined'
    return
  jar = generateJar(jSessionId, url)
  return jar
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
      return
    attrsCount++
    return "• " + newAttr
  for childProp in resJson[attrGroup]
    for attr in childProp[attrCategory]
      if typeof attr == "string"
        attr = attr.replace(/&#x[0-9]+(.);/g, ',')
        if (!uniqueAttrs[attr])
          uniqueAttrs[attr] = 1
          attrs += getNewAttr(attr) + "\n>"
      else
        if attr[attrTypeFieldName].match(attrTypeRegex)
          attrVal = attr[attrValueField]
          attrVal = attrVal.replace(/&#x[0-9]+(.);/g, ',')
          if (!uniqueAttrs[attrVal])
            uniqueAttrs[attrVal] = 1
            attrs += getNewAttr(attrVal) + "\n>"
  attrs.replace(",", "")
  return attrs
getOneHourAgoTS = () ->
  ONE_HOUR = 60 * 60 * 1000;
  return now - ONE_HOUR
getLinkToHost = (hostName) ->
  encodedQuery = encodeURIComponent('host withkey "' + hostName)
  url = getOpsaUri() + '/#/logsearchpql?search=' + encodedQuery + '"&start=' + getOneHourAgoTS() + '&end=' + now + '&selectedTimeRange=ONE_HOUR'
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
  eol = "\n>";
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
    dynamicAttrsText += "*Events:* " + eol + eventsText + eol
  if logsText != ""
    dynamicAttrsText += "*Logs:* " + eol + logsText + eol
  if metricesText != ""
    dynamicAttrsText += "*Breached Metrices:* " + eol + metricesText
  return dynamicAttrsText

handleNoData = (anoms, userRes) ->
  if (anoms.length == 0)
    userRes.reply getNoDataText(userRes)
deepClone = (obj) ->
  JSON.parse(JSON.stringify(obj))
########################################################
#                  General  Variables                  #
########################################################
pleaseWaitMsg = 'Please wait...'
now = new Date().getTime()
hubotRouter = new RegistrationHandler()
########################################################
#                   Anomalies API                      #
########################################################
AnomAPI = (xsrfToken, jSessionId) ->
  if xsrfToken
    @xsrfToken = xsrfToken.slice 1, -1
  if jSessionId
    @jSessionId = jSessionId
  return
AnomAPI::constructor = AnomAPI
AnomAPI::requestPrimaryData = () ->
  oneHourAgo = getOneHourAgoTS()
  createAnomaliesApiUri = (startTime, endTime)->
    "/rest/getQueryResult?aqlQuery=%5Banomalies%5BattributeQuery(%7Bopsa_collection_anomalies%7D,+%7B%7D,+%7Bi.anomaly_id%7D)%5D()%5D+&endTime=" + endTime + "&granularity=0&pageIndex=1&paramsMap=%7B%22$drill_dest%22:%22AnomalyInstance%22,%22$drill_label%22:%22opsa_collection_anomalies_description%22,%22$drill_value%22:%22opsa_collection_anomalies_anomaly_id%22,%22$limit%22:%22500%22,%22$interval%22:300,%22$offset%22:0,%22$N%22:5,%22$pctile%22:10,%22$timeoffset%22:0,%22$starttimeoffset%22:0,%22$endtimeoffset%22:0,%22$timeout%22:0,%22$drill_type%22:%22%22,%22$problemtime%22:1463653196351,%22$aggregate_playback_flag%22:null%7D&queryType=generic&startTime=" + startTime + "&timeZoneOffset=-180&timeout=10&visualType=table"
  anomUrl = getOpsaUri() + createAnomaliesApiUri(oneHourAgo, now)
  @sJar = generateJar(@jSessionId, anomUrl)
  @sHeaders =
    'XSRFToken': @xsrfToken
  self = @
  requestp({url: anomUrl, jar: @sJar, method: 'POST', headers: @sHeaders})
AnomAPI::getMetricsDescUrl = (parsedInfo) ->
  now = new Date().getTime()
  endTime = parsedInfo.inactiveTime ? now
  metricsUri = "/rest/getQueryDescriptors?endTime=" + endTime + "&q=AnomalyInstance(" + parsedInfo.anomalyId + ")&startTime=" + parsedInfo.triggerTime
  return getOpsaUri() + metricsUri
AnomAPI::getMetricsUrl = (parsedInfo, descResponse) ->
  now = new Date().getTime()
  endTime = parsedInfo.inactiveTime ? now
  descArray = JSON.parse(descResponse.body).descriptors
  for desc of descArray
    if (descArray[desc].label.startsWith("Breaches for Anomaly"))
      return getOpsaUri() + "/rest/getQueryResult?aqlQuery=" + encodeURIComponent(descArray[desc].aql) + "&endTime=" + endTime + '&granularity=0&pageIndex=1&paramsMap={"$starttime":"' + new Date(parsedInfo.triggerTime) + '","$limit":"1000","$interval":7200,"$offset":0,"$N":5,"$pctile":10,"$timeoffset":0,"$starttimeoffset":0,"$endtimeoffset":0,"$timeout":0,"$drill_dest":"","$drill_label":"","$drill_value":"","$drill_type":"","$problemtime":' + parsedInfo.triggerTime + ',"$aggregate_playback_flag":null}&queryType=anomalyInstance&startTime=' + parsedInfo.triggerTime + '&timeZoneOffset=-180&timeout=10'
AnomAPI::parseRes = (res, requestedHost, requestedAnomalyType) ->
  body = res.body
  anomalies = new Array()
  collections = JSON.parse(body)
  extractInfoFromRawProps = (props, propName, propContainer)->
    propVal = propContainer.displayValue
    switch propName
      when "Active time"
        props.triggerTime = propVal
      when "Inactive time"
        props.inactiveTime = propVal
      when "Anomaly id"
        props.anomalyId = propVal
      when "Entity"
        props.rawEntity = propVal
        if (propContainer.drillPQL.startsWith("host"))
          props.anomalyType = "host"
        if (propContainer.drillPQL.startsWith("service"))
          props.anomalyType = "service"
    return props
  modifyPropText = (propName, propVal, extractedInfo)->
    switch propName
      when "Active time"
        propName = "Trigger Time"
        propVal = new Date(Number(propVal))
      when "Severity"
        str = ''
        jsonValue = JSON.parse(propVal)
        for val of jsonValue
          str += ',' + jsonValue[val]
        str = str.replace ',', ''
        propVal = str
      when "Entity"
        if (extractedInfo.anomalyType == "host")
          propVal = getLinkToHost(propVal);
    return {
      propName,
      propVal
    }
  toSkipProperty = (propName, extractedInfo) ->
    if propName in ["Inactive time", "First breach", "Breaches timestamps", "Rules"]
      return true
    if propName == "Entity" && extractedInfo.anomalyType == "service"
      return true
  okToDisplay = (display, origPropName, origPropVal, extractedInfo) ->
    display == false && origPropName == "Entity" && (origPropVal == requestedHost || requestedHost == "*") && ( requestedAnomalyType == extractedInfo.anomalyType)
  toSkipAnomaly = (propName, propVal) ->
    propName == "Status" && propVal != "active"
  extractSingleAnomalyData = (anomalyRawData) ->
    anomalyPropertiesAsText = ""
    ok2Display = false;
    anomAttr = {}
    anomAttr.anomalyPropertiesText = ""
    for colIdx of anomalyRawData
      origPropName = propNames[colIdx]
      origPropVal = anomalyRawData[colIdx].displayValue
      anomAttr = extractInfoFromRawProps(anomAttr, origPropName, anomalyRawData[colIdx])
      mProps = modifyPropText(origPropName, origPropVal, anomAttr)
      if toSkipAnomaly(mProps.propName, mProps.propVal)
        return null
      if okToDisplay(ok2Display, origPropName, origPropVal, anomAttr)
        ok2Display = true
      if toSkipProperty(mProps.propName, anomAttr)
        continue
      anomalyPropertiesAsText += "*" + mProps.propName + ":* " + mProps.propVal + "\n"
    if (!ok2Display)
      return null
    curHost = anomAttr.rawEntity
    anomAttr.text = "\n*Displaying anomalies for " + requestedAnomalyType + ":* " + curHost + "\n>>>" + anomalyPropertiesAsText
    return anomAttr
  extractAnomaliesFromTable = (table)->
    tableAnomalies = new Array()
    for columnIdx of table.columnNames
      propNames.push table.columnNames[columnIdx].columnTitle
    tableRows = table.tableDataWithDrill
    for rowIdx of tableRows
      row = tableRows[rowIdx]
      singleAnomaly = extractSingleAnomalyData(row)
      if (singleAnomaly)
        tableAnomalies.push(singleAnomaly)
    return tableAnomalies
  for collectionGroupId of collections
    collectionGroup = collections[collectionGroupId]
    for collectionId of collectionGroup
      collection = collectionGroup[collectionId].processedResult
      for tableIdx of collection
        table = collection[tableIdx]
        propNames = new Array()
        extractedAnoms = extractAnomaliesFromTable(table)
        anomalies = anomalies.concat(extractedAnoms)
  return anomalies
AnomAPI::requestMetrices = (anom) ->
  sJar = @sJar
  sHeaders = @sHeaders
  mDescUrl = AnomAPI::getMetricsDescUrl(anom)
  requestp({url: mDescUrl, jar: sJar, method: 'GET', headers: sHeaders}).then ((descRes) ->
    mUrl = AnomAPI::getMetricsUrl(anom, descRes)
    requestp({url: mUrl, jar: sJar, method: 'POST', headers: sHeaders})
  )
AnomAPI::parseAnoms = (userRes, anomRes) ->
  requestedHost = getRequestedHost(userRes)
  requestedAnomalyType = getRequestedAnomaliyType(userRes)
  @parseRes(anomRes, requestedHost, requestedAnomalyType)
########################################################
#                   Controllers                        #
########################################################
module.exports = (robot) ->
  invokeAnomaliesAPI = (userRes) ->
    userRes.reply pleaseWaitMsg
    opsaLogin().then ((res) ->
      anomAPI = new AnomAPI(res.xsrfToken, res.jSessionId)
      anomAPI.requestPrimaryData().then ((anomRes) ->
        anoms = anomAPI.parseAnoms(userRes, anomRes)
        handleNoData(anoms, userRes)
        for anom in anoms
          (((anom)->
            cAnom = deepClone(anom)
            return () ->
              anomAPI.requestMetrices(cAnom).then ((resultRes) ->
                cAnom.text += getDynamicAttrsText(resultRes)
                userRes.reply cAnom.text + "\n"
              ))(anom))()
      )
    )
  exp = /display anomalies for (host|service)\s*:\s*(.*)/i
  hubotRouter.register robot, exp, invokeAnomaliesAPI

