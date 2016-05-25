request = require('request')
Properties = require('opsa-api-properties.coffee')
require('request-debug')(request);
########################################################
#                   Opsa API                      #
########################################################
OpsaAPI = (xsrfToken, jSessionId) ->
  if xsrfToken
    @xsrfToken = xsrfToken.slice 1, -1
  if jSessionId
    @jSessionId = jSessionId
  return
OpsaAPI::login = (userRes, loginCallback) ->
  if !okToContinue()
    return new Promise((resolve, reject) ->)
  userRes.reply 'Please wait...'
  opsaUri = getOpsaUri();
  seqUrl = opsaUri + "/j_security_check"
  xsrfUrl = opsaUri + "/rest/getXSRFToken"
  loginForm =
    j_username: Properties.user
    j_password: Properties.password
  @sessionData = {}
  localSessionData = @sessionData
  requestp(opsaUri).then ((res) ->
    jar4SecurityRequest = createJar(res, seqUrl, 1)
    requestp(seqUrl, jar4SecurityRequest, 'POST', {}, loginForm).then ((res) ->
      requestp(opsaUri, jar4SecurityRequest).then ((apiSessionResponse) ->
        localSessionData.sessionId = getSessionId(apiSessionResponse, 0)
        jar4XSRFRequest = createJar(apiSessionResponse, xsrfUrl)
        requestp(xsrfUrl, jar4XSRFRequest)
      )
    )
  ), (err) ->
    ongoing = false
    console.error '%s; %s', err.message, getOpsaUri()
    console.log '%j', err.res.statusCode
    return
requestp = (url, jar, method, headers, form) ->
  headers = headers or {}
  method = method or 'GET'
  jar = jar or {}
  form = form or {}
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
      if err
        return reject(err)
      else if res.statusCode == 200 || res.statusCode == 302 || res.statusCode == 400
        resolve res, body
      else
        ongoing = false
        err = new Error('Unexpected status code: ' + res.statusCode)
        err.res = res
        return reject(err)
      resolve res, body
      return
    return
  )
########################################################
#                   Utils                              #
########################################################
getOpsaUri = ->
  Properties.protocol + "://" + Properties.host + ":" + Properties.port + "/" + Properties.path
getSessionId = (res, cookieIndex) ->
  cookie = res.headers["set-cookie"]
  if typeof cookie == 'undefined'
    return
  firstCookie = cookie[cookieIndex]
  jSessionId = firstCookie.split("=")[1].split(";")[0]
generateJar = (jSessionId, url) ->
  jar = request.jar()
  cookie = request.cookie('JSESSIONID=' + jSessionId)
  console.log "setting cookie: " + cookie
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
lastTime = Date.now()
ongoing = false
okToContinue = ->
  secondsSinceLastTime = (Date.now() - lastTime) / 1000
  if secondsSinceLastTime < 10 && ongoing
    return false
  else
    lastTime = Date.now();
    ongoing = true
    return true
getRequestedHost = (res) ->
  res.match[1].replace(/^https?\:\/\//i, "");
########################################################
#                   Anomalies API                      #
########################################################
AnomaliesAPI = (xsrfToken, jSessionId) ->
  OpsaAPI.call this, xsrfToken, jSessionId
  return
OpsaAPI = OpsaAPI
AnomaliesAPI.prototype = Object.create(OpsaAPI.prototype)
AnomaliesAPI::constructor = AnomaliesAPI
AnomaliesAPI::invoke = () ->
  ONE_HOUR = 60 * 60 * 1000;
  now = new Date().getTime()
  oneHourAgo = now - ONE_HOUR
  createAnomaliesApiUri = (startTime, endTime)->
    "/rest/getQueryResult?aqlQuery=%5Banomalies%5BattributeQuery(%7Bopsa_collection_anomalies%7D,+%7B%7D,+%7Bi.anomaly_id%7D)%5D()%5D+&endTime=" + endTime + "&granularity=0&pageIndex=1&paramsMap=%7B%22$drill_dest%22:%22AnomalyInstance%22,%22$drill_label%22:%22opsa_collection_anomalies_description%22,%22$drill_value%22:%22opsa_collection_anomalies_anomaly_id%22,%22$limit%22:%22500%22,%22$interval%22:300,%22$offset%22:0,%22$N%22:5,%22$pctile%22:10,%22$timeoffset%22:0,%22$starttimeoffset%22:0,%22$endtimeoffset%22:0,%22$timeout%22:0,%22$drill_type%22:%22%22,%22$problemtime%22:1463653196351,%22$aggregate_playback_flag%22:null%7D&queryType=generic&startTime=" + startTime + "&timeZoneOffset=-180&timeout=10&visualType=table"
  anomUrl = getOpsaUri() + createAnomaliesApiUri(oneHourAgo, now)
  @sessionJar = generateJar(@jSessionId, anomUrl)
  @sessionHeaders =
    'XSRFToken': @xsrfToken
  requestp(anomUrl, @sessionJar, 'POST', @sessionHeaders)
getMetricsDescriptorsUrl = (parsedInfo) ->
  now = new Date().getTime()
  endTime = parsedInfo.inactiveTime ? now
  metricsUri = "/rest/getQueryDescriptors?endTime=" + endTime + "&q=AnomalyInstance(" + parsedInfo.anomalyId + ")&startTime=" + parsedInfo.triggerTime
  return getOpsaUri() + metricsUri
getMetricsResultsUrl = (parsedInfo, descResponse) ->
  now = new Date().getTime()
  endTime = parsedInfo.inactiveTime ? now
  descArray = JSON.parse(descResponse.body).descriptors
  for desc of descArray
    if (descArray[desc].label.startsWith("Breaches for Anomaly"))
      return getOpsaUri() + "/rest/getQueryResult?aqlQuery=" + encodeURIComponent(descArray[desc].aql) + "&endTime=" + endTime + '&granularity=0&pageIndex=1&paramsMap={"$starttime":"' + new Date(parsedInfo.triggerTime) + '","$limit":"1000","$interval":7200,"$offset":0,"$N":5,"$pctile":10,"$timeoffset":0,"$starttimeoffset":0,"$endtimeoffset":0,"$timeout":0,"$drill_dest":"","$drill_label":"","$drill_value":"","$drill_type":"","$problemtime":' + parsedInfo.triggerTime + ',"$aggregate_playback_flag":null}&queryType=anomalyInstance&startTime=' + parsedInfo.triggerTime + '&timeZoneOffset=-180&timeout=10'
extractAnomalies = (body, requestedHost) ->
  anomalies = new Array()
  collections = JSON.parse(body)
  extractInfoFromProps = (props, propName, propVal)->
    switch propName
      when "Active time"
        props.triggerTime = propVal
      when "Inactive time"
        props.inactiveTime = propVal
      when "Anomaly id"
        props.anomalyId = propVal
    return props
  modifyOutput = (propName, propVal)->
    switch propName
      when "Status"
        if propVal == "Inactive"
          return null
      when "Inactive time", "First breach","Breaches timestamps","Rules"
        return null
      when "Active time"
        propName = "Trigger Time"
        propVal = new Date(propVal)
      when "Severity"
        str = ''
        jsonValue = JSON.parse(propVal)
        for val of jsonValue
          str += ',' + jsonValue[val]
        str = str.replace ',', ''
        propVal = str
    return {
      propName,
      propVal
    }
  extractSingleAnomalyData = (anomalyRawData) ->
    anomalyPropertiesAsText = ""
    display = false;
    extractedInfo = {}
    extractedInfo.anomalyPropertiesText = ""
    for colIdx of anomalyRawData
      propName = propNames[colIdx]
      propVal = anomalyRawData[colIdx].displayValue
      extractedInfo = extractInfoFromProps(extractedInfo, propName, propVal)
      modifiedProps = modifyOutput(propName, propVal)
      if (!modifiedProps)
        continue
      propName = modifiedProps.propName
      propVal = modifiedProps.propVal
      if propName == "Status" && propVal != "active"
        return null
      if display == false && propName == "Entity" && (propVal == requestedHost || requestedHost == "*")
        display = true
        hostName = propVal
      anomalyPropertiesAsText += "*" + propName + ":* " + propVal + "\n"
    if (!display)
      return null
    extractedInfo.anomalyPropsText = "\n*Anomalies for host: *`" + hostName + "`\n" + anomalyPropertiesAsText
    return extractedInfo
  for collectionGroupId of collections
    collectionGroup = collections[collectionGroupId]
    for collectionId of collectionGroup
      collection = collectionGroup[collectionId].processedResult
      for tableIdx of collection
        table = collection[tableIdx]
        propNames = new Array()
        for columnIdx of table.columnNames
          propNames.push table.columnNames[columnIdx].columnTitle
        tableRows = table.tableDataWithDrill
        for rowIdx of tableRows
          row = tableRows[rowIdx]
          singleAnomaly = extractSingleAnomalyData(row)
          if (singleAnomaly)
            anomalies.push(singleAnomaly)
  return anomalies
########################################################
#                   Controllers                        #
########################################################


module.exports = (robot) ->
  robot.respond /display anomalies for host:?:\s*(.*)/i, (userRes) ->
    opsaAPI = new OpsaAPI()
    opsaAPI.login(userRes).then ((res) ->
      anomaliesAPI = new AnomaliesAPI(res.body, opsaAPI.sessionData.sessionId)
      anomaliesAPI.invoke().then ((anomResponse) ->
        body = anomResponse.body
        requestedHost = getRequestedHost(userRes)
        extractedAnomalies = extractAnomalies(body, requestedHost)
        if (extractedAnomalies.length == 0)
          return userRes.reply 'No data found for host: ' + requestedHost + "\n"
        for anomalyData in extractedAnomalies
          requestp(getMetricsDescriptorsUrl(anomalyData), anomaliesAPI.sessionJar, 'GET', anomaliesAPI.sessionHeaders).then ((descResponse) ->
            metricResultsHeaders = anomaliesAPI.sessionHeaders
            requestp(getMetricsResultsUrl(anomalyData, descResponse), anomaliesAPI.sessionJar, 'POST', metricResultsHeaders).then ((resultResponse) ->
              ongoing = false
            )
          )
        #          parsedInfo.metrics = getAnomaliesMetrics(parsedInfo, getMetricsCallback)
        return
      )
    )

