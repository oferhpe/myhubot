request = require('request')
require('request-debug')(request);

########################################################
#                   Opsa API                           #
########################################################
opsa = require('opsa')
########################################################
#                   Utils                              #
########################################################
utils = require('utils')

########################################################
#                  General  Variables                  #
########################################################
pleaseWaitMsg = 'Please wait...'
hubotRouter = new utils.RegistrationHandler()
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
  oneHourAgo = utils.getOneHourAgoTS()
  createAnomaliesApiUri = (startTime, endTime)->
    "/rest/getQueryResult?aqlQuery=%5Banomalies%5BattributeQuery(%7Bopsa_collection_anomalies%7D,+%7B%7D,+%7Bi.anomaly_id%7D)%5D()%5D+&endTime=" + endTime + "&granularity=0&pageIndex=1&paramsMap=%7B%22$drill_dest%22:%22AnomalyInstance%22,%22$drill_label%22:%22opsa_collection_anomalies_description%22,%22$drill_value%22:%22opsa_collection_anomalies_anomaly_id%22,%22$limit%22:%22500%22,%22$interval%22:300,%22$offset%22:0,%22$N%22:5,%22$pctile%22:10,%22$timeoffset%22:0,%22$starttimeoffset%22:0,%22$endtimeoffset%22:0,%22$timeout%22:0,%22$drill_type%22:%22%22,%22$problemtime%22:1463653196351,%22$aggregate_playback_flag%22:null%7D&queryType=generic&startTime=" + startTime + "&timeZoneOffset=-180&timeout=10&visualType=table"
  anomUrl = opsa.getUrl() + createAnomaliesApiUri(oneHourAgo, utils.now)
  @sJar = opsa.generateJar(@jSessionId, anomUrl)
  @sHeaders =
    'XSRFToken': @xsrfToken
  self = @
  utils.requestp({url: anomUrl, jar: @sJar, method: 'POST', headers: @sHeaders})
AnomAPI::getMetricsDescUrl = (parsedInfo) ->
  now = new Date().getTime()
  endTime = parsedInfo.inactiveTime ? now
  metricsUri = "/rest/getQueryDescriptors?endTime=" + endTime + "&q=AnomalyInstance(" + parsedInfo.anomalyId + ")&startTime=" + parsedInfo.triggerTime
  return opsa.getUrl() + metricsUri
AnomAPI::getMetricsUrl = (parsedInfo, descResponse) ->
  now = new Date().getTime()
  endTime = parsedInfo.inactiveTime ? now
  descArray = JSON.parse(descResponse.body).descriptors
  for desc of descArray
    if (descArray[desc].label.startsWith("Breaches for Anomaly"))
      return opsa.getUrl() + "/rest/getQueryResult?aqlQuery=" + encodeURIComponent(descArray[desc].aql) + "&endTime=" + endTime + '&granularity=0&pageIndex=1&paramsMap={"$starttime":"' + new Date(parsedInfo.triggerTime) + '","$limit":"1000","$interval":7200,"$offset":0,"$N":5,"$pctile":10,"$timeoffset":0,"$starttimeoffset":0,"$endtimeoffset":0,"$timeout":0,"$drill_dest":"","$drill_label":"","$drill_value":"","$drill_type":"","$problemtime":' + parsedInfo.triggerTime + ',"$aggregate_playback_flag":null}&queryType=anomalyInstance&startTime=' + parsedInfo.triggerTime + '&timeZoneOffset=-180&timeout=10'
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
        jsonValue = JSON.parse(propVal)
        idx = Object.keys(jsonValue).length
        propVal = jsonValue[Object.keys(jsonValue)[idx - 1]]
      when "Entity"
        if (extractedInfo.anomalyType == "host")
          propVal = utils.getLinkToHost(propVal);
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
  utils.requestp({url: mDescUrl, jar: sJar, method: 'GET', headers: sHeaders}).then ((descRes) ->
    mUrl = AnomAPI::getMetricsUrl(anom, descRes)
    utils.requestp({url: mUrl, jar: sJar, method: 'POST', headers: sHeaders})
  )
AnomAPI::parseAnoms = (userRes, anomRes) ->
  requestedHost = utils.getRequestedHost(userRes)
  requestedAnomalyType = utils.getRequestedAnomaliyType(userRes)
  @parseRes(anomRes, requestedHost, requestedAnomalyType)
########################################################
#                   Controllers                        #
########################################################
module.exports = (robot) ->
  invokeAnomaliesAPI = (userRes) ->
    userRes.reply pleaseWaitMsg
    opsa.login().then ((res) ->
      anomAPI = new AnomAPI(res.xsrfToken, res.jSessionId)
      anomAPI.requestPrimaryData().then ((anomRes) ->
        anoms = anomAPI.parseAnoms(userRes, anomRes)
        utils.handleNoData(anoms, userRes)
        for anom in anoms
          (((anom)->
            cAnom = utils.deepClone(anom)
            return () ->
              anomAPI.requestMetrices(cAnom).then ((resultRes) ->
                cAnom.text += utils.getDynamicAttrsText(resultRes)
                userRes.reply cAnom.text + "\n"
              ))(anom))()
      )
    )
  exp = /display anomalies for (host|service)\s*:\s*(.*)/i
  hubotRouter.register robot, exp, invokeAnomaliesAPI

