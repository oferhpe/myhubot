Opsa = require('opsa-general-api.coffee')
Utils = require('opsa-api-utils.coffee')
AnomaliesAPI = (xsrfToken, jSessionId) ->
  OpsaAPI.call this, xsrfToken, jSessionId
  return
OpsaAPI = Opsa.OpsaAPI
AnomaliesAPI.prototype = Object.create(OpsaAPI.prototype)
AnomaliesAPI::constructor = AnomaliesAPI
AnomaliesAPI::invoker = (callback) ->
  ONE_HOUR = 60 * 60 * 1000;
  now = new Date().getTime()
  oneHourAgo = now - ONE_HOUR
  createAnomaliesApiUri = (startTime, endTime)->
    "/rest/getQueryResult?aqlQuery=%5Banomalies%5BattributeQuery(%7Bopsa_collection_anomalies%7D,+%7B%7D,+%7Bi.anomaly_id%7D)%5D()%5D+&endTime=" + endTime + "&granularity=0&pageIndex=1&paramsMap=%7B%22$drill_dest%22:%22AnomalyInstance%22,%22$drill_label%22:%22opsa_collection_anomalies_description%22,%22$drill_value%22:%22opsa_collection_anomalies_anomaly_id%22,%22$limit%22:%22500%22,%22$interval%22:300,%22$offset%22:0,%22$N%22:5,%22$pctile%22:10,%22$timeoffset%22:0,%22$starttimeoffset%22:0,%22$endtimeoffset%22:0,%22$timeout%22:0,%22$drill_type%22:%22%22,%22$problemtime%22:1463653196351,%22$aggregate_playback_flag%22:null%7D&queryType=generic&startTime=" + startTime + "&timeZoneOffset=-180&timeout=10&visualType=table"
  anomUrl = Utils.getOpsaUri() + createAnomaliesApiUri(oneHourAgo, now)
  anomJar = Utils.generateJar(@jSessionId, anomUrl)
  anomHeaders =
    'XSRFToken': @xsrfToken
  Utils.requestp(anomUrl, anomJar, 'POST', anomHeaders).then ((anomResponse) ->
    callback(anomResponse.body)
  )
  return


module.exports = {
  AnomaliesAPI,
#  parseOpsaAnomaliesData
}

