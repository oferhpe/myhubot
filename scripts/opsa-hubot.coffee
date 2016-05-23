Utils = require('opsa-api-utils.coffee')
request = require('request')
Anomalies = require('opsa-anomalies-api.coffee')
Opsa = require('opsa-general-api.coffee')

require('request-debug')(request);

module.exports = (robot) ->
  robot.respond /display anomalies for host:?:\s*(.*)/i, (res) ->
    loginCallback = (xsrfToken, sessionId) ->
      anomaliesAPI = new Anomalies.AnomaliesAPI(xsrfToken, sessionId)
      apiCallback = (body) ->
        requestedHost = Utils.getRequestedHost(res)
        replyText = Anomalies.parseOpsaAnomaliesData(body, requestedHost)
        res.reply replyText
        Utils.ongoing = false
        return
      anomaliesAPI.invoke apiCallback
    Opsa.OpsaAPI::login(res, loginCallback)

