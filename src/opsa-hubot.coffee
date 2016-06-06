request = require('request')
require('request-debug')(request);
opsa = require('opsa')
utils = require('utils')
pleaseWaitMsg = 'Please wait...'
hubotRouter = new utils.RegistrationHandler()
AnomAPI = require("AnomAPI")

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

