Utils = require('opsa-api-utils.coffee')
Properties = require('opsa-api-properties.coffee')

OpsaAPI = (xsrfToken, jSessionId) ->
  @xsrfToken = xsrfToken.slice 1, -1
  @jSessionId = jSessionId
  return
OpsaAPI::invoke = (callback)->
  @invoker(callback)
  return

OpsaAPI::login = (userRes, loginCallback) ->
  if !Utils.okToContinue()
    return
  opsaUri = Utils.getOpsaUri();
  seqUrl = opsaUri + "/j_security_check"
  xsrfUrl = opsaUri + "/rest/getXSRFToken"
  loginForm =
    j_username: Properties.user
    j_password: Properties.password

  invokeAPI = (res, apiSessionResponse) ->
    xsrfToken = res.body
    sessionId = Utils.getSessionId(apiSessionResponse, 0)
    #eee
    loginCallback(xsrfToken, sessionId)

  Utils.requestp(opsaUri).then ((res) ->
    jar4SecurityRequest = Utils.createJar(res, seqUrl, 1)
    Utils.requestp(seqUrl, jar4SecurityRequest, 'POST', {}, loginForm).then ((res) ->
      Utils.requestp(opsaUri, jar4SecurityRequest).then ((apiSessionResponse) ->
        jar4XSRFRequest = Utils.createJar(apiSessionResponse, xsrfUrl)
        Utils.requestp(xsrfUrl, jar4XSRFRequest).then ((res) ->
          invokeAPI res, apiSessionResponse
        )
      )
    )
    return
  ), (err) ->
    Utils.ongoing = false
    console.error '%s; %s', err.message, Utils.getOpsaUri()
    console.log '%j', err.res.statusCode
    return
  userRes.reply 'Please wait...'


module.exports = {
  OpsaAPI: OpsaAPI
}

