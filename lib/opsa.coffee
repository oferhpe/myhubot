fs = require('fs');
utils = require('utils')
Properties = require('opsa-api-properties.coffee')
request = require('request')
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
getUrl = ->
  Properties.protocol + "://" + Properties.host + ":" + Properties.port + "/" + Properties.path
login = () ->
  opsaUri = getUrl();
  seqUrl = opsaUri + "/j_security_check"
  xsrfUrl = opsaUri + "/rest/getXSRFToken"
  loginForm =
    j_username: Properties.user
    j_password: Properties.password
  utils.requestp({url: opsaUri}).then ((res) ->
    jar4SecurityRequest = createJar(res, seqUrl, 1)
    utils.requestp({url: seqUrl, jar: jar4SecurityRequest, method: 'POST', form: loginForm}).then ((res) ->
      utils.requestp({url: opsaUri, jar: jar4SecurityRequest}).then ((apiSessionResponse) ->
        jSessionId = getSessionId(apiSessionResponse, 0)
        jar4XSRFRequest = createJar(apiSessionResponse, xsrfUrl)
        utils.requestp({url: xsrfUrl, jar: jar4XSRFRequest}).then((res) ->
          new Promise((resolve, reject) ->
            resolve {xsrfToken: res.body, jSessionId: jSessionId}
          ))
      )
    )
  ), (err) ->
    console.error '%s; %s', err.message, getOpsaUri()
    console.log '%j', err.res.statusCode
    return
module.exports = {
  login
  getUrl
  generateJar
}
