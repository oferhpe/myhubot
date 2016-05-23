request = require('request');
require('request-debug')(request);
Properties = require('opsa-api-properties.coffee')

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

getRequestedHost = (res) ->
  res.match[1].replace(/^https?\:\/\//i, "");

module.exports = {
  getOpsaUri
  getSessionId
  generateJar
  createJar
  okToContinue
  requestp
  getRequestedHost
  ongoing
}
