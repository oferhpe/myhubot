Utils = require('opsa-api-utils.coffee')
request = require('request')
Anomalies = require('opsa-anomalies-api.coffee')
Opsa = require('opsa-general-api.coffee')

require('request-debug')(request);
parseOpsaAnomaliesData = (body, requestedHost) ->
  colNames = new Array()
  collections = JSON.parse(body)
  output = ""
  modifyOutput = ->
    colName = colNames[colIdx]
    colValue = row[colIdx].displayValue
    switch colName
      when "Inactive time", "First breach","Breaches timestamps","Rules"
        retVal = null
      when "Active time"
        retVal = {
          colValue: new Date(colValue * 1000)
          colName: "Trigger Time"
        }
      when "Severity"
        str = ''
        jsonValue = JSON.parse(colValue)
        for val of jsonValue
          str += ',' + jsonValue[val]
        str = str.replace ',', ''
        colValue = str
        retVal = {
          colName,
          colValue
        }
      else
        retVal = {
          colName,
          colValue
        }
    return retVal
  for collectionId of collections
    for resultObjectIdx of collections[collectionId]
      obj = collections[collectionId]
      for tableIdx of obj[resultObjectIdx].processedResult
        table = obj[resultObjectIdx].processedResult[tableIdx]
        for columnIdx of table.columnNames
          colNames.push table.columnNames[columnIdx].columnTitle
        for rowIdx of table.tableDataWithDrill
          row = table.tableDataWithDrill[rowIdx]
          rowStr = ""
          display = false;
          displayed = 0
          for colIdx of row
            __ret = modifyOutput()
            if (!__ret)
              continue
            colName = __ret.colName
            colValue = __ret.colValue
            if display == false && colName == "Entity" && (colValue == requestedHost || requestedHost == "*")
              display = true
              displayed++
            rowStr += "*" + colName + ":* " + colValue + "\n"
          if (display)
            output += rowStr
  if displayed == 0
    replyText = 'No data found for host: ' + requestedHost + "\n"
  else
    replyText = 'Displaying Anomalies For Host: ' + requestedHost + "\n" + output
  return replyText
module.exports = (robot) ->
  robot.respond /display anomalies for host:?:\s*(.*)/i, (res) ->
    loginCallback = (xsrfToken, sessionId) ->
      anomaliesAPI = new Anomalies.AnomaliesAPI(xsrfToken, sessionId)
      apiCallback = (body) ->
        requestedHost = Utils.getRequestedHost(res)
        replyText = parseOpsaAnomaliesData(body, requestedHost)
        res.reply replyText
        Utils.ongoing = false
        return
      anomaliesAPI.invoke apiCallback
    Opsa.OpsaAPI::login(res, loginCallback)

