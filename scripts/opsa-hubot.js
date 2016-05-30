// Generated by CoffeeScript 1.10.0
(function () {
  var AnomAPI, Properties, RegistrationHandler, createJar, deepClone, generateJar, getLabels, getLinkToHost, getMetricesText, getNoDataText, getOneHourAgoTS, getOpsaUri, getRequestedAnomaliyType, getRequestedHost, getSessionId, handleNoData, hubotRouter, now, opsaLogin, pleaseWaitMsg, progressCallback, request, requestp;

  request = require('request');

  Properties = require('opsa-api-properties.coffee');

  require('request-debug')(request);
  opsaLogin = function () {
    var loginForm, opsaUri, seqUrl, xsrfUrl;
    opsaUri = getOpsaUri();
    seqUrl = opsaUri + "/j_security_check";
    xsrfUrl = opsaUri + "/rest/getXSRFToken";
    loginForm = {
      j_username: Properties.user,
      j_password: Properties.password
    };
    return requestp({
      url: opsaUri
    }).then((function (res) {
      var jar4SecurityRequest;
      jar4SecurityRequest = createJar(res, seqUrl, 1);
      return requestp({
        url: seqUrl,
        jar: jar4SecurityRequest,
        method: 'POST',
        form: loginForm
      }).then((function (res) {
        return requestp({
          url: opsaUri,
          jar: jar4SecurityRequest
        }).then((function (apiSessionResponse) {
          var jSessionId, jar4XSRFRequest;
          jSessionId = getSessionId(apiSessionResponse, 0);
          jar4XSRFRequest = createJar(apiSessionResponse, xsrfUrl);
          return requestp({
            url: xsrfUrl,
            jar: jar4XSRFRequest
          }).then(function (res) {
            return new Promise(function (resolve, reject) {
              return resolve({
                xsrfToken: res.body,
                jSessionId: jSessionId
              });
            });
          });
        }));
      }));
    }), function (err) {
      console.error('%s; %s', err.message, getOpsaUri());
      console.log('%j', err.res.statusCode);
    });
  };
  requestp = function (params) {
    var form, headers, jar, method, progressCallback, url;
    url = params.url;
    headers = params.headers || {};
    method = params.method || 'GET';
    jar = params.jar || {};
    form = params.form || {};
    progressCallback = this.progressCallback || function () {
        };
    return new Promise(function (resolve, reject) {
      var reqData;
      reqData = {
        uri: url,
        headers: headers,
        method: method
      };
      if (jar) {
        reqData.jar = jar;
      }
      if (form) {
        reqData.form = form;
      }
      request(reqData, function (err, res, body) {
        progressCallback(err, res, body);
        if (err) {
          return reject(err);
        } else if (res.statusCode === 200 || res.statusCode === 302 || res.statusCode === 400) {
          resolve(res, body);
        } else {
          err = new Error('Unexpected status code: ' + res.statusCode);
          err.res = res;
          return reject(err);
        }
        resolve(res, body);
      });
    });
  };
  getOpsaUri = function () {
    return Properties.protocol + "://" + Properties.host + ":" + Properties.port + "/" + Properties.path;
  };
  getSessionId = function (res, cookieIndex) {
    var cookie, firstCookie, jSessionId;
    cookie = res.headers["set-cookie"];
    if (typeof cookie === 'undefined') {
      return;
    }
    firstCookie = cookie[cookieIndex];
    return jSessionId = firstCookie.split("=")[1].split(";")[0];
  };
  generateJar = function (jSessionId, url) {
    var cookie, jar;
    jar = request.jar();
    cookie = request.cookie('JSESSIONID=' + jSessionId);
    console.log("setting cookie: " + cookie);
    jar.setCookie(cookie, url, function (error, cookie) {
    });
    return jar;
  };
  createJar = function (res, url, cookieIndex) {
    var jSessionId, jar;
    if (!cookieIndex) {
      cookieIndex = 0;
    }
    jSessionId = getSessionId(res, cookieIndex);
    if (typeof jSessionId === 'undefined') {
      return;
    }
    jar = generateJar(jSessionId, url);
    return jar;
  };
  getRequestedHost = function (res) {
    return res.match[2].replace(/^https?\:\/\//i, "").replace("//", "");
  };
  getRequestedAnomaliyType = function (res) {
    return res.match[1];
  };
  getLabels = function (resultResponse) {
    var childProp, getNewLabel, i, j, labelCount, labelText, labels, len, len1, prop, ref, resJson, uniqueLabels, val;
    resJson = JSON.parse(resultResponse.body);
    labels = "";
    labelCount = 0;
    uniqueLabels = {};
    getNewLabel = function (labelText) {
      var newLabel;
      newLabel = labelText.replaceAll(",,", "");
      if (newLabel.lastIndexOf(",") === newLabel.length - 1) {
        newLabel = newLabel.substring(0, newLabel.length - 1);
      }
      return newLabel;
    };
    for (prop in resJson) {
      val = resJson[prop];
      if (prop !== "anomaly_result") {
        for (i = 0, len = val.length; i < len; i++) {
          childProp = val[i];
          labelCount++;
          ref = childProp.metricLabels;
          for (j = 0, len1 = ref.length; j < len1; j++) {
            labelText = ref[j];
            labelText = labelText.replace(/&#x[0-9]+(.);/g, ',');
            if (!uniqueLabels[labelText]) {
              uniqueLabels[labelText] = 1;
              labels += getNewLabel(labelText) + "\n>";
            }
          }
        }
      }
    }
    labels.replace(",", "");
    if (labelCount > 1) {
      labels = "\n>" + labels;
    }
    return labels;
  };
  getOneHourAgoTS = function () {
    var ONE_HOUR;
    ONE_HOUR = 60 * 60 * 1000;
    return now - ONE_HOUR;
  };
  getLinkToHost = function (hostName) {
    var encodedQuery, url;
    encodedQuery = encodeURIComponent('host withkey "' + hostName);
    url = getOpsaUri() + '/#/logsearchpql?search=' + encodedQuery + '"&start=' + getOneHourAgoTS() + '&end=' + now + '&selectedTimeRange=ONE_HOUR';
    return url;
  };
  progressCallback = function () {
  };
  RegistrationHandler = function () {
    this.registeredListeners = {};
    this.register = function (robot, exp, callback) {
      if (this.registeredListeners[exp]) {
        return;
      } else {
        this.registeredListeners[exp] = 1;
      }
      return robot.respond(exp, callback);
    };
  };
  getNoDataText = function (userRes) {
    return 'No data found for host: ' + getRequestedHost(userRes) + "\n";
  };
  getMetricesText = function (resultRes) {
    return "*Breached Metrics:* " + getLabels(resultRes);
  };
  handleNoData = function (anoms, userRes) {
    if (anoms.length === 0) {
      return userRes.reply(getNoDataText(userRes));
    }
  };
  deepClone = function (obj) {
    return JSON.parse(JSON.stringify(obj));
  };

  pleaseWaitMsg = 'Please wait...';

  now = new Date().getTime();

  hubotRouter = new RegistrationHandler();
  AnomAPI = function (xsrfToken, jSessionId) {
    if (xsrfToken) {
      this.xsrfToken = xsrfToken.slice(1, -1);
    }
    if (jSessionId) {
      this.jSessionId = jSessionId;
    }
  };

  AnomAPI.prototype.constructor = AnomAPI;
  AnomAPI.prototype.requestPrimaryData = function () {
    var anomUrl, createAnomaliesApiUri, oneHourAgo, self;
    oneHourAgo = getOneHourAgoTS();
    createAnomaliesApiUri = function (startTime, endTime) {
      return "/rest/getQueryResult?aqlQuery=%5Banomalies%5BattributeQuery(%7Bopsa_collection_anomalies%7D,+%7B%7D,+%7Bi.anomaly_id%7D)%5D()%5D+&endTime=" + endTime + "&granularity=0&pageIndex=1&paramsMap=%7B%22$drill_dest%22:%22AnomalyInstance%22,%22$drill_label%22:%22opsa_collection_anomalies_description%22,%22$drill_value%22:%22opsa_collection_anomalies_anomaly_id%22,%22$limit%22:%22500%22,%22$interval%22:300,%22$offset%22:0,%22$N%22:5,%22$pctile%22:10,%22$timeoffset%22:0,%22$starttimeoffset%22:0,%22$endtimeoffset%22:0,%22$timeout%22:0,%22$drill_type%22:%22%22,%22$problemtime%22:1463653196351,%22$aggregate_playback_flag%22:null%7D&queryType=generic&startTime=" + startTime + "&timeZoneOffset=-180&timeout=10&visualType=table";
    };
    anomUrl = getOpsaUri() + createAnomaliesApiUri(oneHourAgo, now);
    this.sJar = generateJar(this.jSessionId, anomUrl);
    this.sHeaders = {
      'XSRFToken': this.xsrfToken
    };
    self = this;
    return requestp({
      url: anomUrl,
      jar: this.sJar,
      method: 'POST',
      headers: this.sHeaders
    });
  };
  AnomAPI.prototype.getMetricsDescUrl = function (parsedInfo) {
    var endTime, metricsUri, ref;
    now = new Date().getTime();
    endTime = (ref = parsedInfo.inactiveTime) != null ? ref : now;
    metricsUri = "/rest/getQueryDescriptors?endTime=" + endTime + "&q=AnomalyInstance(" + parsedInfo.anomalyId + ")&startTime=" + parsedInfo.triggerTime;
    return getOpsaUri() + metricsUri;
  };
  AnomAPI.prototype.getMetricsUrl = function (parsedInfo, descResponse) {
    var desc, descArray, endTime, ref;
    now = new Date().getTime();
    endTime = (ref = parsedInfo.inactiveTime) != null ? ref : now;
    descArray = JSON.parse(descResponse.body).descriptors;
    for (desc in descArray) {
      if (descArray[desc].label.startsWith("Breaches for Anomaly")) {
        return getOpsaUri() + "/rest/getQueryResult?aqlQuery=" + encodeURIComponent(descArray[desc].aql) + "&endTime=" + endTime + '&granularity=0&pageIndex=1&paramsMap={"$starttime":"' + new Date(parsedInfo.triggerTime) + '","$limit":"1000","$interval":7200,"$offset":0,"$N":5,"$pctile":10,"$timeoffset":0,"$starttimeoffset":0,"$endtimeoffset":0,"$timeout":0,"$drill_dest":"","$drill_label":"","$drill_value":"","$drill_type":"","$problemtime":' + parsedInfo.triggerTime + ',"$aggregate_playback_flag":null}&queryType=anomalyInstance&startTime=' + parsedInfo.triggerTime + '&timeZoneOffset=-180&timeout=10';
      }
    }
  };
  AnomAPI.prototype.parseRes = function (res, requestedHost, requestedAnomalyType) {
    var anomalies, body, collection, collectionGroup, collectionGroupId, collectionId, collections, extractAnomaliesFromTable, extractInfoFromRawProps, extractSingleAnomalyData, extractedAnoms, modifyPropText, okToDisplay, propNames, table, tableIdx, toSkipAnomaly, toSkipProperty;
    body = res.body;
    anomalies = new Array();
    collections = JSON.parse(body);
    extractInfoFromRawProps = function (props, propName, propContainer) {
      var propVal;
      propVal = propContainer.displayValue;
      switch (propName) {
        case "Active time":
          props.triggerTime = propVal;
          break;
        case "Inactive time":
          props.inactiveTime = propVal;
          break;
        case "Anomaly id":
          props.anomalyId = propVal;
          break;
        case "Entity":
          props.rawEntity = propVal;
          if (propContainer.drillPQL.startsWith("host")) {
            props.anomalyType = "host";
          }
          if (propContainer.drillPQL.startsWith("service")) {
            props.anomalyType = "service";
          }
      }
      return props;
    };
    modifyPropText = function (propName, propVal, extractedInfo) {
      var jsonValue, str, val;
      switch (propName) {
        case "Active time":
          propName = "Trigger Time";
          propVal = new Date(Number(propVal));
          break;
        case "Severity":
          str = '';
          jsonValue = JSON.parse(propVal);
          for (val in jsonValue) {
            str += ',' + jsonValue[val];
          }
          str = str.replace(',', '');
          propVal = str;
          break;
        case "Entity":
          if (extractedInfo.anomalyType === "host") {
            propVal = getLinkToHost(propVal);
          }
      }
      return {
        propName: propName,
        propVal: propVal
      };
    };
    toSkipProperty = function (propName, extractedInfo) {
      if (propName === "Inactive time" || propName === "First breach" || propName === "Breaches timestamps" || propName === "Rules") {
        return true;
      }
      if (propName === "Entity" && extractedInfo.anomalyType === "service") {
        return true;
      }
    };
    okToDisplay = function (display, origPropName, origPropVal, extractedInfo) {
      return display === false && origPropName === "Entity" && (origPropVal === requestedHost || requestedHost === "*") && (requestedAnomalyType === extractedInfo.anomalyType);
    };
    toSkipAnomaly = function (propName, propVal) {
      return propName === "Status" && propVal !== "active";
    };
    extractSingleAnomalyData = function (anomalyRawData) {
      var anomAttr, anomalyPropertiesAsText, colIdx, curHost, mProps, ok2Display, origPropName, origPropVal;
      anomalyPropertiesAsText = "";
      ok2Display = false;
      anomAttr = {};
      anomAttr.anomalyPropertiesText = "";
      for (colIdx in anomalyRawData) {
        origPropName = propNames[colIdx];
        origPropVal = anomalyRawData[colIdx].displayValue;
        anomAttr = extractInfoFromRawProps(anomAttr, origPropName, anomalyRawData[colIdx]);
        mProps = modifyPropText(origPropName, origPropVal, anomAttr);
        if (toSkipAnomaly(mProps.propName, mProps.propVal)) {
          return null;
        }
        if (okToDisplay(ok2Display, origPropName, origPropVal, anomAttr)) {
          ok2Display = true;
        }
        if (toSkipProperty(mProps.propName, anomAttr)) {
          continue;
        }
        anomalyPropertiesAsText += "*" + mProps.propName + ":* " + mProps.propVal + "\n";
      }
      if (!ok2Display) {
        return null;
      }
      curHost = anomAttr.rawEntity;
      anomAttr.text = "\n*Displaying anomalies for " + requestedAnomalyType + ":* " + curHost + "\n>>>" + anomalyPropertiesAsText;
      return anomAttr;
    };
    extractAnomaliesFromTable = function () {
      var columnIdx, row, rowIdx, singleAnomaly, tableAnomalies, tableRows;
      tableAnomalies = new Array();
      for (columnIdx in table.columnNames) {
        propNames.push(table.columnNames[columnIdx].columnTitle);
      }
      tableRows = table.tableDataWithDrill;
      for (rowIdx in tableRows) {
        row = tableRows[rowIdx];
        singleAnomaly = extractSingleAnomalyData(row);
        if (singleAnomaly) {
          tableAnomalies.push(singleAnomaly);
        }
      }
      return tableAnomalies;
    };
    for (collectionGroupId in collections) {
      collectionGroup = collections[collectionGroupId];
      for (collectionId in collectionGroup) {
        collection = collectionGroup[collectionId].processedResult;
        for (tableIdx in collection) {
          table = collection[tableIdx];
          propNames = new Array();
          extractedAnoms = extractAnomaliesFromTable(table);
          anomalies = anomalies.concat(extractedAnoms);
        }
      }
    }
    return anomalies;
  };
  AnomAPI.prototype.requestMetrices = function (anom) {
    var mDescUrl, sHeaders, sJar;
    sJar = this.sJar;
    sHeaders = this.sHeaders;
    mDescUrl = AnomAPI.prototype.getMetricsDescUrl(anom);
    return requestp({
      url: mDescUrl,
      jar: sJar,
      method: 'GET',
      headers: sHeaders
    }).then((function (descRes) {
      var mUrl;
      mUrl = AnomAPI.prototype.getMetricsUrl(anom, descRes);
      return requestp({
        url: mUrl,
        jar: sJar,
        method: 'POST',
        headers: sHeaders
      });
    }));
  };
  AnomAPI.prototype.parseAnoms = function (userRes, anomRes) {
    var requestedAnomalyType, requestedHost;
    requestedHost = getRequestedHost(userRes);
    requestedAnomalyType = getRequestedAnomaliyType(userRes);
    return this.parseRes(anomRes, requestedHost, requestedAnomalyType);
  };
  module.exports = function (robot) {
    var exp, invokeAnomaliesAPI;
    invokeAnomaliesAPI = function (userRes) {
      userRes.reply(pleaseWaitMsg);
      return opsaLogin().then((function (res) {
        var anomAPI;
        anomAPI = new AnomAPI(res.xsrfToken, res.jSessionId);
        return anomAPI.requestPrimaryData().then((function (anomRes) {
          var anom, anoms, i, len, results;
          anoms = anomAPI.parseAnoms(userRes, anomRes);
          handleNoData(anoms, userRes);
          results = [];
          for (i = 0, len = anoms.length; i < len; i++) {
            anom = anoms[i];
            results.push(((function (anom) {
              var cAnom;
              cAnom = deepClone(anom);
              return function () {
                return anomAPI.requestMetrices(cAnom).then((function (resultRes) {
                  cAnom.text += getMetricesText(resultRes);
                  return userRes.reply(cAnom.text);
                }));
              };
            })(anom))());
          }
          return results;
        }));
      }));
    };
    exp = /display anomalies for (host|service)\s*:\s*(.*)/i;
    return hubotRouter.register(robot, exp, invokeAnomaliesAPI);
  };

}).call(this);

//# sourceMappingURL=opsa-hubot.js.map
