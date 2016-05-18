// Generated by CoffeeScript 1.10.0
(function() {
    var createJar, createMessage, displayAnomalies, displayHosts, getSessionId, hostName, password, request, requestp, scan, semaphore, updateSemaphore, user;

  createMessage = function(res) {
    var msgData, numHosts, opsa;
    numHosts = res.match[1];
    opsa = JSON.stringify({
        "oa_sysperf_global"
    :
        [
            {
                "processedResult": [
                    {
                        "resultType": "singlevalue",
                        "metricName": "AGGREGATE_AVG_oa_sysperf_global_cpu_util",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29;",
                        "metricUnit": "%",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29;",
                        "dimensionValues": [
                            "16.60.188.71"
                        ],
                        "displayDimensionValues": [
                            "16.60.188.71"
                        ],
                        "drillLabel": "host withkey \"16.60.188.71\"",
                        "drillPQL": "host withkey \"16.60.188.71\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 41.6077777777778,
                                "computeType": "topn_aggregate_avg"
                            }
                        ]
                    },
                    {
                        "resultType": "singlevalue",
                        "metricName": "TOPN_AGGREGATE_AVG_oa_sysperf_global_cpu_util_10",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "metricUnit": "",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "dimensionValues": [
                            "16.60.188.71"
                        ],
                        "displayDimensionValues": [
                            "16.60.188.71"
                        ],
                        "drillLabel": "host withkey \"16.60.188.71\"",
                        "drillPQL": "host withkey \"16.60.188.71\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 1.0,
                                "computeType": "topn_aggregate_avg_rank"
                            }
                        ]
                    },
                    {
                        "resultType": "singlevalue",
                        "metricName": "AGGREGATE_AVG_oa_sysperf_global_cpu_util",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29;",
                        "metricUnit": "%",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29;",
                        "dimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "displayDimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "drillLabel": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillPQL": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 3.06888888888889,
                                "computeType": "topn_aggregate_avg"
                            }
                        ]
                    },
                    {
                        "resultType": "singlevalue",
                        "metricName": "TOPN_AGGREGATE_AVG_oa_sysperf_global_cpu_util_10",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "metricUnit": "",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "dimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "displayDimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "drillLabel": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillPQL": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 2.0,
                                "computeType": "topn_aggregate_avg_rank"
                            }
                        ]
                    }
                ],
                "filterQueryResult": false,
                "metricLabels": [
                    "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                    "CPU Util &#x28;Aggregate avg&#x29; &#x28;&#x25;&#x29;"
                ],
                "outerCall": false,
                "partialResult": false,
                "aggregatePlayback": false,
                "metaResult": false
            }
        ]
    }
    );
    msgData = {
      text: "Latest changes",
      attachments: [
        {
          fallback: "Comparing 77777",
          title: "Comparing 88988888}",
          title_link: "89988898",
          text: "commits_summary",
          mrkdwn_in: ["text"]
        }
      ]
    };
    return res.robot.emit('slack.attachment', {
      message: {
        "type": "message",
        "channel": "C2147483705",
        "user": "ofer",
        "text": "Hello world",
        "ts": "1355517523.000005",
        "envelope": "envelope"
      },
      content: {
          text: "Alert Test",
          fallback: "Alert fallback",
        fields: [
          {
              title: "Alert Field 1",
              value: "Alert value 1"
          }
        ]
      },
      channel: "#opsa-channel",
      username: "opsa",
      icon_url: "...",
      icon_emoji: "..."
    });
  };

  scan = function(obj, level) {
    var c, fields, k, lineNum, spaces;
    k = void 0;
    if (typeof level === 'undefined') {
      level = 0;
    }
    spaces = '';
    c = 0;
    while (c < level) {
      spaces += ' ';
      c++;
    }
    if (obj instanceof Object) {
      fields = '';
      lineNum = 1;
      for (k in obj) {
        k = k;
        if (obj.hasOwnProperty(k)) {
          fields += spaces + '*' + k + ':*' + scan(obj[k], level + 1) + "\n";
        }
      }
    } else {
      return spaces + "`" + obj + '`\n';
    }
    return fields + '\n';
  };

  displayHosts = function(res) {
    var numHosts, opsa;
    numHosts = res.match[1];
    opsa = JSON.stringify({
        "oa_sysperf_global"
    :
        [
            {
                "processedResult": [
                    {
                        "resultType": "singlevalue",
                        "metricName": "AGGREGATE_AVG_oa_sysperf_global_cpu_util",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29;",
                        "metricUnit": "%",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29;",
                        "dimensionValues": [
                            "16.60.188.71"
                        ],
                        "displayDimensionValues": [
                            "16.60.188.71"
                        ],
                        "drillLabel": "host withkey \"16.60.188.71\"",
                        "drillPQL": "host withkey \"16.60.188.71\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 41.6077777777778,
                                "computeType": "topn_aggregate_avg"
                            }
                        ]
                    },
                    {
                        "resultType": "singlevalue",
                        "metricName": "TOPN_AGGREGATE_AVG_oa_sysperf_global_cpu_util_10",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "metricUnit": "",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "dimensionValues": [
                            "16.60.188.71"
                        ],
                        "displayDimensionValues": [
                            "16.60.188.71"
                        ],
                        "drillLabel": "host withkey \"16.60.188.71\"",
                        "drillPQL": "host withkey \"16.60.188.71\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 1.0,
                                "computeType": "topn_aggregate_avg_rank"
                            }
                        ]
                    },
                    {
                        "resultType": "singlevalue",
                        "metricName": "AGGREGATE_AVG_oa_sysperf_global_cpu_util",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29;",
                        "metricUnit": "%",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29;",
                        "dimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "displayDimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "drillLabel": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillPQL": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 3.06888888888889,
                                "computeType": "topn_aggregate_avg"
                            }
                        ]
                    },
                    {
                        "resultType": "singlevalue",
                        "metricName": "TOPN_AGGREGATE_AVG_oa_sysperf_global_cpu_util_10",
                        "metricLabel": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "metricUnit": "",
                        "metricDescription": "CPU Util &#x28;Aggregate avg&#x29; &#x28;Topn&#x29;",
                        "dimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "displayDimensionValues": [
                            "opsa-aob2.hpswlabs.adapps.hp.com"
                        ],
                        "drillLabel": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillPQL": "host withkey \"opsa-aob2.hpswlabs.adapps.hp.com\"",
                        "drillTimeFrame": null,
                        "metricValues": [
                            {
                                "metricValue": 2.0,
                                "computeType": "topn_aggregate_avg_rank"
                            }
                        ]
                    }
                ],
                "filterQueryResult": false,
                "metricLabels": [
                    "CPU Util &#x28;*Aggregate* avg&#x29; &#x28;Topn&#x29;",
                    "CPU Util &#x28;*Aggregate* avg&#x29; &#x28;&#x25;&#x29;"
                ],
                "outerCall": false,
                "partialResult": false,
                "aggregatePlayback": false,
                "metaResult": false
            }
        ]
    }
    );
    return res.reply(("Displaying top " + numHosts + " hosts") + scan(JSON.parse(opsa)));
  };

    request = require('request');

    require('request-debug')(request);

    hostName = '16.60.188.235:8080/opsa';

    user = "opsa";

    password = "opsa";

    semaphore = 0;

    getSessionId = function (res) {
        var firstCookie, jSessionId;
        firstCookie = res.headers["set-cookie"][0];
        return jSessionId = firstCookie.split("=")[1].split(";")[0];
  };

    createJar = function (res, securityCheckUrl) {
        var cookie, jSessionId, jar;
        jSessionId = getSessionId(res);
        jar = request.jar();
        cookie = request.cookie('JSESSIONID=' + jSessionId);
        return jar.setCookie(cookie, securityCheckUrl, function (error, cookie) {
        });
    };

    updateSemaphore = function () {
        var ongoing;
        if (Date.now() - semaphore < 250) {
            ongoing = true;
        }
        return semaphore = Date.now();
    };

    displayAnomalies = function (res1) {
        var opsaHomeUrl;
        if (updateSemaphore()) {
            return;
        }
        opsaHomeUrl = 'http://' + hostName;
        requestp(opsaHomeUrl).then((function (res, data) {
            var form, headers, jar, securityCheckUrl;
            securityCheckUrl = opsaHomeUrl + "/j_security_check";
            jar = createJar(res, securityCheckUrl);
            form = {
                j_username: user,
                j_password: password
            };
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-US,en;q=0.8,he;q=0.6',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36',
                'Origin': 'http://16.60.188.235:8080',
                'Referer': 'http://16.60.188.235:8080/opsa/',
                'Cache-Control': 'max-age=0'
            };
            requestp(securityCheckUrl, headers, 'POST', jar, form).then((function (res) {
                var getXSRFTokenUrl;
                headers = {
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Encoding': 'gzip, deflate, sdch',
                    'Accept-Language': 'en-US,en;q=0.8,he;q=0.6',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36',
                    'Cache-Control': 'max-age=0'
                };
                getXSRFTokenUrl = opsaHomeUrl + "/rest/getXSRFToken";
                jar = createJar(res, getXSRFTokenUrl);
                return requestp(getXSRFTokenUrl, headers, 'GET', jar).then((function (res) {
                    var iconv;
                    iconv = require("iconv-lite");
                    return console.log(iconv.decode(res.body, 'x-www-form-urlencoded'));
                }));
            }));
        }), function (err) {
            console.error('%s; %s', err.message, opsaHomeUrl);
            console.log('%j', err.res.statusCode);
        });
        return res1.reply('Displaying Anomalies For Host: ' + res1.match[1]);
    };

    requestp = function (url, headers, method, jar, form) {
        headers = headers || {};
        method = method || 'GET';
        jar = jar || {};
        form = form || {};
        return new Promise(function (resolve, reject) {
            request({
                uri: url,
                headers: headers,
                method: method,
                jar: jar,
                form: form,
                encoding: null
            }, function (err, res, body) {
                if (err) {
                    return reject(err);
                } else if (res.headers["set-cookie"]) {
                    resolve(res, body);
                } else if (res.statusCode !== 200) {
                    err = new Error('Unexpected status code: ' + res.statusCode);
                    err.res = res;
                    return reject(err);
        }
                resolve(res, body);
            });
        });
    };

  module.exports = function(robot) {
    robot.respond(/top (.*) hosts/i, function(res) {
      return displayHosts(res);
    });
      robot.respond(/alert (.*)/i, function (res) {
      return createMessage(res);
      });
      return robot.respond(/display anomalies for host: (.*)/i, function (res) {
          return displayAnomalies(res);
    });
  };

}).call(this);

//# sourceMappingURL=opsa.js.map
