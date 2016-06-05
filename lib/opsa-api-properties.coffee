fs = require('fs');
configurationFile = 'opsa-configuration.json';
String.prototype.replaceAll = (search, replacement) ->
  target = this;
  return target.replace(new RegExp(search, 'g'), replacement)
jsonifyConfFile = (rawFile) ->
  rawFile.replaceAll('"', "").replaceAll('\n', ",").replace(',', "").replace(',}', "}").replaceAll(':', ':"').replaceAll(':" ', '": "').replaceAll(',', '","').replace('}",', '"}').replace("{  ", "{").replaceAll(" ", "").replace("{", '{"').replace('}"', '}')

rawFile = fs.readFileSync(configurationFile, 'utf8')
confFile = jsonifyConfFile(rawFile)
module.exports = JSON.parse(confFile)
