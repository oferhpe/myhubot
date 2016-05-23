fs = require('fs');
configurationFile = 'opsa-configuration.json';
String.prototype.replaceAll = (search, replacement) ->
  target = this;
  return target.replace(new RegExp(search, 'g'), replacement)

confFile = fs.readFileSync(configurationFile, 'utf8').replaceAll('"', "").replaceAll('\n', ",").replace(',', "").replace(',}', "}").replaceAll(':', ':"').replaceAll(':" ', '": "').replaceAll(',', '","').replace('}",', '"}').replace("{  ", "{").replaceAll(" ", "").replace("{", '{"').replace('}"', '}')
module.exports = JSON.parse(confFile)
