fs = require 'fs'
path = require 'path'
require('coffee-script/register');
#require('./node_modules/hubot/bin/hubot.js');
module.exports = (robot, scripts) ->
  scriptsPath = path.resolve(__dirname, 'src')
  if fs.existsSync scriptsPath
    for script in fs.readdirSync(scriptsPath).sort()
      if scripts? and '*' not in scripts
        robot.loadFile(scriptsPath, script) if script in scripts
      else
        robot.loadFile(scriptsPath, script)