const path = require('path')

const indyVdrShared = require('../shared/package.json')

module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    [
      'module-resolver',
      {
        extensions: ['.tsx', '.ts', '.js', '.json'],
        alias: {
          [indyVdrShared.name]: path.join(__dirname, '../shared', indyVdrShared.source),
        },
      },
    ],
  ],
}
