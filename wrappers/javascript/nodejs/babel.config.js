const path = require('path')

const ariesAskarShared = require('../shared/package.json')

module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    [
      'module-resolver',
      {
        extensions: ['.tsx', '.ts', '.js', '.json'],
        alias: {
          [ariesAskarShared.name]: path.join(__dirname, '../shared', ariesAskarShared.source),
        },
      },
    ],
  ],
}
