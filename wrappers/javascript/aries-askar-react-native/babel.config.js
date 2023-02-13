const path = require('path')

const ariesAskarShared = require('../aries-askar-shared/package.json')

module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    [
      'module-resolver',
      {
        extensions: ['.tsx', '.ts', '.js', '.json'],
        alias: {
          [ariesAskarShared.name]: path.join(__dirname, '../aries-askar-shared', ariesAskarShared.source),
        },
      },
    ],
  ],
}
