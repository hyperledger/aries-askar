const path = require('path')

const ariesAskarShared = require('../shared/package.json')

module.exports = {
  presets: [['@babel/preset-env', { targets: { node: 'current' } }], '@babel/preset-typescript'],
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
