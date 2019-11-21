process.env.CHROME_BIN = require('puppeteer').executablePath()

module.exports = function(config) {
  config.set({
    // see https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ["mocha", "browserify"],
    files: [
      "test/typescript/**/*.specs.ts"
    ],
    // see https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      '**/*.ts': ['typescript'],
      'test/typescript/**/*.specs.js': ['browserify']
    },
    // see https://npmjs.org/browse/keyword/karma-reporter
    reporters: ["mocha"],
    //colors: true,
    //logLevel: config.LOG_INFO,
    //autoWatch: true,
    // see https://npmjs.org/browse/keyword/karma-launcher
    browsers: ["ChromeHeadless"], //TODO should also use firefox in headleass mode but a PR on https://www.npmjs.com/package/karma-firefox-launcher is needed for it to happen
  })
}
