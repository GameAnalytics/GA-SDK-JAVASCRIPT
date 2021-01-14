module.exports = function(config) {
    config.set({
        browsers: ['ChromeHeadless'],
        frameworks: ['jasmine'],
        files: [
            'dist/*.js',
            'test/*.js'
        ],
        exclude: [
            'dist/*.min.js',
            'dist/GameAnalytics.js',
            'dist/GameAnalytics.node.js'
        ],
    });
};
