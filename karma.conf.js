module.exports = function(config) {
    const isCI = !!process.env.CI;
    config.set({
        browsers: [isCI ? 'ChromeHeadlessCI' : 'ChromeHeadless'],
        customLaunchers: {
            ChromeHeadlessCI: {
                base: 'ChromeHeadless',
                flags: ['--no-sandbox', '--disable-setuid-sandbox'],
            },
        },
        frameworks: ['jasmine'],
        files: [
            'dist/*.js',
            'test/*.js'
        ],
        exclude: [
            'dist/*.min.js',
            'dist/GameAnalytics.js',
            'dist/GameAnalytics.node.js',
            'dist/GameAnalytics.esm.js'
        ],
    });
};
