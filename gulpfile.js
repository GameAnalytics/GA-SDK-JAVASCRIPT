var gulp = require('gulp');
var ts = require('gulp-typescript');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var Server = require('karma').Server;
var argv = require('yargs').argv;
var gulpif = require('gulp-if');
var tsProject = ts.createProject('tsconfig.json');
var tsProjectMini = ts.createProject('tsconfig.json', { outFile: "./dist/GameAnalytics.min.js" });
var tsProjectDebug = ts.createProject('tsconfig.json', { outFile: "./dist/GameAnalytics.debug.js" });
var tsDeclaration = ts.createProject('tsconfig.json');
var replace = require('gulp-replace');
var concat = require('gulp-concat');
var insert = require('gulp-insert');

gulp.task('build_debug', function() {
    var tsResult = tsProjectDebug.src()
        .pipe(sourcemaps.init())
        .pipe(tsProjectDebug());

    return tsResult.js
        .pipe(sourcemaps.write())
        .pipe(gulp.dest('.'));
});

gulp.task('declaration', function() {
    var tsResult = tsDeclaration.src()
        .pipe(tsDeclaration());

    return tsResult.dts
        .pipe(replace('declare module public_enums', 'export module gameanalytics'))
        .pipe(replace('declare var GameAnalytics', 'declare var GameAnalyticsCommand'))
        .pipe(insert.wrap("", "export declare var GameAnalytics: typeof gameanalytics.GameAnalytics;\n"))
        .pipe(insert.wrap("", "export default GameAnalytics;\n"))
        .pipe(gulp.dest('.'));
});

gulp.task('bundle_min_js', function() {
    return gulp.src(['./vendor/hmac-sha256-min.js', './vendor/enc-base64-min.js'])
        .pipe(concat('bundle.min.js'))
        .pipe(gulp.dest('./vendor'));
});

gulp.task('bundle_js', function() {
    return gulp.src(['./vendor/hmac-sha256.js', './vendor/enc-base64.js'])
        .pipe(concat('bundle.js'))
        .pipe(gulp.dest('./vendor'));
});

gulp.task('test', function (done) {
    new Server({
        configFile: __dirname + '/karma.conf.js',
        singleRun: true
    }, done).start();
});

gulp.task('build_mini', function() {
    var tsResult = tsProjectMini.src()
        .pipe(replace('GALogger.debugEnabled = true', 'GALogger.debugEnabled = false'))
        .pipe(replace('GALogger.d(', '//GALogger.d('))
        .pipe(gulpif(argv.nologging, replace('GALogger.', '//GALogger.')))
        .pipe(gulpif(argv.nologging, replace('//GALOGGER_START', '/*GALOGGER_START')))
        .pipe(gulpif(argv.nologging, replace('//GALOGGER_END', '//GALOGGER_END*/')))
        .pipe(gulpif(argv.nologging, replace('import GALogger = gameanalytics.logging.GALogger', '//import GALogger = gameanalytics.logging.GALogger')))
        .pipe(tsProjectMini());

    return tsResult.js
        .pipe(gulp.dest('.'));
});

gulp.task('build_normal', function() {
    var tsResult = tsProject.src()
        .pipe(replace('GALogger.debugEnabled = true', 'GALogger.debugEnabled = false'))
        .pipe(replace('GALogger.d(', '//GALogger.d('))
        .pipe(tsProject());

    return tsResult.js
        .pipe(gulp.dest('.'));
});

var mini = function() {
    return gulp.src(['./vendor/bundle.min.js', './dist/GameAnalytics.min.js'])
        .pipe(concat('GameAnalytics.min.js'))
        .pipe(uglify())
        .pipe(insert.wrap("(function(scope){\n", "\nscope.gameanalytics=gameanalytics;\nscope.GameAnalytics=GameAnalytics;\n})(this);\n"))
        .pipe(gulp.dest('./dist'));
};
gulp.task('mini', gulp.series(gulp.parallel('bundle_min_js', 'build_mini'), mini));

var normal = function() {
    return gulp.src(['./vendor/bundle.min.js', './dist/GameAnalytics.js'])
        .pipe(concat('GameAnalytics.js'))
        .pipe(uglify())
        .pipe(insert.wrap("(function(scope){\n", "\nscope.gameanalytics=gameanalytics;\nscope.GameAnalytics=GameAnalytics;\n})(this);\n"))
        .pipe(gulp.dest('./dist'));
};
gulp.task('normal', gulp.series(gulp.parallel('bundle_min_js', 'build_normal'), normal));

var unity = function() {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.js'])
        .pipe(concat('GameAnalytics.jspre'))
        .pipe(gulp.dest('./dist'));
};
gulp.task('unity', gulp.series(gulp.parallel('bundle_js', 'build_normal'), unity));

var ga_node = function() {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.js'])
        .pipe(concat('GameAnalytics.node.js'))
        .pipe(insert.wrap("'use strict';\n", "module.exports = gameanalytics;"))
        .pipe(gulp.dest('./dist'));
};
gulp.task('ga_node', gulp.series(gulp.parallel('bundle_js', 'build_normal'), ga_node));

var construct = function () {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.js'])
        .pipe(concat('GameAnalytics.construct.js'))
        .pipe(insert.wrap("'use strict';\n", "globalThis.gameanalytics = gameanalytics;"))
        .pipe(gulp.dest('./dist'));
};
gulp.task('construct', gulp.series(gulp.parallel('bundle_js', 'build_normal'), construct));

var debug = function() {
    return gulp.src(['./vendor/bundle.min.js', './dist/GameAnalytics.debug.js'])
        .pipe(concat('GameAnalytics.debug.js'))
        .pipe(insert.wrap("(function(scope){\n", "\nscope.gameanalytics=gameanalytics;\nscope.GameAnalytics=GameAnalytics;\n})(this);\n"))
        .pipe(gulp.dest('./dist'));
};
gulp.task('debug', gulp.series(gulp.parallel('bundle_min_js', 'build_debug'), debug));

gulp.task('default', gulp.series('debug', 'mini', 'unity', 'ga_node', 'construct', 'normal', 'declaration'));
