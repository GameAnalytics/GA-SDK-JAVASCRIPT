var gulp = require('gulp');
var ts = require('gulp-typescript');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var Server = require('karma').Server;
var tsProject = ts.createProject('tsconfig.json');
var tsProjectMini = ts.createProject('tsconfig.json', { outFile: "./dist/GameAnalytics.min.js" });
var tsProjectDebug = ts.createProject('tsconfig.json', { outFile: "./dist/GameAnalytics.debug.js" });
var tsDeclaration = ts.createProject('tsconfig.json');
var replace = require('gulp-replace');
var concat = require('gulp-concat');

gulp.task('mini', ['bundle_js', 'build_mini'], function() {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.min.js'])
        .pipe(concat('GameAnalytics.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest('./dist'));
});

gulp.task('build_mini', function() {
    var tsResult = tsProjectMini.src()
        .pipe(replace('GALogger.d(', '//GALogger.d('))
        .pipe(replace('GALogger.i(', '//GALogger.i('))
        .pipe(replace('GALogger.w(', '//GALogger.w('))
        .pipe(tsProjectMini());

    return tsResult.js
        .pipe(gulp.dest('.'));
});

gulp.task('normal', ['bundle_js', 'build_normal'], function() {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.js'])
        .pipe(concat('GameAnalytics.js'))
        .pipe(uglify())
        .pipe(gulp.dest('./dist'));
});

gulp.task('unity', ['bundle_js', 'build_normal'], function() {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.js'])
        .pipe(concat('GameAnalytics.jslib'))
        .pipe(gulp.dest('./dist'));
});

gulp.task('build_normal', function() {
    var tsResult = tsProject.src()
        .pipe(tsProject());

    return tsResult.js
        .pipe(gulp.dest('.'));
});

gulp.task('debug', ['bundle_js', 'build_debug'], function() {
    return gulp.src(['./vendor/bundle.js', './dist/GameAnalytics.debug.js'])
        .pipe(concat('GameAnalytics.debug.js'))
        .pipe(gulp.dest('./dist'));
});

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
        .pipe(gulp.dest('.'));
});

gulp.task('bundle_js', function() {
    return gulp.src(['./vendor/hmac-sha256.js', './vendor/enc-base64-min.js'])
        .pipe(concat('bundle.js'))
        .pipe(gulp.dest('./vendor'));
});

gulp.task('test', function (done) {
    new Server({
        configFile: __dirname + '/karma.conf.js',
        singleRun: true
    }, done).start();
});

gulp.task('default', ['debug', 'mini', 'normal', 'declaration']);
