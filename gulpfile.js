var gulp = require('gulp');
var ts = require('gulp-typescript');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var Server = require('karma').Server;
var tsProject = ts.createProject('tsconfig.json');
var tsProjectMini = ts.createProject('tsconfig.json', { outFile: "./dist/GameAnalytics.min.js" });
var tsProjectDebug = ts.createProject('tsconfig.json', { outFile: "./dist/GameAnalytics.debug.js" });
var replace = require('gulp-replace');

gulp.task('mini', function() {
    var tsResult = tsProjectMini.src()
        .pipe(replace('GALogger.d(', '//GALogger.d('))
        .pipe(replace('GALogger.i(', '//GALogger.i('))
        .pipe(replace('GALogger.w(', '//GALogger.w('))
        .pipe(tsProjectMini());

    return tsResult.js
        .pipe(uglify())
        .pipe(gulp.dest('.'));
});

gulp.task('normal', function() {
    var tsResult = tsProject.src()
        .pipe(tsProject());

    return tsResult.js
        .pipe(uglify())
        .pipe(gulp.dest('.'));
});

gulp.task('debug', function() {
    var tsResult = tsProjectDebug.src()
        .pipe(sourcemaps.init())
        .pipe(tsProjectDebug());

    return tsResult.js
        .pipe(sourcemaps.write())
        .pipe(gulp.dest('.'));
});

gulp.task('test', function (done) {
    new Server({
        configFile: __dirname + '/karma.conf.js',
        singleRun: true
    }, done).start();
});

gulp.task('default', ['mini', 'normal']);
