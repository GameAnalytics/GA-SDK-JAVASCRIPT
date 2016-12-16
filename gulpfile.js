var gulp = require('gulp');
var ts = require('gulp-typescript');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var Server = require('karma').Server;
var tsProject = ts.createProject('tsconfig.json');
var tsMinProject = ts.createProject('tsconfig.json', { outFile: './dist/GameAnalytics.min.js' });

gulp.task('default', function() {
    var tsResult = tsMinProject.src()
        .pipe(tsMinProject());

    return tsResult.js
        .pipe(uglify())
        .pipe(gulp.dest('.'));
});

gulp.task('debug', function() {
    var tsResult = tsProject.src()
        .pipe(sourcemaps.init())
        .pipe(tsProject());

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
