'use strict';

var gulp = require('gulp'),
    gutil = require('gulp-util'),
    mocha = require('gulp-mocha'),
    istanbul = require('gulp-istanbul'),
    exit = require('gulp-exit');

var TESTS = './test/*.js';
var SRC = './lib/**/*.js';
var MOCHA_OPTS = {
  timeout: 20000
};

gulp.task('clean', function() {
  var del = require('del');
  return del(['./coverage/']);
});

gulp.task('lint', function() {
  var eslint = require('gulp-eslint');

  var t = gulp.src([
    SRC,
    TESTS,
    'gulpfile.js'
  ])
  .pipe(eslint())
  .pipe(eslint.format())
  .pipe(eslint.failAfterError());
  return t;
});

gulp.task('test', ['lint'], function() {
  return gulp.src([TESTS])
    .pipe(mocha(MOCHA_OPTS))
    .pipe(exit());
});

gulp.task('doc', function() {
  var documentation = require('gulp-documentation');
  return gulp.src([SRC])
    .pipe(documentation({
      format: 'html',
      github: true
    }))
    .pipe(gulp.dest('doc'));
});

gulp.task('doc-deploy', ['doc'], function() {
  var ghPages = require('gulp-gh-pages');
  return gulp.src('./doc/**/*')
    .pipe(ghPages());
});

gulp.task('pre-coverage', ['clean'], function() {
  return gulp.src([SRC])
    .pipe(istanbul())
    .pipe(istanbul.hookRequire());
});

gulp.task('coverage', ['pre-coverage'], function() {
  var t = gulp.src([TESTS])
  .pipe(mocha(MOCHA_OPTS).on('error', function(er) {
    gutil.log(er);
    t.end();
  }))
  .pipe(istanbul.writeReports({
    dir: './coverage'
  }));
  // XXX: This line needs to be commented out for `gulp serve` to work, but
  // needs to be enabled for Travis tests to pass (since gulp fails to exit
  // after the tests otherwise).
  //.pipe(exit());
  return t;
});

gulp.task('ci', ['coverage'], function() {
  var coveralls = require('gulp-coveralls');
  gulp.src('./coverage/**/lcov.info')
  .pipe(coveralls());
});

gulp.task('watch', ['coverage'], function() {
  return gulp.watch([SRC, TESTS], ['coverage']);
});

gulp.task('serve', ['watch'], function() {
  var gls = require('gulp-live-server');
  var open = require('open');
  var server = gls['static']('coverage/lcov-report');
  server.start();
  open('http://localhost:3000/');
  return gulp.watch(['coverage/lcov-report/**/*.html'], function(file) {
    return server.notify.apply(server, [file]);
  });
});

gulp.task('default', ['coverage']);
