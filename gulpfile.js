const gulp = require('gulp');
const ts = require('gulp-typescript');
const sourcemaps = require('gulp-sourcemaps');
const merge = require('merge-stream');

const tsProject = ts.createProject('tsconfig.json');

const dirs = {
  dist: ['dist']
}

const compileProd = () => {
  return tsProject.src()
    .pipe(tsProject())
    .js.pipe(gulp.dest(dirs.dist));
};

const compileTest = () => {
  const tsResult = tsProject.src()
    .pipe(sourcemaps.init())
    .pipe(tsProject());
  return merge(tsResult, tsResult.js)
    .pipe(sourcemaps.write('.'))
    .pipe(gulp.dest(dirs.dist));
};

const buildTest = gulp.series(compileTest);

module.exports = {
  buildTest,
};
