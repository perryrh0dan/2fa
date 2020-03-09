const gulp = require('gulp');
const ts = require('gulp-typescript');
const sourcemaps = require('gulp-sourcemaps');
const merge = require('merge-stream');

const tsProject = ts.createProject('tsconfig.json');

const dirs = {
  dist: ['dist']
}

const compileProd = () => {
  const tsResult = tsProject.src()
    .pipe(tsProject({ declaration: true }));

  return merge([
    tsResult.dts.pipe(gulp.dest(dirs.dist)),
    tsResult.js.pipe(gulp.dest(dirs.dist)),
  ])
};


const compileTest = () => {
  const tsResult = tsProject.src()
    .pipe(sourcemaps.init())
    .pipe(tsProject());
  return merge(tsResult, tsResult.js)
    .pipe(sourcemaps.write('.'))
    .pipe(gulp.dest(dirs.dist));
};

const movePackage = () => {
  return gulp.src('package.json')
    .pipe(gulp.dest(dirs.dist));
};

const moveReadme = () => {
  return gulp.src('readme.md')
    .pipe(gulp.dest(dirs.dist));
};

const buildMeta = gulp.series(movePackage, moveReadme)
const buildProd = gulp.series(compileProd);
const buildTest = gulp.series(compileTest);


module.exports = {
  buildMeta,
  buildProd,
  buildTest,
};
