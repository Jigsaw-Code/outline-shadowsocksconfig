// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// <reference types="gulp" />

const gulp = require('gulp');
const runSequence = require('run-sequence');
const gulpLoadPlugins = require('gulp-load-plugins');

const plugins = gulpLoadPlugins();

const moduleCompatibilityHeader = `(function iife() {
  const platformExportObj = (function detectPlatformExportObj() {
    if (typeof module !== 'undefined' && module.exports) {
      return module.exports;  // node
    } else if (typeof window !== 'undefined') {
      return window;  // browser
    }
    throw new Error('Could not detect platform global object (no window or module.exports)');
  })();`;

const moduleCompatibilityFooter = `})();`;

gulp.task('build:lib', () => {
  const tsProject = plugins.typescript.createProject('tsconfig.json');

  return gulp.src([
      'shadowsocks_config.ts',
    ])
    // Handle source maps manually rather than having tsc generate them because we
    // modify the output of tsc.
    .pipe(plugins.sourcemaps.init())
    .pipe(tsProject())
    .once('error', function () {
      this.once('finish', () => process.exit(1));
    })
    .pipe(plugins.replace(
      'Object.defineProperty(exports, "__esModule", { value: true });',
      moduleCompatibilityHeader
    ))
    .pipe(plugins.replace(
      'exports.',
      'platformExportObj.'
    ))
    .pipe(plugins.insert.append(moduleCompatibilityFooter))
    .pipe(plugins.sourcemaps.write())
    .pipe(gulp.dest('.'));
});

gulp.task('build:tests', () => {
  const tsProject = plugins.typescript.createProject('tsconfig.json', {
    module: 'commonjs',
    moduleResolution: 'node',
  });
  return gulp.src([
      'shadowsocks_config.spec.ts',
    ])
    .pipe(tsProject())
    .once('error', function () {
      this.once('finish', () => process.exit(1));
    })
    .js
    .pipe(gulp.dest('.'));
});


gulp.task('default', ['build:lib', 'build:tests']);

