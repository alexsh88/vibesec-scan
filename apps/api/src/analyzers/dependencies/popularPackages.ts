// Curated, bundled reference lists for the supply-chain heuristics (no network).
//
// POPULAR_NPM / POPULAR_PYPI: hand-curated from the author's knowledge of the most-depended-upon /
// most-downloaded packages (npm "most depended upon" rankings and the top-PyPI-packages download
// dataset, as of 2025-2026). They are a heuristic baseline for typosquat detection — completeness is
// not the goal; a popular name missing here only means look-alikes of it are not flagged.
//
// INSTALL_SCRIPT_ALLOWLIST: well-known packages that legitimately run install scripts (native
// builds, binary downloads, git hooks, postinstall banners), so their install script is not a
// supply-chain signal by itself.
//
// KNOWN_DISTINCT: real, established packages that happen to sit within edit distance 1 of a popular
// name; never flagged as typosquats.

export const POPULAR_NPM: readonly string[] = `
lodash react react-dom express chalk commander debug axios tslib moment request prop-types uuid
fs-extra async bluebird vue classnames yargs underscore rxjs semver glob dotenv body-parser mkdirp
jquery minimist colors inquirer webpack typescript @types/node core-js cheerio q aws-sdk rimraf
node-fetch ws mongoose eslint babel-runtime jsonwebtoken redux shelljs @babel/core @babel/runtime
@babel/preset-env @babel/cli @babel/parser @babel/traverse @babel/types @babel/generator
@babel/template @babel/helper-plugin-utils handlebars yeoman-generator through2 zone.js
@angular/core @angular/common @angular/compiler @angular/platform-browser @angular/router
@angular/forms @angular/http jest mocha chai sinon supertest nodemon cross-env concurrently
ora cors morgan cookie-parser express-session passport bcrypt bcryptjs mysql mysql2 pg sequelize
redis ioredis mongodb knex graphql apollo-server @apollo/client socket.io socket.io-client
styled-components @emotion/react @emotion/styled tailwindcss postcss autoprefixer sass node-sass
less webpack-cli webpack-dev-server babel-loader css-loader style-loader file-loader url-loader
html-webpack-plugin mini-css-extract-plugin terser terser-webpack-plugin uglify-js rollup vite
esbuild parcel next nuxt gatsby @nestjs/core @nestjs/common koa koa-router hapi fastify
eslint-plugin-import eslint-plugin-react eslint-config-airbnb eslint-plugin-prettier
eslint-config-prettier prettier @typescript-eslint/parser @typescript-eslint/eslint-plugin
ts-node ts-jest @types/jest @types/react @types/express @types/lodash @types/react-dom
react-router react-router-dom react-redux redux-thunk redux-saga mobx immer immutable
@reduxjs/toolkit zustand react-query @tanstack/react-query swr formik yup zod joi ajv
date-fns dayjs luxon moment-timezone numeral validator qs query-string querystring
path-to-regexp mime mime-types mime-db content-type cookie cookie-signature etag fresh
send serve-static finalhandler on-finished statuses http-errors depd destroy vary
iconv-lite safe-buffer string_decoder readable-stream inherits util-deprecate isarray
process-nextick-args core-util-is buffer events util assert stream-browserify crypto-browserify
browserify chokidar fsevents graceful-fs readdirp anymatch micromatch picomatch braces
fill-range to-regex-range is-number is-glob glob-parent is-extglob minimatch brace-expansion
balanced-match concat-map once wrappy inflight path-is-absolute fs.realpath
ansi-styles ansi-regex strip-ansi supports-color has-flag color-convert color-name
escape-string-regexp string-width wrap-ansi cliui y18n yargs-parser camelcase decamelize
emoji-regex is-fullwidth-code-point signal-exit cross-spawn which isexe shebang-command
path-key execa get-stream npm-run-path onetime mimic-fn strip-final-newline human-signals
source-map source-map-support js-yaml yaml argparse esprima acorn acorn-walk estraverse
esutils @babel/code-frame js-tokens picocolors kleur chalk-template log-symbols cli-spinners
cli-cursor restore-cursor figures boxen update-notifier configstore xdg-basedir dot-prop
p-limit p-locate p-try locate-path find-up path-exists pkg-dir resolve resolve-from
import-fresh parent-module callsites object-assign extend deepmerge clone lodash.merge
lodash.get lodash.set lodash.debounce lodash.throttle lodash.clonedeep lodash.isequal
node-forge jsdom puppeteer playwright selenium-webdriver sharp jimp canvas pdfkit
nodemailer twilio stripe firebase firebase-admin @aws-sdk/client-s3 googleapis
winston pino bunyan log4js loglevel helmet compression express-validator
multer formidable busboy body cookie-session csurf passport-local passport-jwt
http-proxy http-proxy-middleware request-promise got superagent needle node-cron cron
bull bullmq agenda kafkajs amqplib xml2js fast-xml-parser papaparse csv-parser xlsx
marked markdown-it highlight.js dompurify sanitize-html he entities htmlparser2 parse5
d3 chart.js three leaflet mapbox-gl socket.io-parser engine.io lru-cache node-cache
nanoid shortid crypto-js argon2 jose jwks-rsa openid-client
electron electron-builder react-native expo @expo/vector-icons vue-router vuex pinia
svelte @sveltejs/kit angular ember-source backbone knockout preact
husky lint-staged commitizen standard-version semantic-release lerna nx turbo
cypress @testing-library/react @testing-library/jest-dom karma jasmine ava tap vitest
nyc istanbul c8 sinon-chai chai-as-promised nock msw @faker-js/faker
`.trim().split(/\s+/);

export const POPULAR_PYPI: readonly string[] = `
requests urllib3 boto3 botocore setuptools certifi charset-normalizer idna six
python-dateutil s3transfer typing-extensions pyyaml numpy packaging pip wheel
cryptography cffi pycparser jmespath rsa pyasn1 pyasn1-modules google-api-core
protobuf attrs jinja2 markupsafe click pandas pytz importlib-metadata zipp
colorama awscli docutils platformdirs filelock virtualenv pyjwt wrapt
tomli pydantic pydantic-core annotated-types pluggy pytest iniconfig exceptiongroup
grpcio googleapis-common-protos aiohttp multidict yarl frozenlist aiosignal
async-timeout requests-oauthlib oauthlib cachetools google-auth decorator
psutil pyparsing scipy pillow soupsieve beautifulsoup4 lxml werkzeug flask
itsdangerous blinker sqlalchemy greenlet tqdm httpx httpcore h11 anyio sniffio
fastapi starlette uvicorn gunicorn django djangorestframework celery kombu
billiard vine amqp redis pymongo psycopg2 psycopg2-binary psycopg mysqlclient
pymysql matplotlib kiwisolver cycler fonttools contourpy seaborn scikit-learn
joblib threadpoolctl tensorflow keras torch torchvision transformers tokenizers
huggingface-hub safetensors regex openai anthropic tiktoken langchain
langchain-core nltk spacy gensim opencv-python networkx sympy mpmath
python-dotenv openpyxl xlrd xlsxwriter tabulate rich pygments markdown
mistune bleach html5lib webencodings chardet tenacity backoff retrying
paramiko bcrypt pynacl fabric invoke pexpect ptyprocess jsonschema
referencing rpds-py jsonpointer simplejson ujson orjson msgpack marshmallow
wtforms flask-sqlalchemy flask-login flask-cors flask-wtf alembic mako
pyopenssl pycryptodome pycryptodomex ecdsa passlib argon2-cffi
selenium scrapy twisted zope-interface pyzmq tornado jupyter notebook
ipython ipykernel jupyter-client jupyter-core traitlets nbformat nbconvert
mypy mypy-extensions black flake8 pycodestyle pyflakes isort pylint
astroid coverage pytest-cov pytest-mock pytest-asyncio tox nox pre-commit
sphinx babel docker kubernetes azure-core azure-storage-blob
google-cloud-storage google-cloud-core google-resumable-media gcsfs s3fs fsspec
pyarrow polars dask distributed toolz sortedcontainers more-itertools
python-multipart email-validator dnspython websockets websocket-client
gevent eventlet pyserial shapely pyproj geopandas fiona
xmltodict defusedxml pycurl httplib2 uritemplate google-api-python-client
oauth2client slack-sdk twilio stripe sentry-sdk prometheus-client
structlog loguru arrow pendulum humanize python-slugify unidecode
termcolor typer pyinstaller cython numba llvmlite
`.trim().split(/\s+/);

export const INSTALL_SCRIPT_ALLOWLIST: ReadonlySet<string> = new Set(`
esbuild sharp bcrypt node-sass sqlite3 better-sqlite3 @swc/core fsevents core-js core-js-pure
protobufjs puppeteer puppeteer-core playwright playwright-core canvas cypress husky electron
node-gyp nodemon ejs es5-ext styled-components @parcel/watcher msgpackr-extract
lmdb @prisma/client prisma @prisma/engines bufferutil utf-8-validate argon2 re2 grpc
@grpc/grpc-js keytar leveldown deasync fibers phantomjs-prebuilt chromedriver geckodriver
node-pty iltorb zeromq kerberos snappy @sentry/cli @sentry/profiling-node unrs-resolver
@biomejs/biome turbo nx @nestjs/core @vscode/ripgrep vue-demi spawn-sync yarn
`.trim().split(/\s+/));

export const KNOWN_DISTINCT: ReadonlySet<string> = new Set(`
inherit utils buffers react-is color yarg ajv-keywords mimic-response
es6-ext es6-iterator es6-symbol is-array source-maps glob-to-regexp
requests-toolbelt python-jose jwt
`.trim().split(/\s+/));
