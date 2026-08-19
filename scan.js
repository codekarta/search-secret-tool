#!/usr/bin/env node

/**
 * ============================================================================
 * Hardcoded Secrets & Sensitive Data Scanner
 * ============================================================================
 * Scans directories and codebases for hardcoded credentials, API keys,
 * connection strings, tokens, and cryptographic hashes based on the
 * detection patterns reference.
 *
 * Generates an interactive, standalone HTML audit report with zero external dependencies.
 *
 * Usage:
 *   node scan_secrets.js [path-to-scan] [options]
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// 1. Tool Metadata & Banner
// ---------------------------------------------------------------------------
const APP_METADATA = {
  name: 'IBM SecretScanner',
  author: 'Manish Bansal',
  email: 'manish.bansal@example.com',
  version: '1.3.0',
  versionDate: '2026-08-17',
  description: 'Hardcoded Secrets & Sensitive Data Detection Tool'
};

function printBanner() {
  console.log(`
\x1b[36m╔══════════════════════════════════════════════════════════════════════════════╗\x1b[0m
\x1b[36m║\x1b[0m   \x1b[1m\x1b[36m🛡️  ${APP_METADATA.name}\x1b[0m \x1b[90m- ${APP_METADATA.description}\x1b[0m
\x1b[36m╠══════════════════════════════════════════════════════════════════════════════╣\x1b[0m
\x1b[36m║\x1b[0m  \x1b[1mCreated by:\x1b[0m  \x1b[37m${APP_METADATA.author}\x1b[0m (\x1b[34m${APP_METADATA.email}\x1b[0m)
\x1b[36m║\x1b[0m  \x1b[1mVersion:\x1b[0m     \x1b[32mv${APP_METADATA.version}\x1b[0m \x1b[90m| Released: ${APP_METADATA.versionDate}\x1b[0m
\x1b[36m╚══════════════════════════════════════════════════════════════════════════════╝\x1b[0m`);
}

// ---------------------------------------------------------------------------
// 2. CLI Arguments & Configuration Parsing
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);

function getFormattedTimestamp() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const year = now.getFullYear();
  const month = pad(now.getMonth() + 1);
  const day = pad(now.getDate());
  const hours = pad(now.getHours());
  const minutes = pad(now.getMinutes());
  const seconds = pad(now.getSeconds());
  return `${year}-${month}-${day}_${hours}-${minutes}-${seconds}`;
}

function printHelp() {
  printBanner();
  console.log(`
\x1b[1mUSAGE:\x1b[0m
  node scan_new.js <path-to-scan> [options]

\x1b[1mARGUMENTS:\x1b[0m
  <path-to-scan>          Directory or file to scan (default: current directory '.')

\x1b[1mOPTIONS:\x1b[0m
  -o, --output <file>     JSON report destination path (default: './reports/report_YYYY-MM-DD_HH-mm-ss.json')
  --reports-dir <dir>     Custom reports directory (default: './reports')
  --unmask                Do not mask secret values in the terminal or JSON report
  --severity <level>      Filter scan results by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
  -q, --quiet             Quiet mode (suppress terminal finding summaries)
  -v, --verbose           Verbose output (logs every scanned file)
  -h, --help              Show this help menu and exit

\x1b[1mVIEWING REPORTS:\x1b[0m
  Open \x1b[36mindex.html\x1b[0m in your browser to view and switch between all scan reports.

\x1b[1mEXAMPLES:\x1b[0m
  node scan_new.js .
  node scan_new.js ./src --severity HIGH
  node scan_new.js /var/www/project -o ./reports/my-audit.json
`);
  process.exit(0);
}

if (args.includes('-h') || args.includes('--help')) {
  printHelp();
}

let targetPath = '.';
let customOutput = null;
let customReportsDir = null;
let maskSecrets = true;
let minSeverity = 'LOW';
let quietMode = false;
let verboseMode = false;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--serve') {
    require('./serve.js');
    return;
  } else if (arg === '-o' || arg === '--output') {
    customOutput = args[++i];
  } else if (arg === '--reports-dir') {
    customReportsDir = args[++i];
  } else if (arg === '--unmask') {
    maskSecrets = false;
  } else if (arg === '--severity') {
    minSeverity = (args[++i] || 'LOW').toUpperCase();
  } else if (arg === '-q' || arg === '--quiet') {
    quietMode = true;
  } else if (arg === '-v' || arg === '--verbose') {
    verboseMode = true;
  } else if (!arg.startsWith('-')) {
    targetPath = arg;
  }
}

const resolvedTarget = path.resolve(targetPath);
if (!fs.existsSync(resolvedTarget)) {
  console.error(`\x1b[31m[ERROR] Target path does not exist:\x1b[0m ${resolvedTarget}\n`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// 2. Exclusion Rules
// ---------------------------------------------------------------------------
const EXCLUDE_DIRS = new Set([
  'node_modules', 'dist', 'build', 'target', 'vendor',
  '.git', '.pnpm', 'coverage', '__pycache__', '.idea', '.vscode',
  '.next', '.nuxt', 'out', 'bin', 'obj', '.bundle', '.gradle', '.mvn',
  '.output', 'bundles', 'staticfiles', '.turbo', '.cache',
  '.venv', 'venv', 'env', 'site-packages', '.tox',
  '.terraform', '.yarn', '.npm', '.pnpm-store', 'Pods', '.serverless',
  'reports'
]);

const EXCLUDE_EXTS = new Set([
  // Binaries, Archives & Compiled
  '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.min.js', '.min.css', '.map',
  '.lock', '.lockb', '.lockfile', '.bin', '.exe', '.dll', '.so', '.dylib', '.wasm', '.pak', '.dat',
  // Checksums & State
  '.sum', '.tfstate',
  // Media & Fonts
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif', '.bmp', '.tiff',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.zip', '.tar', '.gz', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
]);

const EXCLUDE_FILES = new Set([
  // Node.js / JS / Bun / Deno
  'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'pnpm-lock.yml', 'bun.lockb', 'bun.lock', 'deno.lock',
  // Python
  'poetry.lock', 'pipfile.lock', 'pdm.lock', 'uv.lock',
  // Rust / Go / PHP / Ruby
  'cargo.lock', 'composer.lock', 'gemfile.lock', 'go.sum', 'gopkg.lock',
  // JVM / Gradle / Maven / Wrappers
  'gradle.lockfile', 'mvnw', 'mvnw.cmd', 'mvnw.ps1', 'gradlew', 'gradlew.bat', 'gradlew.ps1',
  // iOS / CocoaPods / Carthage / Swift / Dart / Elixir
  'podfile.lock', 'package.resolved', 'cartfile.resolved', 'pubspec.lock', 'mix.lock', 'rebar.lock',
  // .NET / NuGet / Infra / Terraform / Helm
  'packages.lock.json', 'flake.lock', '.terraform.lock.hcl', 'chart.lock', 'helm.lock', 'berksfile.lock',
  // Scanner Reports & Self
  path.basename(__filename).toLowerCase(), 'secret-scan-report.html', 'report-viewer.html', 'index.html'
]);

function isExcludedFile(fileName, fullPath = '') {
  const lowerName = fileName.toLowerCase();
  if (EXCLUDE_FILES.has(fileName) || EXCLUDE_FILES.has(lowerName)) return true;
  if (typeof TOML_RULE_FILES !== 'undefined' && (TOML_RULE_FILES.has(fileName) || TOML_RULE_FILES.has(lowerName))) return true;
  
  // HTML / JSON report files generated by scanner
  if (/^secret-scan-report.*\.html$/i.test(fileName)) return true;
  if (/^report.*\.html$/i.test(fileName)) return true;
  if (/^report_.*\.json$/i.test(fileName)) return true;
  if (fileName === 'reports.json') return true;
  
  // Lockfiles & Dependency Checksums (package-lock.json, *.lock, *.lockb, *.lockfile, *.resolved, go.sum, etc.)
  if (/\.lock(b|file)?$/i.test(fileName)) return true;
  if (/[\w.-]*lock\.(json|yaml|yml|hcl)$/i.test(fileName)) return true;
  if (/^(package-lock|packages\.lock|npm-shrinkwrap)\.json$/i.test(fileName)) return true;
  if (/^(package|cartfile)\.resolved$/i.test(fileName)) return true;
  if (/\.(sum|tfstate|tfstate\.backup)$/i.test(fileName)) return true;
  if (/^(checksums|sha256sums|md5sums)\.txt$/i.test(fileName)) return true;
  
  // Build Wrappers & wrapper directories
  if (/^(mvnw|gradlew)(\.cmd|\.bat|\.ps1)?$/i.test(fileName)) return true;
  if (/[/\\](\.mvn|gradle[/\\]wrapper|\.yarn|\.terraform)[/\\]/i.test(fullPath)) return true;
  
  // Minified bundles & hashed chunks
  if (/\.min\.(js|css)$/i.test(fileName)) return true;
  if (/\.(bundle|chunk)\.(js|css)$/i.test(fileName)) return true;
  if (/^[\w-]+-[a-zA-Z0-9_-]{6,}\.(js|css)$/i.test(fileName)) return true;
  
  return false;
}

// ---------------------------------------------------------------------------
// 3. Master Pattern Definitions & Severity Mapping
// ---------------------------------------------------------------------------
const SEVERITY_LEVELS = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1
};

const PATTERNS = [
  // --- Category: Database Credentials & Connection Strings ---
  {
    id: 'DB_CONN_URI',
    name: 'Database Connection URI with Credentials',
    category: 'Database Connection Strings',
    severity: 'CRITICAL',
    description: 'Matches standard database connection strings with embedded plaintext username & password (Postgres, MySQL, Oracle, MSSQL, MongoDB, Redis, etc.).',
    remediation: 'Externalize credentials into environment variables injected at runtime or use a managed Secrets Vault / IAM database authentication.',
    regex: /\b(?:mongodb(?:\+srv)?|postgres|postgresql|mysql|mariadb|oracle|sqlserver|mssql|db2|h2|sqlite|sybase|redis|rediss|amqp|amqps|clickhouse|cassandra|snowflake|redshift|jdbc:(?:oracle|sqlserver|mysql|mariadb|postgresql|postgres|db2|h2|sqlite|sybase|clickhouse|snowflake|redshift|[a-z0-9_-]+):(?:\/\/)?|https?|ftps?):\/\/[^/:?#@\s"'`]+:(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[^/:?#@\s"'`]{3,}@[^\s"'`]+/gi
  },
  {
    id: 'ORACLE_JDBC_URL',
    name: 'Oracle Thin/OCI JDBC URL Credentials',
    category: 'Database Connection Strings',
    severity: 'CRITICAL',
    description: 'Matches Oracle-specific JDBC driver URLs containing embedded user/password combinations.',
    remediation: 'Use Oracle Wallets, connection pooling with environment variables, or JNDI datasource configuration.',
    regex: /\bjdbc:oracle:(?:thin|oci)?:[^\/:?#@\s"'`]+\/(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[^/:?#@\s"'`]{3,}@[^\s"'`]+/gi
  },
  {
    id: 'ADONET_ODBC_CONN',
    name: 'ADO.NET / ODBC Semicolon Connection String',
    category: 'Database Connection Strings',
    severity: 'HIGH',
    description: 'Matches Microsoft SQL Server, Oracle, DB2, and generic ODBC/ADO.NET connection strings containing user credentials.',
    remediation: 'Use Windows Integrated Security (SSPI), Azure Managed Identity, or retrieve connection strings from Azure Key Vault / App Configuration.',
    regex: /(?:\b(?:Data\s*Source|Server|Initial\s*Catalog|Database|jdbc:[a-z0-9_:-]+|Driver|Provider)\b[^;"'\n]*;\s*)*(?:User\s*Id|uid|user|username)\s*=\s*[^;"'\n]*;\s*(?:Password|pwd)\s*=\s*["']?(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[^;"'\s]{3,}["']?/gi
  },
  {
    id: 'DB_CONFIG_PASSWORD_KEY',
    name: 'Database Password Key in Config File',
    category: 'Database Connection Strings',
    severity: 'HIGH',
    description: 'Matches database password keys in configuration files (Spring, Quarkus, .properties, .yaml, .ini).',
    remediation: 'Replace plaintext values with environment variable place-holders like ${DB_PASSWORD}.',
    regex: /(?:datasource|jdbc|db|database|spring\.datasource|oracle|mssql|sqlserver|db2|h2|sqlite|mysql|mariadb|postgres|postgresql|mongodb|redis|cassandra|clickhouse|keystore|truststore)[._-](?:pass(?:word|wd)|pwd|pass[._-]?code|access[._-]?code)\s*[:=]\s*(?!(?:["'`]*\$|#|\s*$|change[_-]?me|your[_-]|example|dummy|placeholder))[^\s#]{3,}/gi,
    fileFilter: (filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      const base = path.basename(filePath).toLowerCase();
      return ext === '.properties' || ext === '.ini' || ext === '.yaml' || ext === '.yml' || ext === '.conf' || ext === '.cfg' || base.startsWith('.env');
    }
  },

  // --- Category: Passwords & Assignments ---
  {
    id: 'HARDCODED_PASSWORD_ASSIGN',
    name: 'Hardcoded Password / Key Variable Assignment',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches variable/key assignments targeting passwords, passcodes, passphrases, and credentials enclosed in quotes.',
    remediation: 'Load credentials dynamically from environment variables or a configuration vault.',
    regex: /(?<!(?:errors?|err|validation|state|msg|message|alert|warning|label|placeholder|title|desc|description)\.)(?:["']?(?:pass(?:word|wd)|pwd|pass[._-]?phrase|pass[._-]?code|access[._-]?code|db[._-]?(?:pass(?:word|wd)?|pwd)|user[._-]?(?:pass(?:word|wd)?|pwd)|admin[._-]?(?:pass(?:word|wd)?|pwd)|root[._-]?(?:pass(?:word|wd)?|pwd)|master[._-]?(?:pass(?:word|wd)?|pwd)|client[._-]?(?:pass(?:word|wd)?|pwd)|auth[._-]?(?:pass(?:word|wd)?|pwd)|keystore[._-]?(?:pass(?:word|wd)?|pwd)|truststore[._-]?(?:pass(?:word|wd)?|pwd))["']?)\s*(?:[:=]|=>|:=)\s*(["'`])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|[^\r\n"']*(?:required|invalid|must\s+be|cannot\s+be|characters|match)|[\^~><=]|\d+(?:px|em|rem|%|vh|vw|pt)\b|\s*\1))([^"'\r\n`]{3,})\1/gi,
    fileFilter: (filePath) => path.basename(filePath).toLowerCase() !== 'package.json'
  },
  {
    id: 'TYPED_PASSWORD_DECLARATION',
    name: 'Strongly-Typed Source Password Declaration',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches strongly-typed variable declarations (String, const, let, final) holding passwords in source code.',
    remediation: 'Remove the hardcoded literal and read from config or system properties.',
    regex: /(?:String|final|const|let|var|val)\s+(?:pass(?:word|wd)|pwd|pass[._-]?phrase|pass[._-]?code|access[._-]?code|db[._-]?(?:pass(?:word|wd)?|pwd)|user[._-]?(?:pass(?:word|wd)?|pwd)|admin[._-]?(?:pass(?:word|wd)?|pwd)|root[._-]?(?:pass(?:word|wd)?|pwd)|secret[._-]?key)\s*=\s*["'](?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[^"'\s]{3,}["']/gi
  },
  {
    id: 'CREDENTIAL_SETTER_CALL',
    name: 'Credential Setter / Method Call with Literal',
    category: 'Passwords & Credentials',
    severity: 'MEDIUM',
    description: 'Matches method calls like setPassword("..."), authenticate("..."), login("...") with inline string constants.',
    remediation: 'Pass runtime credential variables rather than hardcoded string parameters.',
    regex: /\b(?:set|with)(?:Password|Passcode|AccessCode|ClientSecret|SecretKey)\s*\(\s*(?:[a-zA-Z0-9_$]+\s*,\s*)*["'](?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[^"'\s]{3,}["']|\b(?:createCredentials|authenticate|login|getConnection)\s*\(\s*(?:[a-zA-Z0-9_$]+\s*,\s*)*["'](?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[^"'\s]{3,}["']/gi
  },
  {
    id: 'DICT_COLLECTION_SECRET_CALL',
    name: 'Dictionary / Map / Collection Method Call with Secret',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches dictionary/map collection methods (dict.add("key", "val"), dict.put, dict.set, dict.setProperty).',
    remediation: 'Externalize credentials and avoid hardcoding plaintext secrets in collection builders.',
    regex: /\b[a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*\s*\.\s*(?:add|put|set|insert|push|set_secret|add_secret|put_secret|append|setProperty|setAttribute)\s*\(\s*(["'`])(?:[a-zA-Z0-9_\s-]*(?:pass(?:word|wd)?|pwd|pass[._-]?phrase|pass[._-]?code|access[._-]?code|secret(?:[._-]?key)?|api[._-]?(?:key|token|secret)|client[._-]?(?:secret|key)|jwt(?:[._-]?(?:token|secret|key))?|token(?:[._-]?secret)?|auth[._-]?(?:key|token|secret)|encryption[._-]?(?:key|secret)|encrypted[._-]?(?:pass(?:word|wd)?|pwd|key|secret)|master[._-]?key|signing[._-]?key|private[._-]?key|access[._-]?(?:secret|token)|webhook[._-]?secret|session[._-]?secret|service[._-]?(?:key|secret)|db[._-]?(?:pass(?:word|wd)?|pwd)|user[._-]?(?:pass(?:word|wd)?|pwd)|admin[._-]?(?:pass(?:word|wd)?|pwd)|root[._-]?(?:pass(?:word|wd)?|pwd))[a-zA-Z0-9_\s-]*)\1\s*,\s*(["'`])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|[^\r\n"']*(?:required|invalid|must\s+be|cannot\s+be|characters|match)|[\^~><=]|\d+(?:px|em|rem|%|vh|vw|pt)\b|\s*\2))([^\r\n\2]{3,})\2\s*\)/gi,
    fileFilter: (filePath) => path.basename(filePath).toLowerCase() !== 'package.json'
  },
  {
    id: 'DICT_SUBSCRIPT_ASSIGNMENT',
    name: 'Dictionary / Map Subscript Index Secret Assignment',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches dictionary/map indexing assignments (dict["password"] = "secret", dict["encryptedKey"] = "val").',
    remediation: 'Load secret values from environment variables or secure storage.',
    regex: /\b[a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*\s*\[\s*(["'`])(?:[a-zA-Z0-9_\s-]*(?:pass(?:word|wd)?|pwd|pass[._-]?phrase|pass[._-]?code|access[._-]?code|secret(?:[._-]?key)?|api[._-]?(?:key|token|secret)|client[._-]?(?:secret|key)|jwt(?:[._-]?(?:token|secret|key))?|token(?:[._-]?secret)?|auth[._-]?(?:key|token|secret)|encryption[._-]?(?:key|secret)|encrypted[._-]?(?:pass(?:word|wd)?|pwd|key|secret)|master[._-]?key|signing[._-]?key|private[._-]?key|access[._-]?(?:secret|token)|webhook[._-]?secret|session[._-]?secret|service[._-]?(?:key|secret)|db[._-]?(?:pass(?:word|wd)?|pwd)|user[._-]?(?:pass(?:word|wd)?|pwd)|admin[._-]?(?:pass(?:word|wd)?|pwd)|root[._-]?(?:pass(?:word|wd)?|pwd))[a-zA-Z0-9_\s-]*)\1\s*\]\s*=\s*(["'`])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|[^\r\n"']*(?:required|invalid|must\s+be|cannot\s+be|characters|match)|[\^~><=]|\d+(?:px|em|rem|%|vh|vw|pt)\b|\s*\2))([^\r\n\2]{3,})\2/gi,
    fileFilter: (filePath) => path.basename(filePath).toLowerCase() !== 'package.json'
  },

  // --- Category: Cloud Providers, LLMs & Well-Known SaaS ---
  {
    id: 'AWS_ACCESS_KEY_ID',
    name: 'AWS Access Key ID',
    category: 'Cloud & SaaS API Keys',
    severity: 'CRITICAL',
    description: 'Matches standard 20-character AWS Access Key IDs (AKIA...).',
    remediation: 'Revoke and rotate the compromised AWS IAM access key immediately in AWS IAM Console.',
    regex: /\bAKIA[0-9A-Z]{16}\b/g
  },
  {
    id: 'AWS_SECRET_KEY_ASSIGN',
    name: 'AWS Secret Access Key Assignment',
    category: 'Cloud & SaaS API Keys',
    severity: 'CRITICAL',
    description: 'Matches assignments of 40-character AWS Secret Access Keys.',
    remediation: 'Rotate the corresponding AWS IAM Access Key and migrate to AWS IAM Roles for EC2/ECS/Lambda.',
    regex: /(?:aws[._-]?secret[._-]?(?:access[._-]?)?key|AWS[._-]?SECRET[._-]?(?:ACCESS[._-]?)?KEY)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi
  },
  {
    id: 'GITHUB_TOKEN',
    name: 'GitHub Personal Access / OAuth Token',
    category: 'Cloud & SaaS API Keys',
    severity: 'CRITICAL',
    description: 'Matches classic GitHub PATs (ghp_), fine-grained tokens (github_pat_), OAuth (gho_), and server tokens (ghs_).',
    remediation: 'Revoke this token in GitHub Settings -> Developer Settings -> Personal Access Tokens.',
    regex: /\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g
  },
  {
    id: 'LLM_PROVIDER_KEY',
    name: 'LLM Provider API Key (OpenAI, Anthropic, HuggingFace, Gemini)',
    category: 'Cloud & SaaS API Keys',
    severity: 'CRITICAL',
    description: 'Matches API key signatures for OpenAI (sk-proj-...), Anthropic (sk-ant-...), HuggingFace (hf_...), and Google Gemini / Cloud (AIza...).',
    remediation: 'Revoke and rotate the API key in the respective AI provider developer dashboard.',
    regex: /\bsk-(?:proj-|svcacct-)?[a-zA-Z0-9_\-]{32,}\b|\bsk-ant-(?:api[0-9]{2}-)?[a-zA-Z0-9_\-]{32,}\b|\bhf_[a-zA-Z0-9]{34,}\b|\bAIza[0-9A-Za-z-_]{35}\b/g
  },
  {
    id: 'GENERIC_LLM_KEY_ASSIGN',
    name: 'Generic LLM Provider Key Assignment',
    category: 'Cloud & SaaS API Keys',
    severity: 'HIGH',
    description: 'Matches explicit assignments to OpenAI, Anthropic, Cohere, Replicate, or LLM token variables.',
    remediation: 'Inject LLM keys via environment variables (e.g. process.env.OPENAI_API_KEY).',
    regex: /(?:openai|anthropic|cohere|replicate|huggingface|llm)[._-]*(?:api[._-]*)?(?:key|token|secret)\s*[:=]\s*["'](?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[a-zA-Z0-9_\-]{16,}["']/gi
  },
  {
    id: 'SAAS_TOKEN_THIRD_PARTY',
    name: 'Third-Party SaaS Token (Slack, Stripe, NPM, SendGrid)',
    category: 'Cloud & SaaS API Keys',
    severity: 'CRITICAL',
    description: 'Matches tokens for Slack (xoxb/xopp/xoxs), Stripe (sk_live/test), NPM (npm_), and SendGrid (SG.).',
    remediation: 'Rotate the third-party SaaS credentials in your service dashboard.',
    regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b|\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b|\bnpm_[a-zA-Z0-9]{36}\b|\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b/g
  },
  {
    id: 'ARTIFACTORY_JFROG_NEXUS',
    name: 'Artifactory / JFrog / Nexus Token',
    category: 'Cloud & SaaS API Keys',
    severity: 'HIGH',
    description: 'Matches JFrog/Artifactory API keys (AKCp...), reference tokens (cmVmd...), scoped access tokens, Nexus credentials, and package repository credential variables.',
    remediation: 'Revoke and rotate package registry tokens and configure credentials via ~/.npmrc or ~/.m2/settings.xml using CI secrets.',
    regex: /\bAKCp[a-zA-Z0-9]{60,80}\b|\bcmVmd[a-zA-Z0-9+/=]{59,}\b|\bjfx_[a-zA-Z0-9_\-]{30,}\b|(?:artifactory|jfrog|nexus|bintray)[._-]*(?:api[._-]*)?(?:key|token|password|secret|pwd)\s*[:=]\s*["']?(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))[a-zA-Z0-9_\-\.\+/=]{8,}["']?|<(?:artifactory|jfrog|nexus)[._-]*(?:api[._-]*)?(?:key|token|password|secret|pwd)\b[^>]*>(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*<))([^<\r\n]{6,})<\/(?:artifactory|jfrog|nexus)[._-]*(?:api[._-]*)?(?:key|token|password|secret|pwd)>/gi
  },
  {
    id: 'XML_CONFIG_CREDENTIAL',
    name: 'XML / Ant Build Configuration Password or Secret',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches passwords, API keys, tokens, keystore passwords, and secrets configured inside XML and build elements (Ant build.xml, Ivy ivysettings.xml, Maven settings.xml, pom.xml, Spring XML, Jenkins credentials, ASP.NET Web.config, NuGet.config, Tomcat server.xml).',
    remediation: 'Externalize credentials from XML files using environment variable placeholders (e.g. ${env.PASSWORD}) or a centralized secrets store.',
    regex: /<(?:password|passwd|passphrase|secret(?:[._-]?key)?|api[._-]?(?:key|token)|client[._-]?secret|access[._-]?(?:key|secret|token)|auth[._-]?(?:token|secret|key)|private[._-]?key|master[._-]?password|proxy[._-]?password|keystore[._-]?password|truststore[._-]?password|storepass|keypass|bind[._-]?password|db[._-]?password|connection[._-]?password|artifactory[._-]?(?:key|token|password)|jfrog[._-]?(?:key|token|password)|nexus[._-]?(?:key|token|password))\b[^>]*>(?!(?:["'`]*\$|\{\{|\{\#[^}]*\}|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*<))([^<\r\n]{3,})<\/(?:password|passwd|passphrase|secret(?:[._-]?key)?|api[._-]?(?:key|token)|client[._-]?secret|access[._-]?(?:key|secret|token)|auth[._-]?(?:token|secret|key)|private[._-]?key|master[._-]?password|proxy[._-]?password|keystore[._-]?password|truststore[._-]?password|storepass|keypass|bind[._-]?password|db[._-]?password|connection[._-]?password|artifactory[._-]?(?:key|token|password)|jfrog[._-]?(?:key|token|password)|nexus[._-]?(?:key|token|password))>|<(?:property|param)\s+[^>]*name=["'](?:[a-zA-Z0-9._-]*(?:password|passwd|passphrase|secret|apiKey|api_key|token|accessKey|privateKey|artifactory|nexus|storepass|keypass)[a-zA-Z0-9._-]*)["']\s+value=["'](?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder))([^"'\r\n]{3,})["']|\b(?:password|passwd|passphrase|storepass|keypass|secret|apiKey|api_key|api-key|clientSecret|client_secret|accessKey|access_key|authToken|auth_token|artifactoryKey|artifactoryToken|jfrogToken|clearTextPassword)\s*=\s*(["'])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))([^"'\r\n]{3,})\1/gi,
    fileFilter: (filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      const base = path.basename(filePath).toLowerCase();
      return ['.xml', '.config', '.pom', '.xaml', '.axml', '.plist', '.xsd', '.wsdl', '.ant', '.ivysettings'].includes(ext) ||
             base === 'build.xml' || base === 'ivysettings.xml' || base === 'ivy.xml' || base === 'pom.xml' || base === 'settings.xml';
    }
  },
  {
    id: 'GRADLE_BUILD_CREDENTIAL',
    name: 'Gradle Build Script Credential / Signing Password',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches hardcoded repository credentials, keystore passwords, API tokens, and signing secrets in Gradle build scripts (build.gradle, build.gradle.kts, settings.gradle, init.gradle).',
    remediation: 'Externalize Gradle secrets into gradle.properties (excluded from git) or inject via environment variables (System.getenv("...")) / CI secrets.',
    regex: /\b(?:password|passwd|passphrase|storePassword|keyPassword|secretKey|signingPassword|artifactoryPassword|nexusPassword|authToken|apiKey|apiToken|secret)\s*(?:=|:|\s)\s*(["'])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))([^"'\r\n]{3,})\1|\b(?:password|passwd|storePassword|keyPassword|setPassword|setStorePassword|setKeyPassword)\s*\(\s*(["'])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|\s*["']))([^"'\r\n]{3,})\1\s*\)/gi,
    fileFilter: (filePath) => {
      const base = path.basename(filePath).toLowerCase();
      return base.endsWith('.gradle') || base.endsWith('.gradle.kts') || base.startsWith('gradle.properties') || base === 'build.gradle' || base === 'settings.gradle';
    }
  },
  {
    id: 'MAVEN_ENCRYPTED_PASSWORD',
    name: 'Maven Encrypted Password / Master Password',
    category: 'Passwords & Credentials',
    severity: 'MEDIUM',
    description: 'Matches Maven master passwords or encrypted server passwords ({...}) in settings.xml and settings-security.xml.',
    remediation: 'Ensure settings-security.xml and encrypted credentials are not stored in shared repositories.',
    regex: /<(?:password|master)\b[^>]*>(\{[a-zA-Z0-9+/=]{16,\}\})<\/(?:password|master)>/gi
  },
  {
    id: 'PACKAGE_REGISTRY_CONFIG_SECRET',
    name: 'Package Registry Config Secret (.npmrc, gradle.properties, .pypirc, NuGet)',
    category: 'Cloud & SaaS API Keys',
    severity: 'HIGH',
    description: 'Matches hardcoded authentication tokens and repository credentials in .npmrc, .yarnrc, gradle.properties, .pypirc, and NuGet configuration files.',
    remediation: 'Inject repository tokens via environment variables in CI/CD pipelines (e.g. NPM_TOKEN, ARTIFACTORY_TOKEN) rather than saving in dotfiles.',
    regex: /(?:\/\/[^\s\/:@]+(?:\/[^\s:@]*)?:_authToken\s*=\s*|_authToken\s*=\s*|_auth\s*=\s*|_password\s*=\s*|(?:artifactory|nexus|sonatype|bintray|pypi|nuget|github|gitlab)[._-]*(?:password|pass|pwd|key|token|secret|apiKey)\s*=\s*)(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder))[^\s#]{4,}/gi
  },
  {
    id: 'APPDYNAMICS_KEY',
    name: 'AppDynamics Agent Account Access Key',
    category: 'Cloud & SaaS API Keys',
    severity: 'MEDIUM',
    description: 'Matches AppDynamics APM agent account access key assignments.',
    remediation: 'Store the AppDynamics account access key in APM configuration files outside source control.',
    regex: /(?:appdynamics|appd)[._-]*(?:agent[._-]*)?(?:account[._-]*)?(?:access[._-]*)?key\s*[:=]\s*["']?[a-zA-Z0-9_\-]{20,}["']?|appdynamics\.agent\.accountAccessKey\s*=\s*[^\s#]+/gi
  },

  // --- Category: Generic Developer Secrets & Tokens ---
  {
    id: 'GENERIC_DEV_SECRET',
    name: 'Generic Developer Secret / Token / API Key',
    category: 'Generic Developer Secrets',
    severity: 'HIGH',
    description: 'Matches variable/key assignments targeting secrets, API keys, JWT tokens, access tokens, and developer credentials enclosed in quotes.',
    remediation: 'Audit the purpose of this key, replace with a secure config loader, and rotate if exposed in git.',
    regex: /(?:["']?(?:token|jwt(?:[._-]?(?:token|secret|key))?|secret(?:[._-]?key)?|api[._-]?(?:key|token|secret)|client[._-]?(?:secret|key)|master[._-]?key|encryption[._-]?key|signing[._-]?key|private[._-]?key|access[._-]?(?:secret|token)|webhook[._-]?secret|session[._-]?secret|auth[._-]?(?:key|token|secret)|token[._-]?secret|service[._-]?(?:key|secret))["']?)\s*(?:[:=]|=>|:=)\s*(["'`])(?!(?:["'`]*\$|\{\{|<|TODO|change[_-]?me|your[_-]|example|dummy|placeholder|required|invalid|must\s+be|cannot\s+be|[\^~><=]|\d+(?:px|em|rem|%|vh|vw|pt)\b|\s*\1))([^"'\r\n`]{3,})\1/gi,
    fileFilter: (filePath) => path.basename(filePath).toLowerCase() !== 'package.json'
  },

  // --- Category: Authentication Tokens & Cryptographic Hashes ---
  {
    id: 'JWT_TOKEN',
    name: 'Raw JSON Web Token (JWT)',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'HIGH',
    description: 'Matches three-part Base64URL-encoded JWT strings (eyJ...).',
    remediation: 'Ensure test or session tokens are not hardcoded in source files. Expire the token if production data is contained.',
    regex: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b/g
  },
  {
    id: 'BEARER_AUTH_HEADER',
    name: 'Bearer Authorization Header / Variable',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'HIGH',
    description: 'Matches hardcoded Bearer token headers in HTTP requests or client configs.',
    remediation: 'Fetch OAuth/OIDC access tokens dynamically at runtime.',
    regex: /(?:Authorization\s*[:=]\s*["']?Bearer\s+|Bearer\s+)eyJ[A-Za-z0-9-_=]{10,}/gi
  },
  {
    id: 'BCRYPT_HASH',
    name: 'Bcrypt Password Hash',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'MEDIUM',
    description: 'Matches modular crypt format Bcrypt password hashes ($2a$, $2b$, $2y$).',
    remediation: 'Store hashed credentials in the database rather than hardcoding in seed files or source code.',
    regex: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g
  },
  {
    id: 'SHA_CREDENTIAL_HASH',
    name: 'SHA-256 / SHA-512 Hash Assigned to Secret Field',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'MEDIUM',
    description: 'Matches 64-char (SHA-256) or 128-char (SHA-512) hexadecimal digests assigned to password or secret properties.',
    remediation: 'Avoid hardcoded password hashes in configuration.',
    regex: /(?:pass(?:word|wd)|pwd|pass[._-]?code|access[._-]?code|secret|pass[._-]?phrase|api[._-]?key)\s*[:=]\s*["'](?:[a-fA-F0-9]{64}|[a-fA-F0-9]{128})["']/gi
  },
  {
    id: 'MD5_SHA1_CREDENTIAL_HASH',
    name: 'MD5 / SHA-1 Hash Assigned to Secret Field',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'LOW',
    description: 'Matches 32-char (MD5) or 40-char (SHA-1) hashes assigned to secret fields.',
    remediation: 'MD5 and SHA-1 are cryptographically broken. Migrate to modern password hashing (Argon2id, Bcrypt) and store in database.',
    regex: /(?:pass(?:word|wd)|pwd|pass[._-]?code|access[._-]?code|secret|pass[._-]?phrase)\s*[:=]\s*["'](?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40})["']/gi
  },
  {
    id: 'BASIC_AUTH_HEADER',
    name: 'HTTP Basic Auth Header / Variable',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'HIGH',
    description: 'Matches Base64-encoded username:password pairs in Authorization: Basic headers.',
    remediation: 'Replace hardcoded Basic auth headers with dynamic token generation or environment configuration.',
    regex: /(?:Authorization\s*[:=]\s*["']?Basic\s+|Basic\s+)[A-Za-z0-9+/]{16,}={0,2}/gi
  },
  {
    id: 'BASE64_SECRET_VAR',
    name: 'Explicit Base64 Secret Variable Assignment',
    category: 'Auth Tokens & Cryptographic Hashes',
    severity: 'MEDIUM',
    description: 'Matches Base64-encoded secret and key variable definitions.',
    remediation: 'Ensure encoded keys are stored in secure key management services.',
    regex: /(?:base64[._-]?secret|encoded[._-]?password|base64[._-]?key)\s*[:=]\s*["'][A-Za-z0-9+/]{20,}={0,2}["']/gi
  },

  // --- Category: Committed Environment Files ---
  {
    id: 'COMMITTED_ENV_SECRET',
    name: 'Committed .env Variable Secret',
    category: 'Environment Variables',
    severity: 'HIGH',
    description: 'Matches sensitive variable names (PASS, SECRET, KEY, TOKEN) in committed .env files with values >= 6 chars.',
    remediation: 'Add .env files to .gitignore and distribute secrets via environment templates (.env.example) and CI/CD secret stores.',
    regex: /^(?:[A-Z0-9_]*(?:PASS(?:WORD|WD)?|PASS[._-]?CODE|ACCESS[._-]?CODE|SECRET|API[._-]?KEY|TOKEN|PRIVATE[._-]?KEY|AUTH[._-]?KEY|ARTIFACTORY|JFROG|NEXUS)[A-Z0-9_]*)\s*=\s*(?!(?:["'`]*\$|\{\{|#|\s*$|change[_-]?me|default|your[_-]|example|dummy|placeholder|<|TODO))[^\s#]{6,}/gm,
    fileFilter: (filePath) => {
      const base = path.basename(filePath).toLowerCase();
      return base.startsWith('.env') || filePath.endsWith('.env');
    }
  },

  // --- Category: Private Keys & Certificates ---
  {
    id: 'PRIVATE_KEY_PEM',
    name: 'PEM-Encoded Private Key',
    category: 'Private Keys & Certificates',
    severity: 'CRITICAL',
    description: 'Matches PEM-encoded private key blocks (RSA, EC, DSA, PKCS8, SSH, PGP). Inline private keys in source code or config files are a critical security risk.',
    remediation: 'Remove the private key from source, revoke/rotate the key pair, and store in a secure key management system (AWS KMS, HashiCorp Vault, Azure Key Vault).',
    regex: /-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|PGP\s+|ENCRYPTED\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----/g
  },

  // --- Category: Cloud & SaaS API Keys (Extended) ---
  {
    id: 'GCP_SERVICE_ACCOUNT',
    name: 'Google Cloud Service Account Key File',
    category: 'Cloud & SaaS API Keys',
    severity: 'CRITICAL',
    description: 'Matches Google Cloud service account JSON key files containing project IDs and embedded private keys.',
    remediation: 'Delete the service account key from GCP IAM console, remove from source, use Workload Identity Federation instead.',
    regex: /"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"/g
  },
  {
    id: 'AZURE_SUBSCRIPTION_KEY',
    name: 'Azure Cognitive Services / Subscription Key',
    category: 'Cloud & SaaS API Keys',
    severity: 'HIGH',
    description: 'Matches Azure subscription keys and Cognitive Services API keys assigned in code or config.',
    remediation: 'Rotate the Azure subscription key and use Azure Key Vault for secret management.',
    regex: /(?:azure|az)[._-]*(?:subscription|cognitive|search|openai)[._-]*(?:api[._-]*)?key\s*[:=]\s*["'][a-fA-F0-9]{32}["']/gi
  },
  {
    id: 'SAAS_TOKEN_EXTENDED',
    name: 'Extended SaaS Token (Twilio, Mailgun, Datadog, Sentry, PyPI)',
    category: 'Cloud & SaaS API Keys',
    severity: 'HIGH',
    description: 'Matches well-known token formats for Twilio Account SID, Mailgun, Datadog, Sentry, and other popular SaaS services.',
    remediation: 'Rotate the token in the respective SaaS provider dashboard and use environment variables.',
    regex: /\bAC[a-f0-9]{32}\b|\b(?:twilio|mailgun|datadog|sentry|newrelic)[._-]*(?:api[._-]*)?(?:key|token|secret)\s*[:=]\s*["']?[a-zA-Z0-9_\-]{20,}["']?/gi
  },

  // --- Category: Infrastructure as Code ---
  {
    id: 'TERRAFORM_HARDCODED_SECRET',
    name: 'Terraform / IaC Hardcoded Secret Default',
    category: 'Infrastructure as Code',
    severity: 'HIGH',
    description: 'Matches Terraform variable defaults and provider blocks containing hardcoded passwords, tokens, or secrets.',
    remediation: 'Use terraform.tfvars, environment variables, or a secrets manager. Never set default values for sensitive variables.',
    regex: /variable\s+["'][^"']*(?:password|secret|token|key|credential)[^"']*["']\s*\{[^}]*default\s*=\s*["'](?!(?:\$\{|change[_-]?me|your[_-]|example|dummy|placeholder))[^"']{3,}["']/gi,
    fileFilter: (filePath) => /\.(tf|hcl|tfvars)$/i.test(path.extname(filePath))
  },
  {
    id: 'DOCKER_HARDCODED_SECRET',
    name: 'Dockerfile / Docker Compose Hardcoded Secret',
    category: 'Infrastructure as Code',
    severity: 'HIGH',
    description: 'Matches hardcoded passwords/tokens in Dockerfile ARG/ENV instructions and docker-compose environment blocks.',
    remediation: 'Use Docker secrets, build-time secret mounts (--mount=type=secret), or .env files excluded from version control.',
    regex: /(?:ARG|ENV)\s+[A-Z_]*(?:PASS(?:WORD|WD)?|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Z_]*\s*=\s*(?!(?:\$\{|change[_-]?me|your[_-]|example|dummy|placeholder))[^\s#]{3,}/gi,
    fileFilter: (filePath) => {
      const base = path.basename(filePath).toLowerCase();
      return base.startsWith('dockerfile') || /^docker-compose.*\.(yml|yaml)$/i.test(base);
    }
  },
  {
    id: 'CICD_INLINE_SECRET',
    name: 'CI/CD Pipeline Inline Secret',
    category: 'Infrastructure as Code',
    severity: 'HIGH',
    description: 'Matches hardcoded secrets in GitHub Actions, GitLab CI, Jenkins, and CircleCI pipeline environment definitions.',
    remediation: 'Use CI/CD platform secret stores (GitHub Secrets, GitLab CI Variables, Jenkins Credentials) instead of inline values.',
    regex: /^[ \t]*[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z_]*\s*:\s*["']?(?!(?:\$\{|\$\{\{|change[_-]?me|your[_-]|example|dummy|placeholder|["']\s*$))[^\s#"']{6,}["']?/gm,
    fileFilter: (filePath) => {
      const base = path.basename(filePath).toLowerCase();
      const dir = filePath.replace(/\\/g, '/');
      return base === '.gitlab-ci.yml' || base === 'jenkinsfile' ||
             (base.endsWith('.yml') || base.endsWith('.yaml')) && (dir.includes('.github/') || dir.includes('.circleci/'));
    }
  },

  // --- Category: Passwords & Credentials (Extended) ---
  {
    id: 'SSH_PASSWORD_INLINE',
    name: 'SSH Inline Password (sshpass / expect)',
    category: 'Passwords & Credentials',
    severity: 'HIGH',
    description: 'Matches sshpass commands or expect scripts with inline SSH passwords.',
    remediation: 'Use SSH key-based authentication instead of password-based access.',
    regex: /sshpass\s+-p\s*['"]?(?!\$\{)[^\s'"]{3,}['"]?\s+ssh/gi
  },

  // --- Category: Credentials in Logs ---
  {
    id: 'SECRET_IN_LOG_STATEMENT',
    name: 'Secret / Password Exposed in Log or Console Statement',
    category: 'Credentials in Logs',
    severity: 'CRITICAL',
    description: 'Matches passwords, secrets, tokens, or API keys being printed to console, logger, or standard output. This exposes credentials in log files, monitoring dashboards, and terminal history.',
    remediation: 'Remove the log statement or mask the sensitive value before logging. Never log credentials, even in debug mode.',
    regex: /\b(?:console\.(?:log|info|warn|error|debug|trace)|logger?\.(?:log|info|warn|error|debug|trace|fatal)|log\.(?:info|warn|error|debug|trace|fatal)|System\.out\.print(?:ln)?|System\.err\.print(?:ln)?|print(?:ln|f)?|puts|NSLog|Log\.(?:d|i|w|e|v)|logging\.(?:info|warn|error|debug|warning|critical))\s*\(\s*(?:[^)]*\b(?:pass(?:word|wd)|pwd|secret(?:[._-]?key)?|(?:api|auth|access)[._-]?(?:key|token|secret)|private[._-]?key|credentials?|client[._-]?secret)\b[^)]*)/gi,
    fileFilter: (filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      return ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.py', '.go', '.rs', '.cs', '.rb', '.php', '.kt', '.swift', '.scala', '.sh'].includes(ext);
    }
  }
];

// ---------------------------------------------------------------------------
// 3.1 Gitleaks & External TOML Rules Loader
// ---------------------------------------------------------------------------

/**
 * Derives a human-readable Category name based on the TOML filename:
 * - 'gitleaks.toml' -> 'Gitleaks Rules'
 * - 'custom-gitleaks-rules.toml' -> 'Custom Gitleaks Rules'
 * - '<name>.toml' -> '<Name> Rules'
 */
function getCategoryForTomlFile(fileName) {
  const base = path.basename(fileName, path.extname(fileName));
  if (base.toLowerCase() === 'gitleaks') {
    return 'Gitleaks Rules';
  }
  const words = base.split(/[-_.]+/).filter(Boolean);
  const formatted = words.map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
  if (/rules$/i.test(formatted)) {
    return formatted;
  }
  return `${formatted} Rules`;
}

/**
 * Converts Go PCRE/TOML regex patterns into compatible JavaScript RegExp objects.
 */
function cleanGoRegex(rawPattern) {
  let p = rawPattern;
  let isCaseInsensitive = false;

  // Handle (?i) flags
  if (p.includes('(?i)') || p.startsWith('(?i)')) {
    isCaseInsensitive = true;
    p = p.replace(/\(\?i\)/g, '');
  }

  // Handle (?i:...) and (?-i:...) inline flag modifiers
  p = p.replace(/\(\?i:([^)]+)\)/g, '$1');
  p = p.replace(/\(\?-i:([^)]+)\)/g, '$1');

  // Replace Python/Go (?P<name>...) named capture groups with JS (?<name>...)
  p = p.replace(/\(\?P<([a-zA-Z0-9_]+)>/g, '(?<$1>');

  // Replace POSIX character classes
  p = p.replace(/\[\[:alnum:\]\]/g, '[a-zA-Z0-9]');
  p = p.replace(/\[\[:alpha:\]\]/g, '[a-zA-Z]');
  p = p.replace(/\[\[:digit:\]\]/g, '[0-9]');
  p = p.replace(/\[\[:xdigit:\]\]/g, '[0-9a-fA-F]');
  p = p.replace(/\[\[:space:\]\]/g, '[ \\t\\r\\n\\v\\f]');

  // Replace \z with $ (end of string)
  p = p.replace(/\\z/g, '$');

  return { pattern: p, flags: isCaseInsensitive ? 'gi' : 'g' };
}

/**
 * Parses all [[rules]] from a Gitleaks or compatible TOML rule configuration file.
 */
function parseGitleaksToml(content, fileName = 'gitleaks.toml') {
  const rules = [];
  const categoryName = getCategoryForTomlFile(fileName);
  const ruleBlocks = content.split(/\[\[rules\]\]/);

  for (let i = 1; i < ruleBlocks.length; i++) {
    const block = ruleBlocks[i];
    const idMatch = block.match(/^\s*id\s*=\s*["']([^"']+)["']/m);
    const descMatch = block.match(/^\s*description\s*=\s*["']([^"']+)["']/m);

    // Regex pattern (supports ''', """, ', or ")
    let regexStr = null;
    const rawRegexMatch = block.match(/^\s*regex\s*=\s*(?:'''([\s\S]*?)'''|"""([\s\S]*?)"""|'([^'\r\n]*)'|"([^"\r\n]*)")/m);
    if (rawRegexMatch) {
      regexStr = rawRegexMatch[1] || rawRegexMatch[2] || rawRegexMatch[3] || rawRegexMatch[4] || null;
    }

    // Path pattern filter (optional)
    const pathMatch = block.match(/^\s*path\s*=\s*(?:'''([\s\S]*?)'''|"""([\s\S]*?)"""|'([^'\r\n]*)'|"([^"\r\n]*)")/m);

    // Secret capture group index (optional)
    const secretGroupMatch = block.match(/^\s*secretGroup\s*=\s*(\d+)/m);

    // Keywords pre-filter (optional)
    const keywordsMatch = block.match(/^\s*keywords\s*=\s*\[([\s\S]*?)\]/m);
    let keywords = [];
    if (keywordsMatch) {
      const kwContent = keywordsMatch[1];
      const kwMatches = kwContent.match(/["']([^"']+)["']/g);
      if (kwMatches) {
        keywords = kwMatches.map(k => k.replace(/^["']|["']$/g, '').toLowerCase());
      }
    }

    if (idMatch && regexStr) {
      const ruleId = idMatch[1].trim();
      const description = descMatch ? descMatch[1].trim() : `Detected match for rule ${ruleId}`;
      const pathStr = pathMatch ? (pathMatch[1] || pathMatch[2] || pathMatch[3] || pathMatch[4] || '').trim() : null;
      const secretGroup = secretGroupMatch ? parseInt(secretGroupMatch[1], 10) : null;

      try {
        const { pattern, flags } = cleanGoRegex(regexStr.trim());
        const compiledRegex = new RegExp(pattern, flags);

        let compiledPathRegex = null;
        if (pathStr) {
          const cleanedPath = cleanGoRegex(pathStr);
          compiledPathRegex = new RegExp(cleanedPath.pattern, cleanedPath.flags.replace('g', ''));
        }

        const formattedName = ruleId.replace(/[-_]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

        rules.push({
          id: `TOML_${ruleId.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}`,
          gitleaksId: ruleId,
          name: formattedName,
          category: categoryName,
          severity: 'HIGH',
          description: description,
          remediation: `Audit and revoke exposed credentials matching rule '${ruleId}'. Externalize sensitive tokens using environment variables.`,
          regex: compiledRegex,
          pathRegex: compiledPathRegex,
          keywords: keywords,
          secretGroup: secretGroup,
          sourceToml: fileName
        });
      } catch (err) {
        // Graceful handling of unsupported PCRE edge-cases
      }
    }
  }
  return rules;
}

/**
 * Discovers and parses all *.toml rule files located in the project root directory.
 */
function discoverAndLoadTomlRules(rootDir) {
  const loadedRules = [];
  const tomlSummaries = [];
  const tomlFileNames = new Set();

  try {
    if (fs.existsSync(rootDir)) {
      const files = fs.readdirSync(rootDir);
      const tomlFiles = files.filter(f => f.toLowerCase().endsWith('.toml'));

      for (const tomlFile of tomlFiles) {
        const fullTomlPath = path.join(rootDir, tomlFile);
        try {
          const stat = fs.statSync(fullTomlPath);
          if (!stat.isFile()) continue;
          const content = fs.readFileSync(fullTomlPath, 'utf8');
          const rules = parseGitleaksToml(content, tomlFile);
          if (rules.length > 0) {
            loadedRules.push(...rules);
            tomlSummaries.push({
              file: tomlFile,
              count: rules.length,
              category: rules[0].category
            });
            tomlFileNames.add(tomlFile.toLowerCase());
          }
        } catch (err) {
          console.error(`\x1b[33m[WARNING] Could not parse TOML file ${tomlFile}:\x1b[0m ${err.message}`);
        }
      }
    }
  } catch (err) {
    console.error(`\x1b[33m[WARNING] Error discovering *.toml files:\x1b[0m ${err.message}`);
  }

  return { rules: loadedRules, summaries: tomlSummaries, fileNames: tomlFileNames };
}

// Discover and initialize rules from all *.toml files in the project root
const { rules: TOML_RULES, summaries: TOML_RULE_SUMMARIES, fileNames: TOML_RULE_FILES } = discoverAndLoadTomlRules(__dirname);
const ALL_PATTERNS = [...PATTERNS, ...TOML_RULES];

// ---------------------------------------------------------------------------
// 4. Utility Functions: Secret Masking, Context Extraction & Smart Tagging
// ---------------------------------------------------------------------------

/**
 * Determines the source type of a file for smart tagging in findings.
 * Returns 'example' for example/sample/template files, 'test' for test/spec files, 'source' otherwise.
 */
function getSourceType(filePath) {
  const base = path.basename(filePath).toLowerCase();
  // Example / sample / template files
  if (/\.(example|sample|template)$/i.test(base) ||
      /[._-](example|sample|template)\./i.test(base) ||
      base.includes('.example') || base.includes('.sample') || base.includes('.template')) {
    return 'example';
  }
  // Test / spec / fixture files
  if (/\.(test|spec)\./i.test(base) ||
      /[\\/](test|tests|__tests__|__mocks__|spec|specs|fixtures)[\\/]/i.test(filePath) ||
      /\.(test|spec)$/i.test(base.replace(path.extname(base), ''))) {
    return 'test';
  }
  return 'source';
}

/**
 * Checks if a line of code is commented out.
 * Returns true for lines starting with //, #, *, /*, <!--, --, %, ;; , REM
 */
function isCommentLine(lineText) {
  const trimmed = lineText.trim();
  return /^(?:\/\/|#(?!!)|\/\*|\*\s|\*\/|<!--|--\s|%|;;\s|REM\s)/i.test(trimmed);
}

/**
 * Determines if a matched value is descriptive text rather than a real secret.
 * A string with 4+ space-separated words is almost certainly a message, not a credential.
 * Also matches common validation/description keywords.
 */
function isDescriptiveText(matchedValue) {
  // Extract the value portion from the match (after = or : and inside quotes)
  const valueMatch = matchedValue.match(/[:=]\s*["'`]([^"'`]+)["'`]/) ||
                     matchedValue.match(/[:=]\s*(.+)$/);
  if (!valueMatch) return false;
  const clean = valueMatch[1].trim();

  // Count words (space-separated tokens)
  const wordCount = clean.split(/\s+/).filter(w => w.length > 0).length;
  if (wordCount >= 4) return true;

  // Check for validation/descriptive keywords
  const descriptivePatterns = /\b(?:must\s+contain|should\s+be|at\s+least|cannot\s+be|is\s+required|is\s+not\s+valid|characters?\s+long|minimum\s+length|maximum\s+length|not\s+provided|enter\s+your|provide\s+a|please\s+enter|type\s+your)\b/i;
  return descriptivePatterns.test(clean);
}

/**
 * Returns source note text based on the sourceType.
 */
function getSourceNote(sourceType) {
  if (sourceType === 'example') {
    return '⚠️ Found in an example/template file — these files are often committed by mistake and must not contain real secrets.';
  }
  if (sourceType === 'test') {
    return '🧪 Found in a test/spec file. Test credentials pointing to real databases are a risk — verify these are truly mock values.';
  }
  return null;
}

/**
 * Determines if a log/console statement is actually logging a secret variable,
 * NOT just mentioning the word "password" in a descriptive string message.
 * 
 * True positive:  console.log("Password:", password)             — 'password' is a variable outside quotes
 * True positive:  console.log(password)                          — 'password' is a variable
 * True positive:  console.log(`Token: ${token}`)                 — 'token' is in template interpolation
 * True positive:  logger.info("Key: " + apiKey)                  — 'apiKey' is outside quotes after +
 * True positive:  console.log(`${uri.replace(pw.password, '*')}`)— 'password' is in interpolation expression
 * False positive: console.log("inside confirm password change")  — 'password' only inside string
 * False positive: console.log("reset-password-request done")     — 'password' only inside string
 * False positive: console.log(`updating password`)               — 'password' only in template text
 * False positive: console.log(`regenerate password ${dbname}`)   — 'password' in text, ${dbname} is not a secret
 * False positive: logger.error(`Invalid secret key for: ${id}`)  — 'secret' in text, ${id} is not a secret
 */
function isLogStatementLoggingSecret(matchedText) {
  // Extract everything after the opening parenthesis of the log call
  const argsMatch = matchedText.match(/\(\s*([\s\S]*)/);
  if (!argsMatch) return false;
  const args = argsMatch[1];

  const secretKeywordPattern = /\b(?:pass(?:word|wd)|pwd|secret(?:[._-]?key)?|(?:api|auth|access)[._-]?(?:key|token|secret)|private[._-]?key|credentials?|client[._-]?secret)\b/i;

  // Step 1: Strip double-quoted and single-quoted strings entirely (literal text, not code)
  let codeOnly = args
    .replace(/"(?:[^"\\]|\\.)*"/g, '')
    .replace(/'(?:[^'\\]|\\.)*'/g, '');

  // Step 2: For template literals, extract ONLY ${...} interpolation expressions (those are code),
  // discard the text parts (descriptive messages are not secrets)
  codeOnly = codeOnly.replace(/`[^`]*`/g, (templateLiteral) => {
    const interpolations = [];
    templateLiteral.replace(/\$\{([^}]*)\}/g, (_, expr) => {
      interpolations.push(expr);
    });
    return ' ' + interpolations.join(' ') + ' ';
  });

  // Step 3: Check if any secret keyword exists in the remaining code-only content
  // (variable names, function arguments, property accesses — not string text)
  return secretKeywordPattern.test(codeOnly);
}

/**
 * Deduplicates findings that match at the same file:line:column.
 * Keeps the finding with the highest severity (most specific rule wins).
 */
function deduplicateFindings(findings) {
  const seen = new Map();
  for (const f of findings) {
    const key = `${f.file}:${f.line}:${f.column}`;
    const existing = seen.get(key);
    if (!existing || SEVERITY_LEVELS[f.severity] > SEVERITY_LEVELS[existing.severity]) {
      seen.set(key, f);
    }
  }
  // Re-assign sequential IDs
  const deduped = [...seen.values()];
  deduped.forEach((f, idx) => { f.id = `SEC-${idx + 1}`; });
  return deduped;
}
function maskValue(value) {
  if (!value) return '****';
  const cleanVal = value.trim();
  if (cleanVal.length <= 8) {
    return '****';
  }
  const prefix = cleanVal.substring(0, Math.min(6, Math.floor(cleanVal.length / 4)));
  const suffix = cleanVal.substring(cleanVal.length - Math.min(4, Math.floor(cleanVal.length / 5)));
  return `${prefix}****${suffix}`;
}

function getLineAndColumn(content, index) {
  const textBefore = content.substring(0, index);
  const lines = textBefore.split('\n');
  const lineNo = lines.length;
  const colNo = lines[lines.length - 1].length + 1;
  return { lineNo, colNo };
}

function extractContextLines(content, lineNo, contextRadius = 2) {
  const lines = content.split(/\r?\n/);
  const startLine = Math.max(1, lineNo - contextRadius);
  const endLine = Math.min(lines.length, lineNo + contextRadius);
  
  const snippetLines = [];
  for (let i = startLine; i <= endLine; i++) {
    snippetLines.push({
      line: i,
      isTarget: i === lineNo,
      text: lines[i - 1]
    });
  }
  return snippetLines;
}

function extractScriptOnlyContent(htmlContent) {
  // Replace anything outside <script...>...</script> with spaces (preserving newlines for accurate line numbers)
  const scriptRegex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let result = '';
  let lastIndex = 0;
  let match;

  while ((match = scriptRegex.exec(htmlContent)) !== null) {
    const beforeScript = htmlContent.substring(lastIndex, match.index);
    result += beforeScript.replace(/[^\r\n]/g, ' ');
    const openTagEnd = match[0].indexOf(match[1]);
    const openTag = match[0].substring(0, openTagEnd);
    result += openTag.replace(/[^\r\n]/g, ' ');
    result += match[1];
    const closeTag = '</script>';
    result += closeTag.replace(/[^\r\n]/g, ' ');
    lastIndex = match.index + match[0].length;
  }
  const remaining = htmlContent.substring(lastIndex);
  result += remaining.replace(/[^\r\n]/g, ' ');
  return result;
}

// ---------------------------------------------------------------------------
// 5. File Discovery, Live Progress Bar & Recursive Scanner
// ---------------------------------------------------------------------------
class ProgressBar {
  constructor(total, options = {}) {
    this.total = Math.max(1, total);
    this.current = 0;
    this.barLength = options.barLength || 25;
    this.isTTY = Boolean(process.stdout.isTTY);
    this.lastRenderTime = 0;
    this.lastLoggedPercent = -1;
    this.quiet = Boolean(options.quiet);
    this.verbose = Boolean(options.verbose);
  }

  update(current, currentFileRel = '') {
    this.current = current;
    if (this.quiet) return;

    const percent = Math.min(100, Math.floor((this.current / this.total) * 100));
    const now = Date.now();

    if (this.verbose) {
      console.log(`\x1b[90m[${percent}%] (${this.current}/${this.total}) Scanning: ${currentFileRel}\x1b[0m`);
      return;
    }

    if (this.isTTY) {
      // Throttle TTY redraws to at most once every 35ms (except first and last item) to prevent I/O bottleneck
      if (current < this.total && now - this.lastRenderTime < 35) {
        return;
      }
      this.lastRenderTime = now;

      const completedChars = Math.round((this.current / this.total) * this.barLength);
      const remainingChars = Math.max(0, this.barLength - completedChars);
      const bar = '█'.repeat(completedChars) + '░'.repeat(remainingChars);

      const termWidth = process.stdout.columns || 80;
      const prefix = `\x1b[36m[${bar}]\x1b[0m \x1b[1m\x1b[37m${String(percent).padStart(3)}%\x1b[0m \x1b[90m(${this.current}/${this.total})\x1b[0m \x1b[33mScanning:\x1b[0m `;
      
      const plainPrefixLength = `[${bar}] ${String(percent).padStart(3)}% (${this.current}/${this.total}) Scanning: `.length;
      const availableSpace = Math.max(10, termWidth - plainPrefixLength - 3);

      let displayFile = currentFileRel;
      if (displayFile.length > availableSpace) {
        displayFile = '...' + displayFile.slice(-(availableSpace - 3));
      }

      process.stdout.write(`\r\x1b[K${prefix}\x1b[1m${displayFile}\x1b[0m`);
    } else {
      // Non-TTY environment (CI / piped / background execution)
      const milestone = Math.floor(percent / 10) * 10;
      if (milestone > this.lastLoggedPercent || current === this.total) {
        this.lastLoggedPercent = milestone;
        console.log(`[Scanning Progress] ${percent}% (${this.current}/${this.total} files) - ${currentFileRel}`);
      }
    }
  }

  finish() {
    if (this.quiet) return;
    if (this.isTTY && !this.verbose) {
      // Clear line so summary table starts on a clean line
      process.stdout.write('\r\x1b[K');
    }
  }
}

function collectCandidateFiles(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) {
    const ext = path.extname(target).toLowerCase();
    const base = path.basename(target);
    if (!EXCLUDE_EXTS.has(ext) && !isExcludedFile(base, target)) {
      return [target];
    }
    return [];
  }

  const fileList = [];
  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (EXCLUDE_EXTS.has(ext) || isExcludedFile(entry.name, fullPath)) {
          continue;
        }
        fileList.push(fullPath);
      }
    }
  }

  walk(target);
  return fileList;
}

function scanFileSystem(target, rootDir, findings = [], stats = { filesScanned: 0, bytesScanned: 0, errors: 0 }) {
  const candidateFiles = collectCandidateFiles(target);
  const totalFiles = candidateFiles.length;

  if (!quietMode && !verboseMode) {
    console.log(`\x1b[90mDiscovered \x1b[1m${totalFiles.toLocaleString()}\x1b[0m\x1b[90m eligible files to scan. Please wait...\x1b[0m\n`);
  }

  if (totalFiles === 0) {
    return findings;
  }

  const progressBar = new ProgressBar(totalFiles, { quiet: quietMode, verbose: verboseMode });

  for (let i = 0; i < candidateFiles.length; i++) {
    const fullPath = candidateFiles[i];
    const relPath = path.relative(rootDir, fullPath) || path.basename(fullPath);
    progressBar.update(i + 1, relPath);
    scanSingleFile(fullPath, rootDir, findings, stats);
  }

  progressBar.finish();
  return findings;
}

function scanSingleFile(fullPath, rootDir, findings, stats) {
  stats.filesScanned++;

  let content;
  try {
    const fileStat = fs.statSync(fullPath);
    // Ignore files larger than 10MB to avoid freezing
    if (fileStat.size > 10 * 1024 * 1024) return;
    stats.bytesScanned += fileStat.size;

    content = fs.readFileSync(fullPath, 'utf8');
  } catch (err) {
    stats.errors++;
    return;
  }

  // Quick binary heuristic check: skip files with excessive null bytes
  if (content.includes('\u0000')) {
    return;
  }

  // Skip minified JS/CSS bundle files (very long single lines)
  const ext = path.extname(fullPath).toLowerCase();
  if ((ext === '.js' || ext === '.mjs' || ext === '.cjs' || ext === '.css') && content.length > 5000) {
    const firstChunk = content.substring(0, 3000);
    const lines = firstChunk.split(/\r?\n/);
    if (lines.some(line => line.length > 1000)) {
      return;
    }
  }

  const relPath = path.relative(rootDir, fullPath) || path.basename(fullPath);

  // For HTML files, only scan JavaScript inside <script> blocks and skip outer HTML tags
  let scanContent = content;
  const isHtml = ext === '.html' || ext === '.htm' || ext === '.xhtml' || ext === '.vue' || ext === '.svelte';
  if (isHtml) {
    scanContent = extractScriptOnlyContent(content);
  }

  // Determine source type (source / test / example) for smart tagging
  const sourceType = getSourceType(fullPath);
  const sourceNote = getSourceNote(sourceType);
  const lowerContent = content.toLowerCase();

  for (const pattern of ALL_PATTERNS) {
    if (pattern.fileFilter && !pattern.fileFilter(fullPath)) {
      continue;
    }

    if (pattern.pathRegex && !pattern.pathRegex.test(relPath) && !pattern.pathRegex.test(fullPath)) {
      continue;
    }

    // Filter by CLI minSeverity
    if (SEVERITY_LEVELS[pattern.severity] < SEVERITY_LEVELS[minSeverity]) {
      continue;
    }

    // Keywords quick pre-filter for performance
    if (pattern.keywords && pattern.keywords.length > 0) {
      if (!pattern.keywords.some(kw => lowerContent.includes(kw))) {
        continue;
      }
    }

    pattern.regex.lastIndex = 0;
    let match;

    while ((match = pattern.regex.exec(scanContent)) !== null) {
      const rawMatch = match[0];
      const matchIndex = match.index;
      const { lineNo, colNo } = getLineAndColumn(content, matchIndex);
      const contextLines = extractContextLines(content, lineNo, 2);

      // Extract precise secret value if secretGroup is defined
      let matchedSecretValue = rawMatch;
      if (pattern.secretGroup && match[pattern.secretGroup]) {
        matchedSecretValue = match[pattern.secretGroup];
      }

      // FP-3: Skip descriptive text (4+ words or validation keywords) for assignment-based rules
      const assignmentRules = ['HARDCODED_PASSWORD_ASSIGN', 'GENERIC_DEV_SECRET', 'TYPED_PASSWORD_DECLARATION', 'DB_CONFIG_PASSWORD_KEY'];
      if (assignmentRules.includes(pattern.id) && isDescriptiveText(rawMatch)) {
        if (pattern.regex.lastIndex === matchIndex) pattern.regex.lastIndex++;
        continue;
      }

      // Log statement FP filter: skip if secret keyword only appears inside quoted strings (descriptive messages)
      if (pattern.id === 'SECRET_IN_LOG_STATEMENT' && !isLogStatementLoggingSecret(rawMatch)) {
        if (pattern.regex.lastIndex === matchIndex) pattern.regex.lastIndex++;
        continue;
      }

      // Detect if the matching line is commented out
      const matchingLine = content.split(/\r?\n/)[lineNo - 1] || '';
      const commentedOut = isCommentLine(matchingLine);

      // Determine effective category — reclassify test file findings
      let effectiveCategory = pattern.category;
      if (sourceType === 'test') {
        effectiveCategory = 'Test Credentials';
      }

      findings.push({
        id: `SEC-${findings.length + 1}`,
        ruleId: pattern.id,
        ruleName: pattern.name,
        category: effectiveCategory,
        severity: pattern.severity,
        description: pattern.description,
        remediation: pattern.remediation,
        file: relPath,
        absolutePath: fullPath,
        line: lineNo,
        column: colNo,
        rawSecret: matchedSecretValue,
        maskedSecret: maskValue(matchedSecretValue),
        context: contextLines,
        sourceType: sourceType,
        sourceNote: sourceNote,
        isCommentedOut: commentedOut,
        commentNote: commentedOut ? '💬 This secret is in commented-out code. While inactive, it still exists in version history and is safe to remove entirely.' : null
      });

      // Avoid infinite loops for zero-length matches
      if (pattern.regex.lastIndex === matchIndex) {
        pattern.regex.lastIndex++;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// 6. Reports Index Manifest & Sync Utilities
// ---------------------------------------------------------------------------
function updateReportsIndex(reportsDirectory) {
  try {
    if (!fs.existsSync(reportsDirectory)) return [];
    const files = fs.readdirSync(reportsDirectory);
    const reportFiles = files.filter(f => f.endsWith('.json') && f !== 'reports.json' && f !== 'manifest.json');
    const indexData = [];

    for (const file of reportFiles) {
      const fullPath = path.join(reportsDirectory, file);
      try {
        const raw = fs.readFileSync(fullPath, 'utf8');
        const parsed = JSON.parse(raw);
        const scan = parsed.scan || {};
        const summary = scan.summary || parsed.summary || {};
        indexData.push({
          filename: file,
          path: `reports/${file}`,
          target: scan.target || parsed.target || '',
          timestamp: scan.timestamp || parsed.timestamp || fs.statSync(fullPath).mtime.toISOString(),
          formattedDate: scan.formattedDate || (scan.timestamp ? new Date(scan.timestamp).toLocaleString() : file),
          total: summary.total !== undefined ? summary.total : (parsed.findings ? parsed.findings.length : 0),
          critical: summary.critical || 0,
          high: summary.high || 0,
          medium: summary.medium || 0,
          low: summary.low || 0
        });
      } catch (err) {
        indexData.push({
          filename: file,
          path: `reports/${file}`,
          target: 'Unknown',
          timestamp: fs.statSync(fullPath).mtime.toISOString(),
          formattedDate: file,
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        });
      }
    }

    // Sort newest first
    indexData.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    const indexPath = path.join(reportsDirectory, 'reports.json');
    fs.writeFileSync(indexPath, JSON.stringify(indexData, null, 2), 'utf8');
    return indexData;
  } catch (err) {
    console.error(`\x1b[33m[WARNING] Could not update reports index:\x1b[0m ${err.message}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 7. Execution & Summary Output
// ---------------------------------------------------------------------------
const startTime = Date.now();

printBanner();
console.log(`\x1b[90mTarget Path:\x1b[0m ${resolvedTarget}`);
if (TOML_RULE_SUMMARIES.length > 0) {
  console.log(`\x1b[90mExternal TOML Rules:\x1b[0m ${TOML_RULE_SUMMARIES.map(s => `\x1b[1m${s.file}\x1b[0m (${s.count} rules -> \x1b[36m${s.category}\x1b[0m)`).join(', ')}`);
}
console.log('');

const scanStats = { filesScanned: 0, bytesScanned: 0, errors: 0 };
const rawFindings = scanFileSystem(resolvedTarget, resolvedTarget, [], scanStats);

// Post-scan deduplication: remove overlapping matches at the same location
const findings = deduplicateFindings(rawFindings);
const duration = ((Date.now() - startTime) / 1000).toFixed(2);

// Severity counts
const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
const highCount = findings.filter(f => f.severity === 'HIGH').length;
const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
const lowCount = findings.filter(f => f.severity === 'LOW').length;

// Source type counts
const exampleFileCount = findings.filter(f => f.sourceType === 'example').length;
const testFileCount = findings.filter(f => f.sourceType === 'test').length;
const commentedOutCount = findings.filter(f => f.isCommentedOut).length;

// Category Breakdown
const categoriesMap = {};
for (const f of findings) {
  categoriesMap[f.category] = (categoriesMap[f.category] || 0) + 1;
}

// Print Summary Table
console.log(`\x1b[1m\x1b[32mScan completed in ${duration}s!\x1b[0m`);
console.log(`Files Analyzed: \x1b[1m${scanStats.filesScanned}\x1b[0m | Total Findings: \x1b[1m${findings.length}\x1b[0m\n`);

console.log(`\x1b[1mSeverity Breakdown:\x1b[0m`);
console.log(`  \x1b[31mCRITICAL:\x1b[0m ${criticalCount}`);
console.log(`  \x1b[33mHIGH:\x1b[0m     ${highCount}`);
console.log(`  \x1b[33mMEDIUM:\x1b[0m   ${mediumCount}`);
console.log(`  \x1b[34mLOW:\x1b[0m      ${lowCount}\n`);

if (exampleFileCount || testFileCount || commentedOutCount) {
  console.log(`\x1b[1mSmart Tags:\x1b[0m`);
  if (exampleFileCount) console.log(`  \x1b[36m📄 Example/Template Files:\x1b[0m ${exampleFileCount}`);
  if (testFileCount) console.log(`  \x1b[36m🧪 Test/Spec Files:\x1b[0m        ${testFileCount}`);
  if (commentedOutCount) console.log(`  \x1b[36m💬 Commented-Out Code:\x1b[0m     ${commentedOutCount}`);
  console.log('');
}

if (!quietMode && findings.length > 0) {
  console.log(`\x1b[1mTop Findings Summary:\x1b[0m`);
  findings.slice(0, 10).forEach(f => {
    const sevColor = f.severity === 'CRITICAL' ? '\x1b[31m' : f.severity === 'HIGH' ? '\x1b[33m' : '\x1b[34m';
    const displaySecret = maskSecrets ? f.maskedSecret : f.rawSecret;
    console.log(`  [${sevColor}${f.severity}\x1b[0m] \x1b[1m${f.ruleName}\x1b[0m`);
    console.log(`    \x1b[90mLocation:\x1b[0m ${f.file}:${f.line}`);
    console.log(`    \x1b[90mMatch:\x1b[0m    ${displaySecret}\n`);
  });

  if (findings.length > 10) {
    console.log(`  \x1b[90m... and ${findings.length - 10} more findings.\x1b[0m\n`);
  }
}

// Prepare reports folder
const reportsDir = path.resolve(customReportsDir || './reports');
if (!fs.existsSync(reportsDir)) {
  fs.mkdirSync(reportsDir, { recursive: true });
}

// Determine output json path
let jsonReportPath;
if (customOutput) {
  jsonReportPath = path.resolve(customOutput);
  const parent = path.dirname(jsonReportPath);
  if (!fs.existsSync(parent)) {
    fs.mkdirSync(parent, { recursive: true });
  }
} else {
  jsonReportPath = path.join(reportsDir, `report_${getFormattedTimestamp()}.json`);
}

// Build structured report object
const reportData = {
  metadata: APP_METADATA,
  scan: {
    target: resolvedTarget,
    timestamp: new Date().toISOString(),
    formattedDate: new Date().toLocaleString(),
    stats: { ...scanStats, durationSeconds: parseFloat(duration), deduplicated: rawFindings.length - findings.length },
    summary: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      total: findings.length,
      exampleFiles: exampleFileCount,
      testFiles: testFileCount,
      commentedOut: commentedOutCount
    },
    categorySummary: categoriesMap
  },
  findings: (maskSecrets ? findings : findings.map(f => ({ ...f, maskedSecret: f.rawSecret }))).map(f => ({
    ...f,
    isFalsePositive: false
  }))
};

// Write JSON Report
fs.writeFileSync(jsonReportPath, JSON.stringify(reportData, null, 2), 'utf8');
console.log(`\x1b[32m[+] JSON Report saved to:\x1b[0m ${jsonReportPath}`);

// Update reports manifest
const indexData = updateReportsIndex(reportsDir);
console.log(`\x1b[32m[+] Updated reports manifest:\x1b[0m ${path.join(reportsDir, 'reports.json')} (${indexData ? indexData.length : 0} report(s) available)`);

// HTML Report Viewer
const rootViewer = path.resolve(__dirname, 'index.html');
if (fs.existsSync(rootViewer)) {
  console.log(`\x1b[36m[+] HTML Report Viewer:\x1b[0m ${rootViewer}`);
}

console.log('');
