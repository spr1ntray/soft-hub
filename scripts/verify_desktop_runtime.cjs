const fs = require('node:fs');
const path = require('node:path');

const ARCH_NAMES = new Map([
  [0, 'ia32'],
  [1, 'x64'],
  [2, 'armv7l'],
  [3, 'arm64'],
  [4, 'universal'],
]);

function verifyRuntime(projectRoot, electronPlatformName, archValue) {
  const expectedOs = electronPlatformName === 'darwin'
    ? 'darwin'
    : electronPlatformName === 'win32'
      ? 'win32'
      : null;
  const expectedArch = ARCH_NAMES.get(archValue);
  if (!expectedOs || !expectedArch) {
    throw new Error(`Soft Hub has no managed runtime contract for ${electronPlatformName}/${archValue}`);
  }

  const runtimeRoot = path.join(projectRoot, 'build', 'runtime', 'python');
  const markerPath = path.join(runtimeRoot, 'soft-hub-runtime.json');
  let marker;
  try {
    marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
  } catch (error) {
    throw new Error(`Managed runtime marker is missing or invalid: ${markerPath}`, { cause: error });
  }
  if (marker.os !== expectedOs || marker.arch !== expectedArch) {
    throw new Error(
      `Refusing to package ${expectedOs}-${expectedArch} with ${String(marker.os)}-${String(marker.arch)} runtime`,
    );
  }

  const required = expectedOs === 'win32'
    ? [
      'python.exe',
      'python312.dll',
      'vcruntime140.dll',
      'vcruntime140_1.dll',
      path.join('Lib', 'site-packages', 'certifi', 'cacert.pem'),
    ]
    : [
      path.join('bin', 'python3'),
      path.join('lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'),
    ];
  const missing = required.filter((relative) => !fs.existsSync(path.join(runtimeRoot, relative)));
  if (missing.length > 0) {
    throw new Error(`Managed ${expectedOs}-${expectedArch} runtime is incomplete: ${missing.join(', ')}`);
  }
  const caBundle = expectedOs === 'win32'
    ? path.join(runtimeRoot, 'Lib', 'site-packages', 'certifi', 'cacert.pem')
    : path.join(runtimeRoot, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem');
  if (fs.statSync(caBundle).size < 100_000) {
    throw new Error(`Managed ${expectedOs}-${expectedArch} runtime has an invalid certifi CA bundle`);
  }
}

exports.verifyRuntime = verifyRuntime;
exports.default = async function beforePack(context) {
  verifyRuntime(path.resolve(__dirname, '..'), context.electronPlatformName, context.arch);
};
