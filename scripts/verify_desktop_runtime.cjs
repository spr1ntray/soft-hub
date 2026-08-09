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
    ? ['python.exe', 'python312.dll', 'vcruntime140.dll', 'vcruntime140_1.dll']
    : [path.join('bin', 'python3')];
  const missing = required.filter((relative) => !fs.existsSync(path.join(runtimeRoot, relative)));
  if (missing.length > 0) {
    throw new Error(`Managed ${expectedOs}-${expectedArch} runtime is incomplete: ${missing.join(', ')}`);
  }
}

exports.verifyRuntime = verifyRuntime;
exports.default = async function beforePack(context) {
  verifyRuntime(path.resolve(__dirname, '..'), context.electronPlatformName, context.arch);
};
