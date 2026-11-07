/**
 * Meshy v1 (.meshy) -> standard GLB converter.
 * Browser-only ES module. Adapted from the HTML converter supplied by the user.
 * Conversion runs on the caller's device, not on GitHub Pages.
 *
 * External decoder (only when meshopt-compressed): meshoptimizer 1.3.0 (MIT).
 *   https://github.com/zeux/meshoptimizer
 */

const MAX_BYTES = 256 * 1024 * 1024;
const MESHOPT_EXTENSION = 'EXT_meshopt_compression';
const MESHY_MAGIC = 'MESHY.AI';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
let decoderPromise;

const align4 = n => (n + 3) & ~3;
const checkSize = (n, label) => {
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_BYTES) {
    throw new Error(`${label}: 파일 크기가 잘못되었거나 256MB 제한을 초과했습니다.`);
  }
};

function report(options, stage, extra = {}) {
  if (typeof options?.onProgress === 'function') options.onProgress({ stage, ...extra });
}

function isGLB(input) {
  return input.byteLength >= 4 && new DataView(input).getUint32(0, true) === 0x46546c67;
}

function readGLB(input) {
  if (!(input instanceof ArrayBuffer)) throw new TypeError('ArrayBuffer가 필요합니다.');
  const data = new Uint8Array(input);
  checkSize(data.length, 'GLB');
  if (data.length < 20 || !isGLB(input)) throw new Error('GLB 헤더가 올바르지 않습니다.');
  const view = new DataView(input);
  if (view.getUint32(4, true) !== 2 || view.getUint32(8, true) !== data.length) {
    throw new Error('GLB 버전 또는 파일 길이가 올바르지 않습니다.');
  }
  let offset = 12;
  let json = null, bin = null, chunks = 0;
  while (offset < data.length) {
    if (offset + 8 > data.length) throw new Error('GLB 청크 헤더가 손상되었습니다.');
    const length = view.getUint32(offset, true);
    const type = view.getUint32(offset + 4, true);
    if (length % 4 !== 0 || offset + 8 + length > data.length) {
      throw new Error('GLB 청크의 크기 또는 정렬이 올바르지 않습니다.');
    }
    const part = data.subarray(offset + 8, offset + 8 + length);
    if (chunks === 0 && type !== 0x4e4f534a) throw new Error('GLB 첫 청크가 JSON이 아닙니다.');
    if (type === 0x4e4f534a) {
      if (json !== null) throw new Error('GLB JSON 청크가 중복되었습니다.');
      try { json = JSON.parse(decoder.decode(part)); }
      catch { throw new Error('GLB JSON을 읽을 수 없습니다.'); }
    } else if (type === 0x004e4942) {
      if (bin !== null) throw new Error('GLB BIN 청크가 중복되었습니다.');
      bin = part;
    }
    offset += 8 + length;
    chunks++;
  }
  if (!json || json.asset?.version !== '2.0') throw new Error('glTF 2.0 형식이 아닙니다.');
  if (json.buffers?.[0] && !json.buffers[0].uri && json.buffers[0].byteLength > (bin?.length || 0)) {
    throw new Error('GLB 바이너리 데이터가 부족합니다.');
  }
  return { json, bin: bin || new Uint8Array() };
}

function writeGLB(json, bin) {
  const rawJSON = encoder.encode(JSON.stringify(json));
  const jsonLength = align4(rawJSON.length);
  const binLength = align4(bin.length);
  const total = 20 + jsonLength + (bin.length ? 8 + binLength : 0);
  checkSize(total, '출력 GLB');
  const output = new Uint8Array(total);
  const head = new DataView(output.buffer);
  head.setUint32(0, 0x46546c67, true); // glTF
  head.setUint32(4, 2, true);
  head.setUint32(8, total, true);
  head.setUint32(12, jsonLength, true);
  head.setUint32(16, 0x4e4f534a, true); // JSON
  output.fill(32, 20, 20 + jsonLength);
  output.set(rawJSON, 20);
  if (bin.length) {
    const offset = 20 + jsonLength;
    head.setUint32(offset, binLength, true);
    head.setUint32(offset + 4, 0x004e4942, true); // BIN\0
    output.set(bin, offset + 8);
  }
  return output.buffer;
}

/** Unwrap MESHY.AI v1 AES-CTR container, or pass through an existing GLB. */
async function unpackMeshy(input) {
  if (!(input instanceof ArrayBuffer)) throw new TypeError('ArrayBuffer가 필요합니다.');
  checkSize(input.byteLength, '입력');
  if (isGLB(input)) return input;
  const data = new Uint8Array(input);
  if (data.length < 8240 || decoder.decode(data.subarray(0, 8)) !== MESHY_MAGIC) {
    throw new Error('MESHY.AI v1 또는 GLB 파일만 지원합니다.');
  }
  if (new DataView(input).getUint16(8, true) !== 1) {
    throw new Error('이 변환기는 Meshy v1 파일만 지원합니다.');
  }
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto를 사용할 수 없습니다. HTTPS에서 실행하세요.');
  const ctr = new Uint8Array(16);
  ctr.set(data.subarray(10, 22));
  ctr[15] = 2;
  const key = await globalThis.crypto.subtle.importKey(
    'raw', encoder.encode('JSON{"accessors":[{"bufferView":'),
    'AES-CTR', false, ['decrypt']
  );
  let clear;
  try {
    clear = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: ctr, length: 32 },
      key, data.subarray(32, 8224)
    );
  } catch {
    throw new Error('Meshy 복호화에 실패했습니다.');
  }
  if (!isGLB(clear) || new DataView(clear).getUint32(4, true) !== 2) {
    throw new Error('복호화 결과가 GLB가 아닙니다. 지원하지 않는 Meshy 버전일 수 있습니다.');
  }
  const output = new Uint8Array(data.length - 48);
  output.set(new Uint8Array(clear));
  output.set(data.subarray(8240), 8192);
  new DataView(output.buffer).setUint32(8, output.length, true);
  return output.buffer;
}

async function getMeshoptDecoder() {
  if (!decoderPromise) {
    decoderPromise = (async () => {
      const urls = [
        'https://cdn.jsdelivr.net/npm/meshoptimizer@1.3.0/meshopt_decoder.mjs',
        'https://unpkg.com/meshoptimizer@1.3.0/meshopt_decoder.mjs',
      ];
      let lastError;
      for (const url of urls) {
        try {
          const { MeshoptDecoder } = await import(/* @vite-ignore */ url);
          if (!MeshoptDecoder?.supported) throw new Error('WebAssembly가 지원되지 않습니다.');
          await MeshoptDecoder.ready;
          return MeshoptDecoder;
        } catch (error) { lastError = error; }
      }
      throw new Error(`Meshoptimizer 로드 실패: ${lastError?.message || '인터넷 연결을 확인하세요.'}`);
    })();
  }
  try { return await decoderPromise; }
  catch (error) { decoderPromise = undefined; throw error; }
}

/**
 * Decompress EXT_meshopt_compression in a GLB and remove that extension.
 * options.onProgress({stage, done?, total?}) can display status.
 * options.decoder is an optional injected MeshoptDecoder (for tests / offline use).
 */
async function decompressGLB(input, options = {}) {
  const { json, bin } = readGLB(input);
  const views = json.bufferViews || [];
  const compressed = views.filter(view => view.extensions?.[MESHOPT_EXTENSION]).length;
  if (!compressed) return { buffer: input, json, decoded: 0 };
  if ((json.buffers || []).some(buffer => buffer.uri)) {
    throw new Error('외부 버퍼를 사용하는 압축 GLB는 지원하지 않습니다.');
  }
  const meshopt = options.decoder || await getMeshoptDecoder();
  if (meshopt.ready) await meshopt.ready;
  if (typeof meshopt.decodeGltfBuffer !== 'function') throw new Error('올바른 Meshoptimizer 디코더가 아닙니다.');

  const pieces = [], outputViews = [];
  let total = 0;
  for (let i = 0; i < views.length; i++) {
    const view = views[i];
    const ext = view.extensions?.[MESHOPT_EXTENSION];
    const outputLength = ext ? ext.count * ext.byteStride : view.byteLength;
    const start = (ext ? ext.byteOffset : view.byteOffset) ?? 0;
    const length = ext ? ext.byteLength : view.byteLength;
    const sourceBuffer = (ext ? ext.buffer : view.buffer) ?? 0;
    if (sourceBuffer !== 0) throw new Error(`외부 버퍼 참조는 지원하지 않습니다: ${i}`);
    if (![outputLength, start, length].every(n => Number.isSafeInteger(n) && n >= 0) ||
        start + length > bin.length || outputLength > MAX_BYTES) {
      throw new Error(`버퍼 범위가 잘못되었습니다: ${i}`);
    }
    if (ext && (!Number.isSafeInteger(ext.count) || ext.count <= 0 ||
        !Number.isSafeInteger(ext.byteStride) || ext.byteStride <= 0 ||
        outputLength !== view.byteLength ||
        !['ATTRIBUTES', 'TRIANGLES', 'INDICES'].includes(ext.mode) ||
        !['NONE', 'OCTAHEDRAL', 'QUATERNION', 'EXPONENTIAL', 'COLOR'].includes(ext.filter || 'NONE'))) {
      throw new Error(`압축 버퍼 정보가 잘못되었습니다: ${i}`);
    }
    const pos = align4(total);
    checkSize(pos + outputLength, '압축 해제 결과');
    const bytes = ext ? new Uint8Array(outputLength) : bin.subarray(start, start + length);
    if (ext) {
      meshopt.decodeGltfBuffer(
        bytes, ext.count, ext.byteStride, bin.subarray(start, start + length), ext.mode, ext.filter || 'NONE'
      );
    }
    const resultView = { ...view, buffer: 0, byteOffset: pos, byteLength: outputLength };
    if (resultView.extensions) {
      resultView.extensions = { ...resultView.extensions };
      delete resultView.extensions[MESHOPT_EXTENSION];
      if (!Object.keys(resultView.extensions).length) delete resultView.extensions;
    }
    pieces.push({ pos, bytes });
    outputViews.push(resultView);
    total = pos + outputLength;
    report(options, 'decompress', { done: i + 1, total: views.length });
  }
  const binary = new Uint8Array(total);
  for (const { pos, bytes } of pieces) binary.set(bytes, pos);
  const outputJSON = { ...json, buffers: [{ byteLength: total }], bufferViews: outputViews };
  for (const key of ['extensionsUsed', 'extensionsRequired']) {
    if (!outputJSON[key]) continue;
    const extensions = outputJSON[key].filter(name => name !== MESHOPT_EXTENSION);
    if (extensions.length) outputJSON[key] = extensions;
    else delete outputJSON[key];
  }
  const result = writeGLB(outputJSON, binary);
  readGLB(result); // self-check generated GLB
  return { buffer: result, json: outputJSON, decoded: compressed };
}

/** Low-level API returning ArrayBuffer (usable with a File or in memory). */
async function convertMeshyBuffer(input, options = {}) {
  report(options, 'unpack');
  const glb = await unpackMeshy(input);
  report(options, 'validate');
  readGLB(glb);
  report(options, 'decompress');
  const result = await decompressGLB(glb, options);
  report(options, 'complete', { decoded: result.decoded });
  return result.buffer;
}

/** Simple API: const glbFile = await convertMeshyToGLB(file); */
export async function convertMeshyToGLB(file, options = {}) {
  if (!(file instanceof Blob)) throw new TypeError('File 또는 Blob이 필요합니다.');
  checkSize(file.size, '입력');
  report(options, 'read');
  const result = await convertMeshyBuffer(await file.arrayBuffer(), options);
  const name = options.filename || ((file.name || 'converted.meshy').replace(/\.(meshy|glb)$/i, '') + '.glb');
  return new File([result], name, { type: 'model/gltf-binary' });
}
