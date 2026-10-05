import { renameApk } from './processor-core.js';

self.onmessage = async event => {
  const { id, file } = event.data || {};
  if (!id || !file) return;
  try {
    const result = await renameApk(file, progress => self.postMessage({ id, type: 'progress', progress }));
    const { bytes, blob, ...meta } = result;
    const buffer = bytes.buffer;
    self.postMessage({ id, type: 'done', bytes: buffer, meta }, [buffer]);
  } catch (error) {
    self.postMessage({ id, type: 'error', message: error?.message || String(error) });
  }
};
