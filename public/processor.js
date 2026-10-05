import { renameApk as coreRenameApk, SOURCE_PACKAGE, TARGET_PACKAGE } from './processor-core.js';

let worker = null;
let nextId = 1;
const pending = new Map();

function getWorker() {
  if (!('Worker' in window)) return null;
  if (!worker) {
    worker = new Worker(new URL('./processor-worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = event => {
      const { id, type } = event.data || {};
      const job = pending.get(id);
      if (!job) return;
      if (type === 'progress') {
        job.onProgress?.(event.data.progress);
      } else if (type === 'done') {
        pending.delete(id);
        const bytes = new Uint8Array(event.data.bytes);
        job.resolve({ ...event.data.meta, bytes });
      } else if (type === 'error') {
        pending.delete(id);
        job.reject(new Error(event.data.message || 'APK processing failed.'));
      }
    };
    worker.onerror = event => {
      for (const [id, job] of pending) job.reject(new Error(event.message || 'APK processing worker crashed.'));
      pending.clear();
      worker = null;
    };
  }
  return worker;
}

export function renameApk(file, onProgress = null) {
  const w = getWorker();
  if (!w) return coreRenameApk(file, onProgress);
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject, onProgress });
    w.postMessage({ id, file });
  });
}

export { SOURCE_PACKAGE, TARGET_PACKAGE };
