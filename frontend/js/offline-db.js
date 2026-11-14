const DB_NAME = 'detector360_forensic_db';
const DB_VERSION = 1;
const STORE_SCANS = 'local_scans';
const STORE_QUEUE = 'pending_urls';
const STORE_META = 'app_meta';
const MAX_LOCAL_SCANS = 30;

function openDatabase() {
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in window)) {
      reject(new Error('IndexedDB no está soportado en este navegador'));
      return;
    }

    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_SCANS)) {
        const scanStore = db.createObjectStore(STORE_SCANS, { keyPath: 'scan_id' });
        scanStore.createIndex('scanned_at', 'scanned_at', { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_QUEUE)) {
        db.createObjectStore(STORE_QUEUE, { keyPath: 'id', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: 'key' });
      }
    };

    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export const OfflineDb = {
  async saveScan(reportData) {
    try {
      const db = await openDatabase();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_SCANS, 'readwrite');
        const store = tx.objectStore(STORE_SCANS);
        store.put(reportData);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });

      await this.pruneOldScans();
    } catch {
      // Fallback silently if private browsing disables IndexedDB
    }
  },

  async pruneOldScans() {
    try {
      const all = await this.listScans();
      if (all.length <= MAX_LOCAL_SCANS) return;

      const toDelete = all.slice(MAX_LOCAL_SCANS);
      const db = await openDatabase();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_SCANS, 'readwrite');
        const store = tx.objectStore(STORE_SCANS);
        for (const item of toDelete) {
          store.delete(item.scan_id);
        }
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch {
      // Ignore prune error
    }
  },

  async getScan(scanId) {
    try {
      const db = await openDatabase();
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_SCANS, 'readonly');
        const req = tx.objectStore(STORE_SCANS).get(scanId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
    } catch {
      return null;
    }
  },

  async listScans() {
    try {
      const db = await openDatabase();
      const items = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_SCANS, 'readonly');
        const req = tx.objectStore(STORE_SCANS).getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
      });

      return items.sort((a, b) => (b.scanned_at || '').localeCompare(a.scanned_at || ''));
    } catch {
      return [];
    }
  },

  async deleteScan(scanId) {
    try {
      const db = await openDatabase();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_SCANS, 'readwrite');
        tx.objectStore(STORE_SCANS).delete(scanId);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch {
      // Ignore
    }
  },

  async enqueueSharedUrl(url) {
    try {
      const db = await openDatabase();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_QUEUE, 'readwrite');
        tx.objectStore(STORE_QUEUE).add({
          url,
          queued_at: new Date().toISOString()
        });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch {
      // Ignore
    }
  },

  async drainPendingUrls() {
    try {
      const db = await openDatabase();
      const pending = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_QUEUE, 'readwrite');
        const store = tx.objectStore(STORE_QUEUE);
        const getAllReq = store.getAll();
        getAllReq.onsuccess = () => {
          const rows = getAllReq.result || [];
          store.clear();
          resolve(rows);
        };
        getAllReq.onerror = () => reject(getAllReq.error);
      });
      return pending;
    } catch {
      return [];
    }
  },

  async incrementExportCount() {
    try {
      const current = await this.getExportCount();
      const db = await openDatabase();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_META, 'readwrite');
        tx.objectStore(STORE_META).put({ key: 'exports_count', value: current + 1 });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      return current + 1;
    } catch {
      return 0;
    }
  },

  async getExportCount() {
    try {
      const db = await openDatabase();
      const row = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_META, 'readonly');
        const req = tx.objectStore(STORE_META).get('exports_count');
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
      return row?.value || 0;
    } catch {
      return 0;
    }
  }
};
