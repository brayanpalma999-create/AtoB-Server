const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

function createStateDatabase({ rootDir, fileName = "atob.sqlite" }) {
  const storageRoot = path.resolve(rootDir || __dirname);
  if (!fs.existsSync(storageRoot)) {
    fs.mkdirSync(storageRoot, { recursive: true });
  }
  const dbPath = path.join(storageRoot, fileName);
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS state_documents (
      collection TEXT NOT NULL,
      id TEXT NOT NULL,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (collection, id)
    );

    CREATE INDEX IF NOT EXISTS idx_state_documents_collection_updated
      ON state_documents(collection, updated_at DESC);
  `);

  const readStmt = db.prepare(`
    SELECT id, payload, updated_at
    FROM state_documents
    WHERE collection = ?
    ORDER BY updated_at DESC, id DESC
  `);
  const deleteCollectionStmt = db.prepare(`
    DELETE FROM state_documents
    WHERE collection = ?
  `);
  const upsertStmt = db.prepare(`
    INSERT INTO state_documents (collection, id, payload, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(collection, id) DO UPDATE SET
      payload = excluded.payload,
      updated_at = excluded.updated_at
  `);
  const removeStmt = db.prepare(`
    DELETE FROM state_documents
    WHERE collection = ? AND id = ?
  `);
  const countStmt = db.prepare(`
    SELECT COUNT(*) AS total
    FROM state_documents
    WHERE collection = ?
  `);

  function normalizeRows(rows) {
    return rows
      .map((row) => {
        try {
          const parsed = JSON.parse(String(row.payload || "{}"));
          if (!parsed || typeof parsed !== "object") return null;
          return parsed;
        } catch (_) {
          return null;
        }
      })
      .filter(Boolean);
  }

  function loadCollection(collection) {
    return normalizeRows(readStmt.all(String(collection || "")));
  }

  function replaceCollection(collection, records, resolveId) {
    const safeCollection = String(collection || "");
    const list = Array.isArray(records) ? records : [];
    const resolveKey =
      typeof resolveId === "function"
        ? resolveId
        : (record) => record?.id ?? record?.accountKey ?? record?.token ?? "";
    const transaction = db.transaction((items) => {
      deleteCollectionStmt.run(safeCollection);
      for (const record of items) {
        const identifier = String(resolveKey(record) || "").trim();
        if (!identifier) continue;
        const payload = JSON.stringify(record ?? {});
        const updatedAt = String(
          record?.updatedAt ||
            record?.savedAt ||
            record?.createdAt ||
            new Date().toISOString(),
        );
        upsertStmt.run(safeCollection, identifier, payload, updatedAt);
      }
    });
    transaction(list);
    return list.length;
  }

  function upsertDocument(collection, id, record, updatedAt) {
    const safeCollection = String(collection || "");
    const safeId = String(id || "").trim();
    if (!safeCollection || !safeId) return false;
    upsertStmt.run(
      safeCollection,
      safeId,
      JSON.stringify(record ?? {}),
      String(updatedAt || record?.updatedAt || record?.savedAt || record?.createdAt || new Date().toISOString()),
    );
    return true;
  }

  function removeDocument(collection, id) {
    const safeCollection = String(collection || "");
    const safeId = String(id || "").trim();
    if (!safeCollection || !safeId) return false;
    removeStmt.run(safeCollection, safeId);
    return true;
  }

  function countCollection(collection) {
    const row = countStmt.get(String(collection || ""));
    return Number(row?.total || 0);
  }

  return {
    dbPath,
    loadCollection,
    replaceCollection,
    upsertDocument,
    removeDocument,
    countCollection,
  };
}

module.exports = {
  createStateDatabase,
};
