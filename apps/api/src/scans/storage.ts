import { createReadStream, createWriteStream } from 'node:fs';
import { access, copyFile, mkdir, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { config } from '../config.js';

/**
 * Object-store abstraction. Keys are `/`-separated relative paths such as
 * `scans/<scanId>/raw.zip`. The local-filesystem implementation below can be swapped for
 * an S3-compatible one without touching callers.
 */
export interface StorageService {
  put(key: string, data: Buffer | Readable): Promise<void>;
  putFile(key: string, localPath: string): Promise<void>;
  getStream(key: string): Promise<Readable>;
  downloadToFile(key: string, localPath: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  /** Lists all keys under a prefix (recursively). */
  list(prefix: string): Promise<string[]>;
  /** Deletes every object under a prefix. */
  deletePrefix(prefix: string): Promise<void>;
}

export class InvalidStorageKeyError extends Error {
  override name = 'InvalidStorageKeyError';
}

export class LocalStorageService implements StorageService {
  private readonly root: string;

  constructor(rootDir: string) {
    this.root = path.resolve(rootDir);
  }

  /** Maps a key to a path, refusing anything that could escape the storage root. */
  private resolveKey(key: string): string {
    const trimmed = key.replace(/\/+$/, '');
    const segments = trimmed.split('/');
    if (
      trimmed === '' ||
      trimmed.includes('\\') ||
      trimmed.includes('\0') ||
      trimmed.startsWith('/') ||
      /^[a-zA-Z]:/.test(trimmed) ||
      segments.some((s) => s === '' || s === '.' || s === '..')
    ) {
      throw new InvalidStorageKeyError(`Invalid storage key: ${key}`);
    }
    const resolved = path.resolve(this.root, ...segments);
    const rel = path.relative(this.root, resolved);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new InvalidStorageKeyError(`Invalid storage key: ${key}`);
    }
    return resolved;
  }

  async put(key: string, data: Buffer | Readable): Promise<void> {
    const target = this.resolveKey(key);
    await mkdir(path.dirname(target), { recursive: true });
    const source = Buffer.isBuffer(data) ? Readable.from([data]) : data;
    await pipeline(source, createWriteStream(target));
  }

  async putFile(key: string, localPath: string): Promise<void> {
    const target = this.resolveKey(key);
    await mkdir(path.dirname(target), { recursive: true });
    await copyFile(localPath, target);
  }

  async getStream(key: string): Promise<Readable> {
    const target = this.resolveKey(key);
    await access(target);
    return createReadStream(target);
  }

  async downloadToFile(key: string, localPath: string): Promise<void> {
    await copyFile(this.resolveKey(key), localPath);
  }

  async exists(key: string): Promise<boolean> {
    try {
      await access(this.resolveKey(key));
      return true;
    } catch {
      return false;
    }
  }

  async list(prefix: string): Promise<string[]> {
    const base = this.resolveKey(prefix);
    const keys: string[] = [];
    const walk = async (dir: string): Promise<void> => {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
        throw err;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full);
        else if (entry.isFile())
          keys.push(path.relative(this.root, full).split(path.sep).join('/'));
      }
    };
    await walk(base);
    return keys.sort();
  }

  async deletePrefix(prefix: string): Promise<void> {
    await rm(this.resolveKey(prefix), { recursive: true, force: true });
  }
}

/** Uploads every regular file under `localDir` to `<prefix>/<relative path>`. */
export async function uploadDirectory(
  storage: StorageService,
  localDir: string,
  prefix: string,
): Promise<number> {
  let count = 0;
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        const rel = path.relative(localDir, full).split(path.sep).join('/');
        await storage.putFile(`${prefix}/${rel}`, full);
        count++;
      }
    }
  };
  await walk(localDir);
  return count;
}

let storage: StorageService | undefined;
export function getStorage(): StorageService {
  storage ??= new LocalStorageService(config.storageDir);
  return storage;
}

export const storageKeys = {
  rawZip: (scanId: string) => `scans/${scanId}/raw.zip`,
  extracted: (scanId: string) => `scans/${scanId}/extracted`,
};
