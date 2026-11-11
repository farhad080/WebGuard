import { open, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { RequestHandler } from 'express';
import multer from 'multer';
import { config } from '../config.js';

const ALLOWED_MIME_TYPES = new Set([
  'application/zip',
  'application/x-zip-compressed', // what Windows browsers send for .zip
]);

const UPLOAD_TMP_DIR = path.join(os.tmpdir(), 'webguard-uploads');

class UploadRejected extends Error {}

async function hasZipSignature(filePath: string): Promise<boolean> {
  const handle = await open(filePath, 'r');
  try {
    const { buffer, bytesRead } = await handle.read(Buffer.alloc(4), 0, 4, 0);
    if (bytesRead < 4) return false;
    // PK\x03\x04 (local file header) or PK\x05\x06 (empty archive)
    return (
      buffer[0] === 0x50 &&
      buffer[1] === 0x4b &&
      ((buffer[2] === 0x03 && buffer[3] === 0x04) || (buffer[2] === 0x05 && buffer[3] === 0x06))
    );
  } finally {
    await handle.close();
  }
}

/**
 * Accepts exactly one `.zip` file in the multipart field `file`, streamed to a temp file.
 * Checks the extension, MIME type, size limit, and ZIP magic bytes. On success `req.file`
 * is set; the route must delete `req.file.path` when done.
 */
export function zipUpload(): RequestHandler {
  return (req, res, next) => {
    const upload = multer({
      dest: UPLOAD_TMP_DIR,
      limits: { fileSize: config.maxUploadBytes, files: 1, fields: 5, parts: 6 },
      fileFilter: (_req, file, cb) => {
        const isZipName = path.extname(file.originalname).toLowerCase() === '.zip';
        if (!isZipName || !ALLOWED_MIME_TYPES.has(file.mimetype)) {
          cb(new UploadRejected('Only .zip files (application/zip) are accepted'));
          return;
        }
        cb(null, true);
      },
    }).single('file');

    upload(req, res, (err: unknown) => {
      if (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
          res.status(413).json({ error: `File exceeds the ${config.maxUploadBytes}-byte limit` });
        } else if (err instanceof multer.MulterError || err instanceof UploadRejected) {
          res.status(400).json({
            error: err instanceof UploadRejected ? err.message : 'Invalid upload',
          });
        } else {
          next(err);
        }
        return;
      }

      const file = req.file;
      if (!file) {
        res.status(400).json({ error: 'A .zip file is required in the "file" field' });
        return;
      }
      hasZipSignature(file.path)
        .then(async (isZip) => {
          if (isZip) {
            next();
            return;
          }
          await unlink(file.path).catch(() => undefined);
          res.status(400).json({ error: 'Uploaded file is not a valid ZIP archive' });
        })
        .catch(next);
    });
  };
}
