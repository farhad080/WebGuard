-- AlterTable
ALTER TABLE "findings" ADD COLUMN     "cwe" TEXT,
ADD COLUMN     "remediation_json" JSONB;

