-- AlterTable
ALTER TABLE "findings" ADD COLUMN     "contributing_detectors" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "evidence" TEXT[] DEFAULT ARRAY[]::TEXT[];

