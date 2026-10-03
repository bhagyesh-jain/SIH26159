import React, { useState, useRef } from "react";
import { Upload, FileCode, AlertCircle, Loader2, CheckCircle2 } from "lucide-react";
import { uploadCapture } from "../../api/captures";
import { CaptureResponse } from "../../types/api";
import { formatBytes } from "../../utils/formatting";

interface CaptureUploadDropzoneProps {
  investigationId: string;
  onUploadSuccess: (capture: CaptureResponse) => void;
  disabled?: boolean;
}

const SUPPORTED_EXTENSIONS = [".pcap", ".pcapng"];

export const CaptureUploadDropzone: React.FC<CaptureUploadDropzoneProps> = ({
  investigationId,
  onUploadSuccess,
  disabled = false,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): boolean => {
    const nameLower = file.name.toLowerCase();
    const hasValidExt = SUPPORTED_EXTENSIONS.some((ext) => nameLower.endsWith(ext));
    if (!hasValidExt) {
      setError(`Unsupported file format '${file.name}'. Only .pcap and .pcapng files are supported.`);
      return false;
    }
    setError(null);
    return true;
  };

  const handleFileChange = (file: File | null) => {
    if (!file) return;
    if (validateFile(file)) {
      setSelectedFile(file);
      setUploadSuccess(null);
    } else {
      setSelectedFile(null);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled && !uploading) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (disabled || uploading) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleUploadSubmit = async () => {
    if (!selectedFile || disabled || uploading) return;

    setUploading(true);
    setError(null);

    try {
      const res = await uploadCapture(investigationId, selectedFile);
      setUploadSuccess(`Capture '${res.filename}' uploaded successfully (SHA-256: ${res.sha256.slice(0, 12)}...).`);
      setSelectedFile(null);
      onUploadSuccess(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to upload capture file.");
      }
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
      <h3 className="text-xs font-mono font-bold uppercase text-slate-400 tracking-wider mb-3 flex items-center gap-2">
        <Upload className="w-4 h-4 text-cyan-400" /> PCAP / PCAPNG Network Capture Ingestion
      </h3>

      {error && (
        <div className="mb-4 p-3 bg-red-950/50 border border-red-800/80 rounded text-xs text-red-300 flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {uploadSuccess && (
        <div className="mb-4 p-3 bg-emerald-950/50 border border-emerald-800/80 rounded text-xs text-emerald-300 flex items-start gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <span>{uploadSuccess}</span>
        </div>
      )}

      {/* Hidden File Input */}
      <input
        type="file"
        ref={fileInputRef}
        accept=".pcap,.pcapng"
        className="hidden"
        disabled={disabled || uploading}
        onChange={(e) => {
          if (e.target.files && e.target.files.length > 0) {
            handleFileChange(e.target.files[0]);
          }
        }}
      />

      {/* Dropzone Container */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !disabled && !uploading && fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-all ${
          isDragging
            ? "border-cyan-500 bg-cyan-950/20"
            : selectedFile
            ? "border-slate-700 bg-slate-950/80"
            : "border-slate-800 bg-slate-950/40 hover:border-slate-700 hover:bg-slate-950/60"
        } ${disabled || uploading ? "opacity-50 cursor-not-allowed" : ""}`}
      >
        {selectedFile ? (
          <div className="flex flex-col items-center justify-center font-mono">
            <FileCode className="w-8 h-8 text-cyan-400 mb-2" />
            <p className="text-sm font-semibold text-slate-200">{selectedFile.name}</p>
            <p className="text-xs text-slate-400 mt-0.5">{formatBytes(selectedFile.size)}</p>
            <span className="text-[11px] text-cyan-400 mt-2 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              Ready for forensic stream processing
            </span>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center text-slate-400">
            <Upload className="w-8 h-8 text-slate-500 mb-2" />
            <p className="text-sm font-medium text-slate-300">
              Drag & drop a <span className="font-mono text-cyan-400">.pcap</span> or{" "}
              <span className="font-mono text-cyan-400">.pcapng</span> file here
            </p>
            <p className="text-xs text-slate-500 mt-1">or click to browse local filesystem</p>
          </div>
        )}
      </div>

      {/* Upload Action Bar */}
      {selectedFile && (
        <div className="mt-4 flex items-center justify-between pt-3 border-t border-slate-800/80">
          <button
            type="button"
            onClick={() => setSelectedFile(null)}
            disabled={uploading}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs font-mono rounded transition-colors"
          >
            Clear Selection
          </button>

          <button
            type="button"
            onClick={handleUploadSubmit}
            disabled={uploading || disabled}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 text-xs font-mono font-bold rounded transition-colors flex items-center gap-2"
          >
            {uploading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Uploading & Ingesting...
              </>
            ) : (
              <>Start Stream Analysis</>
            )}
          </button>
        </div>
      )}
    </div>
  );
};
