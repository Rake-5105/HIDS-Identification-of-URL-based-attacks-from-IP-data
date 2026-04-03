import { Upload, FileText, File, X } from 'lucide-react';
import { useState } from 'react';

const FileUpload = ({ fileType, onUpload, accept }) => {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);

  const icons = {
    logs: FileText,
    pcap: File,
    csv: File
  };

  const Icon = icons[fileType] || File;

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setProgress(0);

    try {
      const result = await onUpload(file, (progressEvent) => {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setProgress(percentCompleted);
      });

      return result;
    } finally {
      setUploading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="space-y-4">
      {/* Drop zone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-xl p-8 transition-colors ${
          dragActive
            ? 'border-blue-500 bg-blue-50'
            : 'border-gray-300 bg-white hover:border-gray-400'
        }`}
      >
        <input
          type="file"
          accept={accept}
          onChange={handleChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={uploading}
        />

        <div className="text-center">
          <div className="inline-flex p-4 bg-gray-100 rounded-full mb-4">
            <Icon size={32} className="text-gray-600" />
          </div>

          {file ? (
            <div className="space-y-2">
              <p className="text-sm font-medium text-gray-900">{file.name}</p>
              <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setFile(null);
                }}
                className="inline-flex items-center space-x-1 text-sm text-red-600 hover:text-red-700"
              >
                <X size={16} />
                <span>Remove</span>
              </button>
            </div>
          ) : (
            <>
              <p className="text-sm font-medium text-gray-900 mb-1">
                Drag & drop your file here, or click to browse
              </p>
              <p className="text-xs text-gray-500">
                Accepted formats: {accept}
              </p>
            </>
          )}
        </div>
      </div>

      {/* Upload progress */}
      {uploading && (
        <div className="space-y-2">
          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-600 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-sm text-center text-gray-600">Uploading... {progress}%</p>
        </div>
      )}

      {/* Upload button */}
      {file && !uploading && (
        <button
          onClick={handleUpload}
          className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2"
        >
          <Upload size={20} />
          <span>Upload File</span>
        </button>
      )}
    </div>
  );
};

export default FileUpload;
