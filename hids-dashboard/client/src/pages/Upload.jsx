import { useState } from 'react';
import { FileText, File, CheckCircle, ArrowRight, Loader } from 'lucide-react';
import axios from 'axios';
import FileUpload from '../components/FileUpload';
import { useNavigate } from 'react-router-dom';

const Upload = () => {
  const [activeTab, setActiveTab] = useState('logs');
  const [uploadResult, setUploadResult] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [processingStatus, setProcessingStatus] = useState(null);
  const navigate = useNavigate();

  const tabs = [
    { id: 'logs', label: 'Log Files', icon: FileText, accept: '.log,.txt' },
    { id: 'pcap', label: 'PCAP Files', icon: File, accept: '.pcap,.pcapng' },
    { id: 'csv', label: 'CSV Files', icon: File, accept: '.csv' }
  ];

  const handleUpload = async (file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`/api/upload/${activeTab}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: onProgress
      });

      setUploadResult(response.data);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.error || 'Upload failed');
    }
  };

  const handleRunAnalysis = async () => {
    if (!uploadResult?.upload_id) return;

    setProcessing(true);
    setProcessingStatus({ status: 'processing', progress: 0, message: 'Initializing...' });

    try {
      // Start processing
      await axios.post(`/api/upload/process/${uploadResult.upload_id}`);

      // Poll for status
      const pollInterval = setInterval(async () => {
        try {
          const statusResponse = await axios.get(`/api/upload/process/status/${uploadResult.upload_id}`);
          setProcessingStatus(statusResponse.data);

          if (statusResponse.data.status === 'completed' || statusResponse.data.status === 'failed') {
            clearInterval(pollInterval);
            setProcessing(false);
          }
        } catch (error) {
          clearInterval(pollInterval);
          setProcessing(false);
          setProcessingStatus({
            status: 'failed',
            message: 'Status check failed'
          });
        }
      }, 2000);
    } catch (error) {
      setProcessing(false);
      setProcessingStatus({
        status: 'failed',
        message: error.response?.data?.error || 'Processing failed'
      });
    }
  };

  const getProgressSteps = () => {
    if (!processingStatus) return [];

    const steps = [
      { label: 'Upload', status: 'completed' },
      { label: 'Parsing', status: processingStatus.progress > 25 ? 'completed' : 'pending' },
      { label: 'Feature Extraction', status: processingStatus.progress > 50 ? 'completed' : 'pending' },
      { label: 'Classification', status: processingStatus.progress > 75 ? 'completed' : 'pending' },
      { label: 'Complete', status: processingStatus.status === 'completed' ? 'completed' : 'pending' }
    ];

    return steps;
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-3xl font-bold text-gray-900">Upload & Analyze</h1>

      {/* File Type Tabs */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex space-x-2 mb-6 border-b border-gray-200">
          {tabs.map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setUploadResult(null);
                  setProcessingStatus(null);
                }}
                className={`flex items-center space-x-2 px-4 py-3 font-medium transition-colors border-b-2 ${
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-600 hover:text-gray-900'
                }`}
              >
                <Icon size={20} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Upload Component */}
        {!uploadResult && (
          <FileUpload
            fileType={activeTab}
            accept={tabs.find(t => t.id === activeTab).accept}
            onUpload={handleUpload}
          />
        )}

        {/* Upload Success */}
        {uploadResult && !processing && !processingStatus && (
          <div className="space-y-4">
            <div className="flex items-center space-x-3 p-4 bg-green-50 border border-green-200 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600 flex-shrink-0" />
              <div className="flex-1">
                <p className="font-medium text-green-900">Upload Successful</p>
                <p className="text-sm text-green-700">{uploadResult.filename}</p>
                <p className="text-xs text-green-600 mt-1">
                  Upload ID: {uploadResult.upload_id}
                </p>
              </div>
            </div>

            <button
              onClick={handleRunAnalysis}
              className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2"
            >
              <span>Run Analysis</span>
              <ArrowRight size={20} />
            </button>

            <button
              onClick={() => setUploadResult(null)}
              className="w-full py-2 px-4 text-gray-600 hover:text-gray-900 transition-colors"
            >
              Upload Different File
            </button>
          </div>
        )}

        {/* Processing Status */}
        {(processing || processingStatus) && (
          <div className="space-y-6">
            {/* Progress Bar */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium text-gray-900">{processingStatus?.message || 'Processing...'}</span>
                <span className="text-gray-600">{processingStatus?.progress || 0}%</span>
              </div>
              <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 transition-all duration-300"
                  style={{ width: `${processingStatus?.progress || 0}%` }}
                />
              </div>
            </div>

            {/* Progress Steps */}
            <div className="space-y-3">
              {getProgressSteps().map((step, idx) => (
                <div key={idx} className="flex items-center space-x-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                    step.status === 'completed'
                      ? 'bg-green-600 text-white'
                      : 'bg-gray-200 text-gray-600'
                  }`}>
                    {step.status === 'completed' ? (
                      <CheckCircle size={16} />
                    ) : (
                      <span className="text-sm">{idx + 1}</span>
                    )}
                  </div>
                  <span className={`font-medium ${
                    step.status === 'completed' ? 'text-gray-900' : 'text-gray-500'
                  }`}>
                    {step.label}
                  </span>
                  {processing && step.status === 'pending' && idx === getProgressSteps().findIndex(s => s.status === 'pending') && (
                    <Loader className="w-4 h-4 text-blue-600 animate-spin" />
                  )}
                </div>
              ))}
            </div>

            {/* Results */}
            {processingStatus?.status === 'completed' && (
              <div className="mt-6 space-y-4">
                <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                  <p className="font-medium text-green-900">Analysis Complete!</p>
                  <p className="text-sm text-green-700 mt-1">
                    Your file has been processed successfully.
                  </p>
                </div>

                {processingStatus.results && (
                  <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                    <p className="text-sm font-medium text-gray-900 mb-2">Summary:</p>
                    <pre className="text-xs text-gray-700 overflow-x-auto">
                      {JSON.stringify(processingStatus.results, null, 2)}
                    </pre>
                  </div>
                )}

                <button
                  onClick={() => navigate('/dashboard')}
                  className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
                >
                  View in Dashboard
                </button>
              </div>
            )}

            {processingStatus?.status === 'failed' && (
              <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                <p className="font-medium text-red-900">Processing Failed</p>
                <p className="text-sm text-red-700 mt-1">{processingStatus.message}</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Instructions */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
        <h3 className="font-semibold text-blue-900 mb-2">Instructions</h3>
        <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
          <li>Select the appropriate file type tab above</li>
          <li>Upload your file (max 50MB)</li>
          <li>Click "Run Analysis" to process the file through the ML pipeline</li>
          <li>Monitor the progress as your file is analyzed</li>
          <li>View results in the Dashboard once complete</li>
        </ul>
      </div>
    </div>
  );
};

export default Upload;
