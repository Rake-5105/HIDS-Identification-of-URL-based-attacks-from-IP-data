import { useState } from 'react';
import { FileText, File, CheckCircle, ArrowRight, Download, Link as LinkIcon } from 'lucide-react';
import axios from 'axios';
import FileUpload from '../components/FileUpload';
import Playbook from '../components/Playbook';
import { BouncingDots } from '../components/ui/BouncingDots';
import { useNavigate } from 'react-router-dom';
import { useUpload } from '../context/UploadContext';

const Upload = () => {
  const [activeTab, setActiveTab] = useState('logs');
  const [uploadResult, setUploadResult] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [processingStatus, setProcessingStatus] = useState(null);
  const [urlInput, setUrlInput] = useState('');
  const [urlPrepared, setUrlPrepared] = useState(null);
  const [urlProcessing, setUrlProcessing] = useState(false);
  const [urlProcessingStatus, setUrlProcessingStatus] = useState(null);
  const [urlResult, setUrlResult] = useState(null);
  const navigate = useNavigate();
  const { saveResult } = useUpload();

  const tabs = [
    { id: 'logs', label: 'Log Files', icon: FileText, accept: '.log,.txt' },
    { id: 'pcap', label: 'PCAP Files', icon: File, accept: '.pcap,.pcapng' },
    { id: 'csv', label: 'CSV Files', icon: File, accept: '.csv' },
    { id: 'url', label: 'URL Analysis', icon: LinkIcon, accept: '' }
  ];

  const normalizeUrl = (value) => {
    const trimmed = value.trim();
    if (!trimmed) return '';

    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  };

  const formatForDisplay = (value) => {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);

    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  };

  const normalizePatterns = (patterns) => {
    if (!patterns) return [];
    if (Array.isArray(patterns)) {
      return patterns.map((item) => formatForDisplay(item)).filter(Boolean);
    }
    return [formatForDisplay(patterns)].filter(Boolean);
  };

  const getUrlAnalysisSummary = () => {
    const attackTypeRaw = formatForDisplay(urlResult?.analysis?.attackType) || 'Unknown';
    const attackType = attackTypeRaw.trim();
    const isThreat = attackType.toLowerCase() !== 'normal' && attackType.toLowerCase() !== 'none';
    const riskLevel = formatForDisplay(urlResult?.analysis?.riskLevel) || 'Unknown';
    const modelName = formatForDisplay(urlResult?.model) || 'Ollama phi3';

    return {
      totalEntries: 1,
      threatsFound: isThreat ? 1 : 0,
      threatRate: isThreat ? '100.0%' : '0.0%',
      modelName,
      attackType,
      riskLevel
    };
  };

  const buildUrlCsvContent = () => {
    const summary = getUrlAnalysisSummary();
    const patterns = normalizePatterns(urlResult?.analysis?.patterns);

    const rows = [
      ['Field', 'Value'],
      ['URL', urlResult?.url || ''],
      ['Attack Type', summary.attackType],
      ['Risk Level', summary.riskLevel],
      ['Threats Found', String(summary.threatsFound)],
      ['Threat Rate', summary.threatRate],
      ['AI Model', summary.modelName],
      ['Recommended Action', formatForDisplay(urlResult?.analysis?.action) || ''],
      ['Explanation', formatForDisplay(urlResult?.analysis?.explanation) || ''],
      ['Suspicious Patterns', patterns.join(' | ') || 'None']
    ];

    return rows
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
  };

  const buildUrlTxtContent = () => {
    const summary = getUrlAnalysisSummary();
    const patterns = normalizePatterns(urlResult?.analysis?.patterns);

    return [
      'HIDS URL Analysis Report',
      '========================',
      `URL: ${urlResult?.url || ''}`,
      `Attack Type: ${summary.attackType}`,
      `Risk Level: ${summary.riskLevel}`,
      `Threats Found: ${summary.threatsFound}`,
      `Threat Rate: ${summary.threatRate}`,
      `AI Model: ${summary.modelName}`,
      '',
      'Suspicious Patterns:',
      patterns.length ? patterns.map((pattern) => `- ${pattern}`).join('\n') : '- None',
      '',
      'Recommended Action:',
      formatForDisplay(urlResult?.analysis?.action) || 'N/A',
      '',
      'Explanation:',
      formatForDisplay(urlResult?.analysis?.explanation) || 'N/A'
    ].join('\n');
  };

  const buildUrlHistoryResult = (resultData) => {
    const attackTypeRaw = formatForDisplay(resultData?.analysis?.attackType) || 'Unknown';
    const attackType = attackTypeRaw.trim() || 'Unknown';
    const isThreat = !['normal', 'none', 'unknown'].includes(attackType.toLowerCase());
    const classification_breakdown = {
      [attackType]: 1
    };

    return {
      upload_id: urlPrepared?.upload_id || `url_${Date.now().toString(16)}`,
      filename: resultData?.url ? `url_${new URL(resultData.url).hostname}` : 'URL Analysis',
      analyzedAt: new Date().toISOString(),
      total_requests: 1,
      threats_detected: isThreat ? 1 : 0,
      threat_percentage: isThreat ? 100 : 0,
      analyzed_with: formatForDisplay(resultData?.model) || 'phi3',
      classification_breakdown,
      analyzed_url: resultData?.url || ''
    };
  };

  const handleDownloadUrlReport = (format) => {
    if (!urlResult) return;

    const content = format === 'csv' ? buildUrlCsvContent() : buildUrlTxtContent();
    const mimeType = format === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
    const safeTime = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `hids_url_report_${safeTime}.${format}`;

    const blob = new Blob([content], { type: mimeType });
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(downloadUrl);
    document.body.removeChild(a);
  };

  const handlePrepareUrl = () => {
    const normalized = normalizeUrl(urlInput);

    if (!normalized) {
      setUrlResult({
        error: 'Please enter a URL to analyze.'
      });
      return;
    }

    try {
      // Validate URL format before sending to backend.
      new URL(normalized);
    } catch {
      setUrlResult({
        error: 'Please enter a valid URL.'
      });
      return;
    }

    setUrlResult(null);
    setUrlProcessingStatus(null);
    setUrlPrepared({
      url: normalized,
      upload_id: `url_${Date.now().toString(16)}`
    });
  };

  const handleRunUrlAnalysis = async () => {
    if (!urlPrepared?.url) return;

    setUrlProcessing(true);
    setUrlResult(null);
    setUrlProcessingStatus({ status: 'processing', progress: 5, message: 'Initializing Phi3 AI...' });

    let fakeProgress = 5;
    const progressTicker = setInterval(() => {
      fakeProgress = Math.min(fakeProgress + 7, 92);
      let message = 'Preparing URL for parsing...';

      if (fakeProgress >= 25 && fakeProgress < 55) {
        message = 'Parsing URL components...';
      } else if (fakeProgress >= 55 && fakeProgress < 85) {
        message = 'Analyzing URL patterns with Phi3...';
      } else if (fakeProgress >= 85) {
        message = 'Generating final report...';
      }

      setUrlProcessingStatus({ status: 'processing', progress: fakeProgress, message });
    }, 700);

    try {
      const response = await axios.post('/api/ai/analyze-url', {
        url: urlPrepared.url
      });

      const historyEntry = buildUrlHistoryResult(response.data);
      saveResult(historyEntry);

      clearInterval(progressTicker);
      setUrlProcessing(false);
      setUrlProcessingStatus({ status: 'completed', progress: 100, message: 'Phi3 AI analysis completed.' });
      setUrlResult(response.data);
    } catch (error) {
      clearInterval(progressTicker);
      setUrlProcessing(false);
      setUrlProcessingStatus({
        status: 'failed',
        progress: fakeProgress,
        message: error.response?.data?.message || error.response?.data?.error || 'URL analysis failed'
      });
      setUrlResult({
        error: error.response?.data?.message || error.response?.data?.error || 'URL analysis failed'
      });
    }
  };

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
    setProcessingStatus({ status: 'processing', progress: 0, message: 'Initializing Phi3 AI...' });

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

            // Save results to shared context when completed
            if (statusResponse.data.status === 'completed' && statusResponse.data.results) {
              saveResult({
                ...statusResponse.data.results,
                upload_id: uploadResult.upload_id,
                filename: uploadResult.filename,
                analyzedAt: new Date().toISOString()
              });
            }
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

  const handleDownload = async (format) => {
    if (!uploadResult?.upload_id) return;

    try {
      const response = await axios.get(`/api/upload/download/${format}/${uploadResult.upload_id}`, {
        responseType: 'blob'
      });

      const blob = new Blob([response.data], {
        type: format === 'csv' ? 'text/csv' : 'text/plain'
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `hids_report_${uploadResult.upload_id.substring(0, 8)}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
      alert('Download failed. Please try again.');
    }
  };

  const getProgressSteps = () => {
    if (!processingStatus) return [];

    const steps = [
      { label: 'Upload', status: 'completed' },
      { label: 'Parsing', status: processingStatus.progress > 20 ? 'completed' : 'pending' },
      { label: 'Phi3 AI Analysis', status: processingStatus.progress > 50 ? 'completed' : 'pending' },
      { label: 'Report Generation', status: processingStatus.progress > 85 ? 'completed' : 'pending' },
      { label: 'Complete', status: processingStatus.status === 'completed' ? 'completed' : 'pending' }
    ];

    return steps;
  };

  const getUrlProgressSteps = () => {
    if (!urlProcessingStatus) return [];

    const progress = urlProcessingStatus.progress || 0;
    return [
      { label: 'Upload', status: 'completed' },
      { label: 'Parsing', status: progress > 20 ? 'completed' : 'pending' },
      { label: 'Phi3 AI Analysis', status: progress > 50 ? 'completed' : 'pending' },
      { label: 'Report Generation', status: progress > 85 ? 'completed' : 'pending' },
      { label: 'Complete', status: urlProcessingStatus.status === 'completed' ? 'completed' : 'pending' }
    ];
  };

  const getPlaybookDetectedAttacks = () => {
    if (processingStatus?.status === 'completed' && processingStatus?.results?.classification_breakdown) {
      return processingStatus.results.classification_breakdown;
    }

    if (activeTab === 'url' && urlProcessingStatus?.status === 'completed' && urlResult?.analysis) {
      const attackType = (formatForDisplay(urlResult.analysis.attackType) || '').trim();
      if (!attackType) return null;
      return { [attackType]: 1 };
    }

    return null;
  };

  // Get detected attacks from processing results for the playbook
  const detectedAttacks = getPlaybookDetectedAttacks();

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Upload & Analyze</h1>

      {/* Two-column layout: Upload (left) + Playbook (right) */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">

        {/* ── Left Column: Upload Section ── */}
        <div className="space-y-6">
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
                      setUrlPrepared(null);
                      setUrlProcessing(false);
                      setUrlProcessingStatus(null);
                      setUrlResult(null);
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

            {/* File Upload Component */}
            {!uploadResult && activeTab !== 'url' && (
              <FileUpload
                fileType={activeTab}
                accept={tabs.find(t => t.id === activeTab).accept}
                onUpload={handleUpload}
              />
            )}

            {/* URL Analysis Component */}
            {activeTab === 'url' && (
              <div className="space-y-4">
                {!urlPrepared && !urlProcessingStatus && (
                  <>
                    <div>
                      <label htmlFor="url-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        URL to Analyze
                      </label>
                      <input
                        id="url-input"
                        type="text"
                        value={urlInput}
                        onChange={(e) => setUrlInput(e.target.value)}
                        placeholder="https://example.com/login?user=admin"
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                      />
                    </div>

                    <button
                      onClick={handlePrepareUrl}
                      className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2"
                    >
                      <span>Prepare URL Analysis</span>
                      <ArrowRight size={20} />
                    </button>
                  </>
                )}

                {urlPrepared && !urlProcessing && !urlProcessingStatus && (
                  <div className="space-y-4">
                    <div className="flex items-center space-x-3 p-4 bg-green-50 border border-green-200 rounded-lg">
                      <CheckCircle className="w-6 h-6 text-green-600 flex-shrink-0" />
                      <div className="flex-1">
                        <p className="font-medium text-green-900">Upload Successful</p>
                        <p className="text-sm text-green-700 break-all">{urlPrepared.url}</p>
                        <p className="text-xs text-green-600 mt-1">
                          Upload ID: {urlPrepared.upload_id}
                        </p>
                      </div>
                    </div>

                    <button
                      onClick={handleRunUrlAnalysis}
                      className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2"
                    >
                      <span>🤖 Run Phi3 AI Analysis</span>
                      <ArrowRight size={20} />
                    </button>

                    <button
                      onClick={() => {
                        setUrlPrepared(null);
                        setUrlInput('');
                        setUrlResult(null);
                      }}
                      className="w-full py-2 px-4 text-gray-600 hover:text-gray-900 transition-colors"
                    >
                      Use Different URL
                    </button>
                  </div>
                )}

                {(urlProcessing || urlProcessingStatus) && (
                  <div className="space-y-6">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="font-medium text-gray-900">{urlProcessingStatus?.message || 'Processing...'}</span>
                        <span className="text-gray-600">{urlProcessingStatus?.progress || 0}%</span>
                      </div>
                      <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-600 transition-all duration-300"
                          style={{ width: `${urlProcessingStatus?.progress || 0}%` }}
                        />
                      </div>
                    </div>

                    <div className="space-y-3">
                      {getUrlProgressSteps().map((step, idx) => (
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
                          {urlProcessing && step.status === 'pending' && idx === getUrlProgressSteps().findIndex((s) => s.status === 'pending') && (
                            <BouncingDots dots={3} className="w-2 h-2 bg-blue-500" />
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {urlResult?.error && (
                  <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                    <p className="font-medium text-red-900">URL Analysis Failed</p>
                    <p className="text-sm text-red-700 mt-1">{urlResult.error}</p>
                    <button
                      onClick={() => {
                        setUrlProcessingStatus(null);
                        setUrlPrepared(null);
                      }}
                      className="mt-3 py-2 px-4 bg-gray-100 text-gray-700 font-medium rounded-lg hover:bg-gray-200 transition-colors"
                    >
                      Try Again
                    </button>
                  </div>
                )}

                {urlResult && !urlResult.error && urlProcessingStatus?.status === 'completed' && (
                  <div className="mt-6 space-y-4">
                    <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                      <p className="font-medium text-green-900">✅ Phi3 AI Analysis Complete!</p>
                      <p className="text-sm text-green-700 mt-1">
                        Your URL has been analyzed by Ollama Phi3 AI.
                      </p>
                    </div>

                    <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                      <p className="text-sm font-medium text-gray-900 mb-3">Analysis Summary:</p>
                      <div className="grid grid-cols-2 gap-3 text-sm">
                        <div className="bg-white p-3 rounded-lg border">
                          <p className="text-gray-500">Total Entries</p>
                          <p className="text-2xl font-bold text-gray-900">{getUrlAnalysisSummary().totalEntries}</p>
                        </div>
                        <div className="bg-white p-3 rounded-lg border">
                          <p className="text-gray-500">Threats Found</p>
                          <p className="text-2xl font-bold text-red-600">{getUrlAnalysisSummary().threatsFound}</p>
                        </div>
                        <div className="bg-white p-3 rounded-lg border">
                          <p className="text-gray-500">Threat Rate</p>
                          <p className="text-2xl font-bold text-orange-600">{getUrlAnalysisSummary().threatRate}</p>
                        </div>
                        <div className="bg-white p-3 rounded-lg border">
                          <p className="text-gray-500">AI Model</p>
                          <p className="text-lg font-bold text-blue-600">{getUrlAnalysisSummary().modelName}</p>
                        </div>
                      </div>

                      <div className="mt-3 bg-white p-3 rounded-lg border">
                        <p className="text-sm font-medium text-gray-700 mb-2">Classification Breakdown:</p>
                        <div className="flex flex-wrap gap-2">
                          <span className="px-3 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                            {getUrlAnalysisSummary().attackType}: 1
                          </span>
                          <span className="px-3 py-1 rounded-full text-xs font-medium bg-amber-100 text-amber-800">
                            Risk: {getUrlAnalysisSummary().riskLevel}
                          </span>
                        </div>
                      </div>

                      {normalizePatterns(urlResult.analysis?.patterns).length > 0 && (
                        <div className="mt-3 bg-white p-3 rounded-lg border">
                          <p className="text-sm font-medium text-gray-700 mb-2">Suspicious Patterns:</p>
                          <ul className="list-disc list-inside text-sm text-gray-700 space-y-1">
                            {normalizePatterns(urlResult.analysis?.patterns).map((pattern, index) => (
                              <li key={`${pattern}-${index}`}>{pattern}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <button
                        onClick={() => handleDownloadUrlReport('csv')}
                        className="py-3 px-4 bg-emerald-600 text-white font-medium rounded-lg hover:bg-emerald-700 transition-colors flex items-center justify-center space-x-2"
                      >
                        <Download size={20} />
                        <span>Download CSV Report</span>
                      </button>
                      <button
                        onClick={() => handleDownloadUrlReport('txt')}
                        className="py-3 px-4 bg-indigo-600 text-white font-medium rounded-lg hover:bg-indigo-700 transition-colors flex items-center justify-center space-x-2"
                      >
                        <Download size={20} />
                        <span>Download TXT Report</span>
                      </button>
                    </div>

                    <button
                      onClick={() => navigate('/app/dashboard')}
                      className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      View in Dashboard
                    </button>

                    <button
                      onClick={() => {
                        setUrlInput('');
                        setUrlPrepared(null);
                        setUrlProcessingStatus(null);
                        setUrlResult(null);
                      }}
                      className="w-full py-2 px-4 text-gray-600 hover:text-gray-900 transition-colors"
                    >
                      Analyze Another URL
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Upload Success */}
            {activeTab !== 'url' && uploadResult && !processing && !processingStatus && (
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
                  <span>🤖 Run Phi3 AI Analysis</span>
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
            {activeTab !== 'url' && (processing || processingStatus) && (
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
                        <BouncingDots dots={3} className="w-2 h-2 bg-blue-500" />
                      )}
                    </div>
                  ))}
                </div>

                {/* Results + Download */}
                {processingStatus?.status === 'completed' && (
                  <div className="mt-6 space-y-4">
                    <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                      <p className="font-medium text-green-900">✅ Phi3 AI Analysis Complete!</p>
                      <p className="text-sm text-green-700 mt-1">
                        Your file has been analyzed by Ollama Phi3 AI.
                      </p>
                    </div>

                    {processingStatus.results && (
                      <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                        <p className="text-sm font-medium text-gray-900 mb-3">Analysis Summary:</p>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div className="bg-white p-3 rounded-lg border">
                            <p className="text-gray-500">Total Entries</p>
                            <p className="text-2xl font-bold text-gray-900">{processingStatus.results.total_requests || 0}</p>
                          </div>
                          <div className="bg-white p-3 rounded-lg border">
                            <p className="text-gray-500">Threats Found</p>
                            <p className="text-2xl font-bold text-red-600">{processingStatus.results.threats_detected || 0}</p>
                          </div>
                          <div className="bg-white p-3 rounded-lg border">
                            <p className="text-gray-500">Threat Rate</p>
                            <p className="text-2xl font-bold text-orange-600">{processingStatus.results.threat_percentage || 0}%</p>
                          </div>
                          <div className="bg-white p-3 rounded-lg border">
                            <p className="text-gray-500">AI Model</p>
                            <p className="text-lg font-bold text-blue-600">{processingStatus.results.analyzed_with || 'Phi3'}</p>
                          </div>
                        </div>

                        {processingStatus.results.classification_breakdown && (
                          <div className="mt-3 bg-white p-3 rounded-lg border">
                            <p className="text-sm font-medium text-gray-700 mb-2">Classification Breakdown:</p>
                            <div className="flex flex-wrap gap-2">
                              {Object.entries(processingStatus.results.classification_breakdown).map(([cls, count]) => (
                                <span key={cls} className={`px-3 py-1 rounded-full text-xs font-medium ${
                                  cls.toLowerCase() === 'normal' ? 'bg-green-100 text-green-800' :
                                  cls.toLowerCase().includes('sql') ? 'bg-red-100 text-red-800' :
                                  cls.toLowerCase().includes('xss') ? 'bg-orange-100 text-orange-800' :
                                  cls.toLowerCase().includes('path') ? 'bg-yellow-100 text-yellow-800' :
                                  cls.toLowerCase().includes('command') ? 'bg-purple-100 text-purple-800' :
                                  'bg-gray-100 text-gray-800'
                                }`}>
                                  {cls}: {count}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Download Buttons */}
                    <div className="grid grid-cols-2 gap-3">
                      <button
                        onClick={() => handleDownload('csv')}
                        className="py-3 px-4 bg-emerald-600 text-white font-medium rounded-lg hover:bg-emerald-700 transition-colors flex items-center justify-center space-x-2"
                      >
                        <Download size={20} />
                        <span>Download CSV Report</span>
                      </button>
                      <button
                        onClick={() => handleDownload('txt')}
                        className="py-3 px-4 bg-indigo-600 text-white font-medium rounded-lg hover:bg-indigo-700 transition-colors flex items-center justify-center space-x-2"
                      >
                        <Download size={20} />
                        <span>Download TXT Report</span>
                      </button>
                    </div>

                    <button
                      onClick={() => navigate('/app/dashboard')}
                      className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      View in Dashboard
                    </button>

                    <button
                      onClick={() => {
                        setUploadResult(null);
                        setProcessingStatus(null);
                      }}
                      className="w-full py-2 px-4 text-gray-600 hover:text-gray-900 transition-colors"
                    >
                      Analyze Another File
                    </button>
                  </div>
                )}

                {processingStatus?.status === 'failed' && (
                  <div className="mt-6 space-y-3">
                    <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                      <p className="font-medium text-red-900">Processing Failed</p>
                      <p className="text-sm text-red-700 mt-1">{processingStatus.message}</p>
                    </div>
                    <button
                      onClick={() => {
                        setProcessingStatus(null);
                        setProcessing(false);
                      }}
                      className="w-full py-2 px-4 bg-gray-100 text-gray-700 font-medium rounded-lg hover:bg-gray-200 transition-colors"
                    >
                      Try Again
                    </button>
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
              <li>Or use URL Analysis to inspect a single URL directly</li>
              <li>Click "Run Phi3 AI Analysis" to process with Ollama's AI</li>
              <li>Monitor the progress as Phi3 analyzes each entry</li>
              <li>Download the report as <strong>CSV</strong> or <strong>TXT</strong> for further investigation</li>
            </ul>
          </div>
        </div>

        {/* ── Right Column: Security Playbook ── */}
        <div className="xl:sticky xl:top-6" style={{ maxHeight: 'calc(100vh - 6rem)' }}>
          <Playbook detectedAttacks={detectedAttacks} />
        </div>

      </div>
    </div>
  );
};

export default Upload;
