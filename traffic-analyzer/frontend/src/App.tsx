import { useCallback, useEffect, useState } from 'react';
import { errorMessage } from './api/client';
import { getHosts, getPackets, getProtocols, getSummary } from './api/endpoints';
import { DEFAULT_PAGE_SIZE, EMPTY_FILTERS } from './api/params';
import type { PacketFilters } from './api/params';
import type {
  CaptureSummary,
  HostEntry,
  PacketPage,
  ProtocolCount,
} from './api/types';
import { buildTimeline } from './lib/timeline';
import type { Timeline } from './lib/timeline';
import { CapturePanel } from './components/CapturePanel';
import { ChartsSection } from './components/ChartsSection';
import { ExportBar } from './components/ExportBar';
import { HealthBanner } from './components/HealthBanner';
import { ImportPanel } from './components/ImportPanel';
import { PacketExplorer } from './components/PacketExplorer';
import { SummaryView } from './components/SummaryView';

const EMPTY_TIMELINE: Timeline = { buckets: [], bucketSeconds: 0, covered: 0 };

/** The API caps a page at 1000 rows; the timeline is built from that bounded sample. */
const TIMELINE_SAMPLE_LIMIT = 1000;

export default function App() {
  const [analysisId, setAnalysisId] = useState<string | null>(null);

  const [summary, setSummary] = useState<CaptureSummary | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [protocols, setProtocols] = useState<ProtocolCount[]>([]);
  const [protocolTotal, setProtocolTotal] = useState(0);
  const [hosts, setHosts] = useState<HostEntry[]>([]);
  const [hostTotal, setHostTotal] = useState(0);

  const [page, setPage] = useState<PacketPage | null>(null);
  const [packetsError, setPacketsError] = useState<string | null>(null);
  const [loadingPackets, setLoadingPackets] = useState(false);

  const [filters, setFilters] = useState<PacketFilters>(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(DEFAULT_PAGE_SIZE);

  const [timeline, setTimeline] = useState<Timeline>(EMPTY_TIMELINE);
  const [timelineSampleSize, setTimelineSampleSize] = useState(0);
  const [timelineError, setTimelineError] = useState<string | null>(null);

  const loadAnalysis = useCallback((id: string) => {
    setAnalysisId(id);
    setOffset(0);
    setFilters({ ...EMPTY_FILTERS });
  }, []);

  // Summary, protocol distribution and host statistics for the loaded analysis.
  useEffect(() => {
    if (!analysisId) {
      setSummary(null);
      setSummaryError(null);
      setProtocols([]);
      setProtocolTotal(0);
      setHosts([]);
      setHostTotal(0);
      return;
    }
    let cancelled = false;

    getSummary(analysisId)
      .then((result) => {
        if (cancelled) return;
        setSummary(result);
        setSummaryError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setSummary(null);
        setSummaryError(errorMessage(error));
      });

    getProtocols(analysisId)
      .then((result) => {
        if (cancelled) return;
        setProtocols(result.items);
        setProtocolTotal(result.total);
      })
      .catch(() => {
        if (cancelled) return;
        setProtocols([]);
        setProtocolTotal(0);
      });

    getHosts(analysisId)
      .then((result) => {
        if (cancelled) return;
        setHosts(result.items);
        setHostTotal(result.total);
      })
      .catch(() => {
        if (cancelled) return;
        setHosts([]);
        setHostTotal(0);
      });

    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  // One page of packets. The whole capture is never downloaded in one request.
  useEffect(() => {
    if (!analysisId) {
      setPage(null);
      setPacketsError(null);
      return;
    }
    let cancelled = false;
    setLoadingPackets(true);
    getPackets(analysisId, filters, { limit, offset })
      .then((result) => {
        if (cancelled) return;
        setPage(result);
        setPacketsError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setPage(null);
        setPacketsError(errorMessage(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoadingPackets(false);
      });
    return () => {
      cancelled = true;
    };
  }, [analysisId, filters, offset, limit]);

  // Timeline sample: the API has no timeline endpoint, so a bounded page of
  // packets is bucketed in the browser.
  useEffect(() => {
    if (!analysisId) {
      setTimeline(EMPTY_TIMELINE);
      setTimelineSampleSize(0);
      setTimelineError(null);
      return;
    }
    let cancelled = false;
    getPackets(analysisId, EMPTY_FILTERS, { limit: TIMELINE_SAMPLE_LIMIT, offset: 0 })
      .then((result) => {
        if (cancelled) return;
        setTimeline(buildTimeline(result.items));
        setTimelineSampleSize(result.items.length);
        setTimelineError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setTimeline(EMPTY_TIMELINE);
        setTimelineSampleSize(0);
        setTimelineError(errorMessage(error));
      });
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  const applyFilters = (next: PacketFilters) => {
    setFilters({ ...next });
  };

  const packetTotal = page?.total ?? summary?.packet_count ?? 0;

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>HTTP/HTTPS Traffic Analyzer</h1>
          <p className="app-tagline">
            Import a capture, inspect the packets, and export what you find. All values come
            from the analysis API — nothing is estimated in the browser.
          </p>
        </div>
        {analysisId ? (
          <p className="app-analysis-id">
            Loaded analysis: <code>{analysisId}</code>
          </p>
        ) : null}
      </header>

      <main className="app-layout">
        <div className="sidebar">
          <HealthBanner />
          <ImportPanel onAnalysisReady={loadAnalysis} />
          <CapturePanel onAnalysisReady={loadAnalysis} />
          <ExportBar analysisId={analysisId} filters={filters} />
        </div>

        <div className="content">
          <SummaryView summary={summary} error={summaryError} />
          <ChartsSection
            protocols={protocols}
            protocolTotal={protocolTotal}
            hosts={hosts}
            hostTotal={hostTotal}
            timeline={timeline}
            timelineSampleSize={timelineSampleSize}
            packetTotal={packetTotal}
            hasAnalysis={analysisId !== null}
          />
          {timelineError ? (
            <p className="notice notice-warn" role="status">
              <span className="notice-text">
                The timeline sample could not be loaded: {timelineError}
              </span>
            </p>
          ) : null}
          <PacketExplorer
            filters={filters}
            onApplyFilters={applyFilters}
            page={page}
            error={packetsError}
            loading={loadingPackets}
            limit={limit}
            offset={offset}
            onLimitChange={setLimit}
            onOffsetChange={setOffset}
            hasAnalysis={analysisId !== null}
          />
        </div>
      </main>

      <footer className="app-footer">
        <p>
          Byte totals count the bytes on the wire (whole frame, link header included). Timestamps
          are UTC. A missing value is shown as “—”, never as 0.
        </p>
      </footer>
    </div>
  );
}
