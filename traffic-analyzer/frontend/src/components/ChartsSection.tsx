import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { HostEntry, ProtocolCount } from '../api/types';
import type { Timeline } from '../lib/timeline';
import { formatBytes, formatNumber, formatPercent } from '../lib/format';
import { Card, EmptyState } from './ui';

const CHART_COLORS = ['#2563eb', '#0d9488', '#b45309', '#7c3aed', '#be123c', '#0369a1', '#4d7c0f', '#9d174d'];

export function ProtocolChart(props: { protocols: ProtocolCount[]; total: number }) {
  const { protocols, total } = props;

  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">
        Counts <strong>packets per application protocol</strong> in the loaded analysis
        ({formatNumber(total)} packets in total). The API reports one row per protocol.
      </figcaption>
      {protocols.length === 0 ? (
        <EmptyState title="No protocol data" message="The analysis contains no packets to distribute." />
      ) : (
        <div className="chart-frame">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={protocols} margin={{ top: 8, right: 16, bottom: 8, left: 4 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="protocol" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} allowDecimals={false} width={56} />
              <Tooltip
                formatter={(value: unknown, name: unknown) => [formatNumber(Number(value)), String(name)]}
              />
              <Bar name="Packets" dataKey="packets" radius={[4, 4, 0, 0]}>
                {protocols.map((entry, index) => (
                  <Cell key={entry.protocol} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      {protocols.length > 0 ? (
        <table className="mini-table">
          <caption>Application protocols (packets, bytes on the wire, share)</caption>
          <thead>
            <tr>
              <th scope="col">Protocol</th>
              <th scope="col">Packets</th>
              <th scope="col">Bytes</th>
              <th scope="col">Share</th>
            </tr>
          </thead>
          <tbody>
            {protocols.map((entry) => (
              <tr key={entry.protocol}>
                <th scope="row">{entry.protocol}</th>
                <td>{formatNumber(entry.packets)}</td>
                <td>{formatBytes(entry.bytes)}</td>
                <td>{formatPercent(entry.percentage)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </figure>
  );
}

export function HostsChart(props: { hosts: HostEntry[]; total: number }) {
  const { hosts, total } = props;
  const data = [...hosts].sort((a, b) => b.total_bytes - a.total_bytes).slice(0, 10);

  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">
        Counts <strong>bytes on the wire per host</strong> (sent + received), top {data.length} of{' '}
        {formatNumber(total)} hosts.
      </figcaption>
      {data.length === 0 ? (
        <EmptyState title="No host data" message="The analysis contains no host activity." />
      ) : (
        <div className="chart-frame chart-frame-tall">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 8 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 12 }} />
              <YAxis type="category" dataKey="ip" tick={{ fontSize: 12 }} width={140} />
              <Tooltip
                formatter={(value: unknown, name: unknown) => [formatBytes(Number(value)), String(name)]}
              />
              <Bar name="Bytes on the wire" dataKey="total_bytes" fill="#0d9488" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </figure>
  );
}

export function TimelineChart(props: {
  timeline: Timeline;
  sampleSize: number;
  totalPackets: number;
}) {
  const { timeline, sampleSize, totalPackets } = props;
  const complete = sampleSize > 0 && sampleSize >= totalPackets;

  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">
        Counts <strong>packets per {timeline.bucketSeconds || 1} second time bucket</strong> (UTC),
        built from {formatNumber(sampleSize)} of {formatNumber(totalPackets)} packets.
        {complete ? ' The sample covers the whole capture.' : ' This is a partial sample.'}
      </figcaption>
      {timeline.buckets.length === 0 ? (
        <EmptyState title="No timeline data" message="The analysis contains no timestamped packets." />
      ) : (
        <div className="chart-frame">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={timeline.buckets} margin={{ top: 8, right: 16, bottom: 8, left: 4 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 12 }} allowDecimals={false} width={56} />
              <Tooltip
                formatter={(value: unknown, name: unknown) => [formatNumber(Number(value)), String(name)]}
              />
              <Bar name="Packets" dataKey="packets" fill="#b45309" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </figure>
  );
}

export function ChartsSection(props: {
  protocols: ProtocolCount[];
  protocolTotal: number;
  hosts: HostEntry[];
  hostTotal: number;
  timeline: Timeline;
  timelineSampleSize: number;
  packetTotal: number;
  hasAnalysis: boolean;
}) {
  const {
    protocols,
    protocolTotal,
    hosts,
    hostTotal,
    timeline,
    timelineSampleSize,
    packetTotal,
    hasAnalysis,
  } = props;

  return (
    <Card
      title="Charts"
      description="Every chart is computed from the numbers the API returns for the loaded analysis."
    >
      {!hasAnalysis ? (
        <EmptyState
          title="No analysis loaded yet"
          message="Import a capture file or record a live capture to see the charts."
        />
      ) : (
        <div className="chart-grid">
          <ProtocolChart protocols={protocols} total={protocolTotal} />
          <HostsChart hosts={hosts} total={hostTotal} />
          <TimelineChart
            timeline={timeline}
            sampleSize={timelineSampleSize}
            totalPackets={packetTotal}
          />
        </div>
      )}
    </Card>
  );
}
