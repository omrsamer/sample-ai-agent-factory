// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { Handle, Position } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import type { FlowNode } from './layout';
import { nodeContext } from './enrich';
import { kindBadge } from '../agentUi';
import { gatewayNotRead } from '../gatewayView';
import { platformHostLabel, mcpHostLabel } from '../platformLabels';
import type { McpServerKind } from '../../../api/client';

const CARD =
  'group/node relative flex items-center gap-2.5 w-[180px] h-[60px] px-3 ' +
  'rounded-2xl border bg-white shadow-sm transition-shadow hover:shadow-md ' +
  'cursor-grab active:cursor-grabbing overflow-hidden';
const LABEL = 'text-sm font-semibold text-slate-900 leading-tight truncate';
const SUBLABEL = 'text-[11px] text-slate-600 leading-tight truncate';

const RAIL = 'absolute inset-y-0 left-0 w-1';

const PILL = 'inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium';

const HOST_TAG =
  'inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium ' +
  'bg-slate-100 text-slate-600';

const HANDLE = '!w-1 !h-1 !min-w-0 !border-0 !bg-transparent';

function NodeHandles() {
  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} className={HANDLE} />
      <Handle type="source" position={Position.Right} isConnectable={false} className={HANDLE} />
    </>
  );
}

function PersonGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" className={className}>
      <path d="M10 10a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm0 1.5c-3.1 0-6 1.6-6 3.8V17h12v-1.7c0-2.2-2.9-3.8-6-3.8Z" />
    </svg>
  );
}

function GroupGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 22 20" fill="currentColor" aria-hidden="true" className={className}>
      <path d="M7 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm8 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM7 10.5c-2.6 0-5 1.3-5 3.3V16h10v-2.2c0-2-2.4-3.3-5-3.3Zm8 0c-.5 0-1 .05-1.5.15 1 .8 1.5 1.9 1.5 3.15V16h5v-2.2c0-2-2.4-3.3-5-3.3Z" />
    </svg>
  );
}

function McpGlyph({ className }: { className?: string }) {

  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" className={className}>
      <path d="M4 3h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm0 9h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1Zm2-7.5a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Zm0 9a.75.75 0 1 0 0 1.5.75.75 0 0 0 0-1.5Z" />
    </svg>
  );
}

function AgentGlyph({ className }: { className?: string }) {

  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" className={className}>
      <path d="M9 1.5a1 1 0 0 1 2 0V3h1.5A3.5 3.5 0 0 1 16 6.5v6A3.5 3.5 0 0 1 12.5 16h-5A3.5 3.5 0 0 1 4 12.5v-6A3.5 3.5 0 0 1 7.5 3H9V1.5ZM7.5 7a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Zm5 0a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5ZM7 12a.75.75 0 0 0 0 1.5h6a.75.75 0 0 0 0-1.5H7ZM2 8a1 1 0 0 1 1 1v2a1 1 0 1 1-2 0V9a1 1 0 0 1 1-1Zm16 0a1 1 0 0 1 1 1v2a1 1 0 1 1-2 0V9a1 1 0 0 1 1-1Z" />
    </svg>
  );
}

function IconChip({ tint, children }: { tint: string; children: React.ReactNode }) {
  return (
    <span
      aria-hidden="true"
      className={`shrink-0 h-9 w-9 rounded-lg flex items-center justify-center ${tint}`}
    >
      {children}
    </span>
  );
}

function TypeTag({ tint, children }: { tint: string; children: React.ReactNode }) {
  return <span className={`${PILL} ${tint}`}>{children}</span>;
}

export function UserNode({ data }: NodeProps<FlowNode>) {
  return (
    <div className={`${CARD} border-slate-200`} title={data.label}>
      <span className={`${RAIL} bg-blue-500`} aria-hidden="true" />
      <IconChip tint="bg-blue-50 text-blue-600">
        <PersonGlyph className="h-5 w-5" />
      </IconChip>
      <div className="min-w-0 flex-1">
        <div className={LABEL}>{data.label}</div>
        <div className={SUBLABEL}>User</div>
      </div>
      <NodeHandles />
    </div>
  );
}

export function GroupNode({ data }: NodeProps<FlowNode>) {
  return (
    <div className={`${CARD} border-cyan-200`} title={data.label}>
      <span className={`${RAIL} bg-cyan-500`} aria-hidden="true" />
      <IconChip tint="bg-cyan-50 text-cyan-600">
        <GroupGlyph className="h-5 w-5" />
      </IconChip>
      <div className="min-w-0 flex-1">
        <div className={LABEL}>{data.label}</div>
        <div className="mt-0.5">
          <span className={`${PILL} bg-cyan-50 text-cyan-700`}>Group</span>
        </div>
      </div>
      <NodeHandles />
    </div>
  );
}

const AGENT_RAIL = 'bg-teal-500';
const AGENT_TYPE_TAG = 'bg-teal-50 text-teal-700';

export function AgentNode({ data }: NodeProps<FlowNode>) {
  const host = platformHostLabel(String(data.metadata.platform ?? ''));
  // Two agents can carry one name: the tenant and the account tell them apart.
  const context = nodeContext(data.metadata);

  return (
    <div className={`${CARD} border-teal-200`} title={context ? `${data.label} · ${context}` : data.label}>
      <span className={`${RAIL} ${AGENT_RAIL}`} aria-hidden="true" />
      <IconChip tint="bg-teal-50 text-teal-600">
        <AgentGlyph className="h-5 w-5" />
      </IconChip>
      <div className="min-w-0 flex-1">
        <div className={LABEL}>{data.label}</div>
        <div className="mt-0.5 flex items-center gap-1 min-w-0">
          <TypeTag tint={AGENT_TYPE_TAG}>Agent</TypeTag>
          {data.metadata.contained === true ? (
            <span className={`${PILL} bg-red-700 text-white`}>Contained</span>
          ) : context ? (
            <span className={SUBLABEL}>{context}</span>
          ) : (
            host && <span className={HOST_TAG}>{host}</span>
          )}
        </div>
      </div>
      <NodeHandles />
    </div>
  );
}

const MCP_KINDS: ReadonlySet<string> = new Set<McpServerKind>(['gateway', 'runtime', 'standard']);

function mcpChipTint(kind: string): string {
  if (kind === 'gateway') return 'bg-violet-50 text-violet-600';
  if (kind === 'runtime') return 'bg-indigo-50 text-indigo-600';
  return 'bg-slate-100 text-slate-600';
}
function mcpRailTint(kind: string): string {
  if (kind === 'gateway') return 'bg-violet-500';
  if (kind === 'runtime') return 'bg-indigo-500';
  return 'bg-slate-300';
}

export function McpNode({ data }: NodeProps<FlowNode>) {
  const kindRaw = String(data.metadata.kind ?? '');
  const badge = MCP_KINDS.has(kindRaw) ? kindBadge(kindRaw as McpServerKind) : null;
  const host = mcpHostLabel(kindRaw);

  const typeTint = badge ? badge.cls : 'bg-slate-100 text-slate-600';
  const kindTitle = badge ? `Tool gateway · ${badge.label}` : 'Tool gateway';
  // A gateway that only the organization registry detected. It stands alone: who can call it,
  // and whether a policy stands between, is not known, so the API draws no edge to it.
  const notRead = gatewayNotRead({ reader_status: String(data.metadata.reader_status ?? ''), detail: null });

  return (
    <div className={`${CARD} ${notRead ? 'border-dashed border-slate-400' : 'border-slate-200'}`} title={notRead ? `${data.label}. ${notRead.title}.` : data.label}>
      <span className={`${RAIL} ${notRead ? 'bg-slate-300' : mcpRailTint(kindRaw)}`} aria-hidden="true" />
      <IconChip tint={mcpChipTint(kindRaw)}>
        <McpGlyph className="h-5 w-5" />
      </IconChip>
      <div className="min-w-0 flex-1">
        <div className={LABEL}>{data.label}</div>
        <div className="mt-0.5 flex items-center gap-1 min-w-0">
          <span className={`${PILL} ${typeTint}`} title={kindTitle}>Gateway</span>
          {/* Short, so that it fits beside the kind on one line; the detail panel says why. */}
          {notRead ? <span className={`${HOST_TAG} whitespace-nowrap`}>Not read</span> : host && <span className={HOST_TAG}>{host}</span>}
        </div>
      </div>
      <NodeHandles />
    </div>
  );
}

export const nodeTypes = {
  user: UserNode,
  group: GroupNode,
  agent: AgentNode,
  mcp: McpNode,
};
