// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from 'react';
import { agentsApi } from '../../api/client';
import { downloadFilename, evidenceFilename, saveFile } from '../shared/download';
import { errorMessage } from '../shared/ui';

const BTN = 'px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-800 text-sm font-medium hover:bg-slate-50 disabled:opacity-50';

export const EVIDENCE_NOTE =
  'One JSON document for an auditor: the agent, its registration and decisions, reviews, containment, risk, tool gateway policy hashes and latest release, and what could not be read.';

/**
 * Downloads the evidence document of one agent. The file is fetched with the bearer token like
 * every other read and saved under the name the server gave. Nothing is previewed.
 */
export default function EvidenceDownload({ agentId, agentName }: { agentId: string; agentName: string }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  const run = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const file = await agentsApi.evidence(agentId);
      // The server names the file. If its header cannot be read, the same name is built here.
      const filename = downloadFilename(file.contentDisposition, evidenceFilename(agentName, agentId, new Date()));
      saveFile(file.blob, filename);
      setMessage({ text: `Saved ${filename}.`, error: false });
    } catch (err) {
      setMessage({ text: `The evidence could not be downloaded. ${errorMessage(err, '')}`.trim(), error: true });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-sm">
      <button type="button" className={BTN} disabled={busy} aria-describedby="evidence-note" onClick={() => void run()}>
        {busy ? 'Preparing…' : 'Download evidence'}
      </button>
      <p id="evidence-note" className="text-xs text-slate-600 mt-1">{EVIDENCE_NOTE}</p>
      <p role="status" className={`text-xs mt-1 ${message?.error ? 'text-red-700' : 'text-slate-700'}`}>{message?.text}</p>
    </div>
  );
}
