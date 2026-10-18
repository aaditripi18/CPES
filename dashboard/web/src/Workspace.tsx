import { createContext, ReactNode, useContext } from "react";
import { useLocalState } from "./lib/hooks";

interface Workspace {
  datasetId: string | null;
  runId: string | null;
  setDatasetId: (id: string | null) => void;
  setRunId: (id: string | null) => void;
}

const Context = createContext<Workspace>({ datasetId: null, runId: null, setDatasetId: () => undefined, setRunId: () => undefined });

/** The dataset and run the user is currently looking at (remembered per browser). */
export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [datasetId, setDatasetId] = useLocalState<string | null>("cpes.dataset", null);
  const [runId, setRunId] = useLocalState<string | null>("cpes.run", null);
  return <Context.Provider value={{ datasetId, runId, setDatasetId, setRunId }}>{children}</Context.Provider>;
}

export const useWorkspace = () => useContext(Context);
