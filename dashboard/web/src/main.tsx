import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes, useParams } from "react-router-dom";
import "./index.css";
import { Layout } from "./Layout";
import { Datasets } from "./pages/Datasets";
import { DatasetDetail } from "./pages/DatasetDetail";
import { Detections, NoRun } from "./pages/Detections";
import { Evaluation, ExperimentPage } from "./pages/Evaluation";
import { Explorer, ExplorerIndex } from "./pages/Explorer";
import { Lineage } from "./pages/Lineage";
import { Live } from "./pages/Live";
import { Overview } from "./pages/Overview";
import { RunDetail, Runs } from "./pages/Runs";
import { System } from "./pages/System";
import { WorkspaceProvider } from "./Workspace";
import { PageHeader } from "./components/ui";

function NotFound() {
  return <PageHeader title="Not found">This page does not exist.</PageHeader>;
}

// Keyed by id so state resets when navigating between datasets/runs.
function Keyed({ children }: { children: (key: string) => JSX.Element }) {
  const { id = "" } = useParams();
  return children(id);
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <WorkspaceProvider>
        <Layout>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/datasets" element={<Datasets />} />
            <Route path="/datasets/:id" element={<Keyed>{(id) => <DatasetDetail key={id} />}</Keyed>} />
            <Route path="/explore" element={<ExplorerIndex />} />
            <Route path="/explore/:id" element={<Keyed>{(id) => <Explorer key={id} />}</Keyed>} />
            <Route path="/runs" element={<Runs />} />
            <Route path="/runs/:id" element={<Keyed>{(id) => <RunDetail key={id} />}</Keyed>} />
            <Route path="/runs/:id/detections" element={<Keyed>{(id) => <Detections key={id} />}</Keyed>} />
            <Route path="/runs/:id/lineage" element={<Keyed>{(id) => <Lineage key={id} />}</Keyed>} />
            <Route path="/detections" element={<NoRun what="detections" />} />
            <Route path="/lineage" element={<NoRun what="lineage" />} />
            <Route path="/live" element={<Live />} />
            <Route path="/evaluation" element={<Evaluation />} />
            <Route path="/experiments/:id" element={<ExperimentPage />} />
            <Route path="/system" element={<System />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Layout>
      </WorkspaceProvider>
    </BrowserRouter>
  </StrictMode>,
);
