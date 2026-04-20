import React from "react";
import ForceGraph2D from "react-force-graph-2d";

const data = {
  nodes: [
    { id: "Core" },
    { id: "Access1" },
    { id: "Access2" }
  ],
  links: [
    { source: "Core", target: "Access1" },
    { source: "Core", target: "Access2" }
  ]
};

function App() {
  return (
    <div style={{ height: "100vh" }}>
      <ForceGraph2D graphData={data} />
    </div>
  );
}

export default App;