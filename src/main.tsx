import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { GuidelinesProvider } from "./contexts/GuidelinesContext";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <GuidelinesProvider>
      <App />
    </GuidelinesProvider>
  </React.StrictMode>,
);
