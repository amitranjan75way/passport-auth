import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { ThemeProvider } from "@mui/material";
import theme from "./themes.ts";

import { BrowserRouter } from "react-router-dom";
import { Provider } from "react-redux";
import { store } from "./store/store.ts";
import { ToastContainer } from "react-toastify";
import { Toaster } from 'react-hot-toast';
import { ThemeContexProvider } from '../src/context/ThemeContext.tsx';
import ErrorBoundary from '../src/components/ErrorBoundry';

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <ThemeContexProvider>
        <BrowserRouter>
          <ThemeProvider theme={theme}>
            <Provider store={store}>
              <ToastContainer />
              <Toaster />
              <App />
            </Provider>
          </ThemeProvider>
        </BrowserRouter>
      </ThemeContexProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
