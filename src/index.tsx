/* @refresh reload */
import "./index.css";

import { Router, Route } from "@solidjs/router";
import { render } from "solid-js/web";

import Layout from "./components/layout";

import DIDWeb from "./pages/did-web";

const root = document.getElementById("root");

render(
  () => (
    <Router root={Layout}>
      <Route path="/" component={DIDWeb} />
    </Router>
  ),
  root!,
);
