import { ParentComponent } from "solid-js";

import blueskyBrandsSolid from "../assets/bluesky-brands-solid.svg";
import githubBrandsSolid from "../assets/github-brands-solid.svg";

const Layout: ParentComponent = (props) => {
  return (
    <div class="max-w-xl mx-auto">
      <div class="min-h-dvh mx-2 p-4 bg-white shadow-xl">
        <header>
          <h1>ATProto</h1>
        </header>
        <main>{props.children}</main>
        <footer>
          <div class="credit flex">
            <div class="text-left flex-grow flex">
              <img
                src={blueskyBrandsSolid}
                width="14"
                height="14"
                class="mr-1"
              />{" "}
              <a target="_blank" href="https://bsky.app/profile/lukeacl.com">
                @lukeacl.com
              </a>{" "}
              <img
                src={githubBrandsSolid}
                width="14"
                height="14"
                class="ml-1 mr-1"
              />{" "}
              <a
                target="_blank"
                href="https://github.com/lukeacl/atproto-did-web"
              >
                lukeacl/atproto-did-web
              </a>
            </div>
            <div class="text-right flex-grow">v{__APP_VERSION__}</div>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Layout;
