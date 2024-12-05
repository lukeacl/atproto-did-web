import { ParentComponent } from "solid-js";

//relative z-10 mx-auto flex min-h-dvh max-w-xl flex-col-reverse

const Layout: ParentComponent = (props) => {
  return (
    <div class="max-w-xl mx-auto">
      <div class="min-h-dvh mx-2 p-4 bg-white shadow-xl">
        <header>
          <h1>ATProto</h1>
        </header>
        <main>{props.children}</main>
        <footer>
          <div class="credit">
            💕{" "}
            <a target="_blank" href="https://bsky.app/profile/lukeacl.com">
              @lukeacl.com
            </a>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Layout;
