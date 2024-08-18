// Reuseable header (buy btc button <a href="/html/blog_posts/bisq.html"><button class="header_btn" id="buy_btn">buy BTC</button></a>)
const headerTemplate = document.createElement("template");
headerTemplate.innerHTML = `
  <link rel="stylesheet" href="/CSS/style.css" />
  <header>
    <nav>
      <a href="/index.html"><button class="header_btn">Home</button></a>
      <a href="https://github.com/edwardbickerton" target="_blank"><button class="header_btn">GitHub</button></a>
      <a href="https://www.linkedin.com/in/edward-bickerton/" target="_blank"><button class="header_btn">LinkedIn</button></a>
    </nav>
    <hr>
  </header>
`;

class Header extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {
    const shadowRoot = this.attachShadow({ mode: "closed" });
    shadowRoot.appendChild(headerTemplate.content);
  }
}

customElements.define("header-component", Header);
// End of reuseable header

// Reuseable footer
const footerTemplate = document.createElement("template");
footerTemplate.innerHTML = `
  <link rel="stylesheet" href="/CSS/style.css" />
  <br>
  <footer>
    <hr>
    <ul id="footer_list">
      <li><a href="/index.html"><button class="footer_btn">
        Home
      </button></a></li>
      <li><a href="https://github.com/edwardbickerton" target="_blank"><button class="footer_btn">
        GitHub
      </button></a></li>
      <li><a href="https://www.linkedin.com/in/edward-bickerton/" target=_blank><button class="footer_btn">
        LinkedIn
      </button></a></li>

    </ul>
  </footer>
`;

class Footer extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {
    const shadowRoot = this.attachShadow({ mode: "closed" });
    shadowRoot.appendChild(footerTemplate.content);
  }
}

customElements.define("footer-component", Footer);
// End of reuseable footer
