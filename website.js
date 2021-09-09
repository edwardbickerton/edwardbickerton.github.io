// Reuseable header
const headerTemplate = document.createElement('template');
headerTemplate.innerHTML = `
  <link rel="stylesheet" href="style.css" />
  <header>
    <nav>
      <a href="index.html"><button class="header_btn">home</button></a>
      <a href="blog.html"><button class="header_btn">blog</button></a>
      <a href="node.html"><button class="header_btn">node</button></a>
      <a href="bisq.html"><button class="header_btn" id="buy_btn">buy BTC</button></a>
    </nav>
    <hr>
  </header>
`;

class Header extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {
    const shadowRoot = this.attachShadow({ mode: 'closed' });
    shadowRoot.appendChild(headerTemplate.content);
  }
}

customElements.define('header-component', Header);
// End of reuseable header

// Reuseable footer
const footerTemplate = document.createElement('template');
footerTemplate.innerHTML = `
  <link rel="stylesheet" href="style.css" />
  <br>
  <footer>
    <hr>
    <ul id="footer_list">

      <li><a href="https://twitter.com/Satsuma_LN" target=_blank><button class="footer_btn">
        Twitter
      </button></a></li>

      <li><a href="https://t.me/Satsuma_LN" target=_blank><button class="footer_btn">
        Telegram
      </button></a></li>

    </ul>
  </footer>
`;

class Footer extends HTMLElement {
  constructor() {
    super();
  }

  connectedCallback() {
    const shadowRoot = this.attachShadow({ mode: 'closed' });
    shadowRoot.appendChild(footerTemplate.content);
  }
}

customElements.define('footer-component', Footer);
// End of reuseable footer