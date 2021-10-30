// Reuseable header (buy btc button <a href="/html/blog_posts/bisq.html"><button class="header_btn" id="buy_btn">buy BTC</button></a>)
const headerTemplate = document.createElement('template');
headerTemplate.innerHTML = `
  <link rel="stylesheet" href="/CSS/style.css" />
  <header>
    <nav>
      <a href="/index.html"><button class="header_btn">home</button></a>
      <a href="/html/blog.html"><button class="header_btn">blog</button></a>
      <a href="/html/node.html"><button class="header_btn">node</button></a>
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
  <link rel="stylesheet" href="/CSS/style.css" />
  <br>
  <footer>
    <hr>
    <ul id="footer_list">
      <li><a href="mailto:satsuma_ln@icloud.com"><button class="footer_btn">
        Email
      </button></a></li>

      <li><a href="https://twitter.com/Satsuma_LN" target=_blank><button class="footer_btn">
        Twitter
      </button></a></li>

      <li><a href="https://t.me/Satsuma_LN" target=_blank><button class="footer_btn">
        Telegram
      </button></a></li>

      <li><a href="https://github.com/Satsuma-LN" target=_blank><button class="footer_btn">
        GitHub
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