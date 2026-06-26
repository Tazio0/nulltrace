import { useEffect, useRef, useState } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import GlobeCanvas from "./GlobeCanvas.jsx";
import markUrl from "../assets/nulltrace-mark.svg";
import { feedItems, futureEndpoints, metrics, navItems, pipeline, routes } from "./data.js";

export default function App() {
  const rootRef = useRef(null);
  const [activeSection, setActiveSection] = useState("signal");

  useEffect(() => {
    const sections = Array.from(document.querySelectorAll("[data-section]"));
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];

        if (visible) setActiveSection(visible.target.id);
      },
      { rootMargin: "-36% 0px -44% 0px", threshold: [0.01, 0.25, 0.6] }
    );

    sections.forEach((section) => observer.observe(section));

    const syncHash = () => {
      if (!window.location.hash) return;

      const target = document.querySelector(window.location.hash);
      if (target) {
        window.setTimeout(() => target.scrollIntoView({ block: "start" }), 80);
      }
    };

    syncHash();
    window.addEventListener("hashchange", syncHash);

    return () => {
      observer.disconnect();
      window.removeEventListener("hashchange", syncHash);
    };
  }, []);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) return undefined;

    gsap.registerPlugin(ScrollTrigger);
    const ctx = gsap.context(() => {
      gsap.utils.toArray(".story-section").forEach((section) => {
        const card = section.querySelector(".section-card");
        const reveals = section.querySelectorAll("[data-reveal]");

        if (card) {
          gsap.fromTo(
            card,
            { autoAlpha: 0, y: 44 },
            {
              autoAlpha: 1,
              y: 0,
              duration: 0.75,
              ease: "power3.out",
              scrollTrigger: {
                trigger: section,
                start: "top 72%",
                toggleActions: "play none none reverse"
              }
            }
          );
        }

        if (reveals.length) {
          gsap.fromTo(
            reveals,
            { autoAlpha: 0, y: 34 },
            {
              autoAlpha: 1,
              y: 0,
              stagger: 0.08,
              duration: 0.75,
              ease: "power3.out",
              scrollTrigger: {
                trigger: section,
                start: "top 62%"
              }
            }
          );
        }
      });

      gsap.to(".globe-frame", {
        scale: 0.82,
        xPercent: -5,
        autoAlpha: 0.7,
        ease: "none",
        scrollTrigger: {
          trigger: "#feed",
          start: "top bottom",
          endTrigger: "#system",
          end: "bottom bottom",
          scrub: true
        }
      });

      gsap.to(".signal-stream", {
        yPercent: -18,
        autoAlpha: 0.22,
        ease: "none",
        scrollTrigger: {
          trigger: "#monitor",
          start: "top bottom",
          endTrigger: "#exports",
          end: "bottom center",
          scrub: true
        }
      });
    }, rootRef.current);

    return () => ctx.revert();
  }, []);

  return (
    <div className={`app scene-${activeSection}`} ref={rootRef}>
      <a className="skip-link" href="#signal">Skip to content</a>

      <VisualBackplane activeSection={activeSection} />
      <Header activeSection={activeSection} />

      <main>
        <HeroSection />
        <MonitorSection />
        <FeedSection />
        <DiscordSection />
        <ExportsSection />
        <SystemSection />
      </main>
    </div>
  );
}

function VisualBackplane({ activeSection }) {
  return (
    <div className="visual-backplane" aria-hidden="true">
      <div className="backplane-vignette" />
      <div className="backplane-grid" />
      <div className="globe-frame">
        <GlobeCanvas activeSection={activeSection} routes={routes} />
      </div>
      <div className="signal-stream">
        {routes.slice(0, 4).map((route) => (
          <span key={route.id} style={{ "--stream-color": route.color }}>
            {route.originCode} / {route.targetCode}
          </span>
        ))}
      </div>
      <div className="scanline" />
    </div>
  );
}

function Header({ activeSection }) {
  return (
    <header className="site-header">
      <a className="brand" href="#signal" aria-label="Nulltrace home">
        <img src={markUrl} alt="" />
        <span>
          <strong>Nulltrace</strong>
          <small>Signal intelligence</small>
        </span>
      </a>

      <nav className="section-nav" aria-label="Page sections">
        {navItems.map((item) => (
          <a key={item.id} className={activeSection === item.id ? "active" : ""} href={`#${item.id}`}>
            {item.label}
          </a>
        ))}
      </nav>
    </header>
  );
}

function HeroSection() {
  return (
    <section id="signal" className="story-section hero-section" data-section>
      <div className="hero-minimal" aria-label="Nulltrace globe overview">
        <span>Nulltrace</span>
        <strong>Global signal map</strong>
      </div>

      <a className="scroll-cue" href="#monitor" aria-label="Scroll to monitor section">
        <span>Open console</span>
        <i aria-hidden="true" />
      </a>
    </section>
  );
}

function MonitorSection() {
  return (
    <section id="monitor" className="story-section monitor-section" data-section>
      <div className="section-card wide-card dashboard-card">
        <SectionIntro kicker="Monitor" title="A live surface for threat movement." />

        <div className="metric-grid">
          {metrics.map((metric) => (
            <article key={metric.label} className="metric-tile" data-reveal>
              <span>{metric.label}</span>
              <strong>{metric.value}</strong>
              <small>{metric.detail}</small>
            </article>
          ))}
        </div>

        <div className="monitor-console" data-reveal>
          <div className="console-map">
            <span className="console-node za">ZA</span>
            <span className="console-node eu">EU</span>
            <span className="console-node us">US</span>
            <span className="console-node apac">APAC</span>
            <svg viewBox="0 0 720 360" role="img" aria-label="Signal paths">
              <path d="M130 235 C260 80 390 210 570 126" />
              <path d="M94 148 C234 270 404 72 642 218" />
              <path d="M178 302 C296 224 426 282 624 92" />
            </svg>
          </div>
          <div className="console-feed">
            {routes.slice(0, 5).map((route) => (
              <div key={route.id} className="console-row">
                <span>{route.severity}</span>
                <strong>{route.originCode}{" -> "}{route.targetCode}</strong>
                <small>{route.count} events</small>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function FeedSection() {
  return (
    <section id="feed" className="story-section feed-section" data-section>
      <div className="section-card split-card">
        <div>
          <SectionIntro kicker="Threat feed" title="Signals worth slowing down for." />
          <p className="section-note">High-confidence indicators, grouped for review before action.</p>
        </div>

        <div className="feed-stack">
          {feedItems.map((item) => (
            <article key={item.indicator} className={`feed-card ${item.severity}`} data-reveal>
              <div className="feed-card-top">
                <span>{item.source}</span>
                <b>{item.severity}</b>
              </div>
              <h3>{item.indicator}</h3>
              <p>{item.context}</p>
              <div className="tag-row">
                {item.meta.map((tag) => <small key={tag}>{tag}</small>)}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function DiscordSection() {
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookStatus, setWebhookStatus] = useState({ type: "idle", message: "" });

  const handleWebhookSubmit = async (event) => {
    event.preventDefault();

    const trimmedUrl = webhookUrl.trim();
    const isDiscordWebhook = /^https:\/\/(?:(?:canary|ptb)\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w.-]+(?:\?.*)?$/i.test(trimmedUrl);

    if (!isDiscordWebhook) {
      setWebhookStatus({
        type: "error",
        message: "Paste a Discord webhook URL from Server Settings > Integrations > Webhooks."
      });
      return;
    }

    setWebhookStatus({ type: "sending", message: "Sending a test alert to your Discord channel..." });

    const payload = {
      username: "Nulltrace",
      allowed_mentions: { parse: [] },
      embeds: [
        {
          title: "Nulltrace connected",
          description: "Reviewed threat alerts can now land in this channel.",
          color: 0xf5f5f1,
          fields: [
            { name: "Signal", value: "Webhook test", inline: true },
            { name: "Severity", value: "Demo", inline: true },
            { name: "Next", value: "Wire live backend alerts when ready." }
          ],
          timestamp: new Date().toISOString()
        }
      ]
    };

    try {
      const response = await fetch(trimmedUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Discord returned ${response.status}`);
      }

      setWebhookStatus({ type: "success", message: "Installed. Check the channel for the Nulltrace test alert." });
    } catch (error) {
      setWebhookStatus({
        type: "error",
        message: "Could not send the test alert from the browser. If Discord blocks it, proxy this through FastAPI."
      });
    }
  };

  return (
    <section id="discord" className="story-section discord-section" data-section>
      <div className="section-card split-card reverse">
        <div className="discord-panel" data-reveal>
          <div className="discord-topbar">
            <span>Nulltrace relay</span>
            <strong># high-signal-alerts</strong>
          </div>
          <div className="discord-message">
            <img src={markUrl} alt="" />
            <div>
              <div className="message-meta">
                <strong>Nulltrace</strong>
                <span>Today at 22:31</span>
              </div>
              <div className="embed-card">
                <span className="embed-rule" />
                <h3>Critical Threat Detected</h3>
                <p>AbuseIPDB route converged on ZA watch lane.</p>
                <dl>
                  <div><dt>Indicator</dt><dd>185.220.101.42</dd></div>
                  <div><dt>Origin</dt><dd>Lagos, NG</dd></div>
                  <div><dt>Target</dt><dd>Johannesburg, ZA</dd></div>
                  <div><dt>Action</dt><dd>Review export</dd></div>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div>
          <SectionIntro kicker="Discord" title="Alerts that land cleanly." />
          <p className="section-note">Paste a channel webhook, send a test alert, and confirm the channel is ready before wiring live backend notifications.</p>

          <form className="webhook-form" onSubmit={handleWebhookSubmit} data-reveal>
            <label htmlFor="discord-webhook">Discord webhook URL</label>
            <div className="webhook-control">
              <input
                id="discord-webhook"
                type="url"
                value={webhookUrl}
                onChange={(event) => {
                  setWebhookUrl(event.target.value);
                  if (webhookStatus.type !== "idle") setWebhookStatus({ type: "idle", message: "" });
                }}
                placeholder="https://discord.com/api/webhooks/..."
                autoComplete="off"
              />
              <button className="button primary" type="submit" disabled={webhookStatus.type === "sending"}>
                {webhookStatus.type === "sending" ? "Sending..." : "Install webhook"}
              </button>
            </div>
            <p className={`webhook-status ${webhookStatus.type}`} aria-live="polite">
              {webhookStatus.message || "Your webhook is only used for this test request."}
            </p>
          </form>
        </div>
      </div>
    </section>
  );
}

function ExportsSection() {
  const exportPreview = [
    "# Review before applying",
    "sudo ufw deny from 185.220.101.42 comment \"Nulltrace critical IOC\"",
    "sudo iptables -A INPUT -s 91.240.118.172 -j DROP",
    "",
    "# Domains stay in DNS/proxy review",
    "malicious-login-check.xyz"
  ].join("\n");

  return (
    <section id="exports" className="story-section exports-section" data-section>
      <div className="section-card split-card">
        <div>
          <SectionIntro kicker="Exports" title="Reviewed signals become action." />
          <div className="export-options" data-reveal>
            <span>Blocklist</span>
            <span>UFW</span>
            <span>iptables</span>
            <span>MikroTik</span>
            <span>JSON</span>
          </div>
        </div>

        <pre className="export-preview" data-reveal>{exportPreview}</pre>
      </div>
    </section>
  );
}

function SystemSection() {
  return (
    <section id="system" className="story-section system-section" data-section>
      <div className="section-card wide-card final-card">
        <SectionIntro kicker="System" title="Built around the pipeline underneath." />

        <div className="pipeline" data-reveal>
          {pipeline.map((step, index) => (
            <article key={step}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{step}</strong>
            </article>
          ))}
        </div>

        <div className="endpoint-panel" data-reveal>
          <p>Future live-data hooks</p>
          <div>
            {futureEndpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}
          </div>
        </div>

        <footer>
          <span>Defensive demo only</span>
          <span>No sound</span>
          <span>Mock data ready for API wiring</span>
        </footer>
      </div>
    </section>
  );
}

function SectionIntro({ kicker, title }) {
  return (
    <div className="section-intro" data-reveal>
      <p className="eyebrow">{kicker}</p>
      <h2>{title}</h2>
    </div>
  );
}
