// The full-screen screenshot viewer shared by /changelog, /themes and the
// homepage's Ninja gallery (LandingPage.tsx loads it on the first click, with
// /static-pages.js). The static pages inline it through static-page-chrome.ts;
// the homepage imports this module on demand so the string stays off the boot
// path. Plain data: no imports, so a Node build can read it too.
export const LIGHTBOX_CSS = `.cl-lb{position:fixed;inset:0;z-index:100;background:rgba(8,10,14,.88);display:flex;align-items:safe center;justify-content:center;padding:20px 76px;overflow-y:auto}
.cl-lb[hidden]{display:none}
.cl-lb .lb-fig{display:flex;flex-direction:column;max-width:100%}
.cl-lb img{display:block;max-width:min(100%,1600px);max-height:max(200px,calc(100dvh - 40px - var(--lb-dock,70px)));width:auto;height:auto;border-radius:10px 10px 0 0;background:var(--bg)}
.cl-lb .lb-dock{width:0;min-width:100%;container-type:inline-size;padding:12px 12px 12px 16px;border-radius:0 0 10px 10px;background:#161a20;border-top:1px solid rgba(255,255,255,.08);color:#e7e9ec;text-align:left}
.cl-lb .lb-in{display:flex;align-items:center;gap:10px 20px}
@container (max-width:620px){.cl-lb .lb-in{flex-direction:column;align-items:stretch}.cl-lb .lb-acts{width:100%;flex-wrap:wrap}.cl-lb .lb-btn{flex:1 1 auto}}
.cl-lb .lb-info{flex:1;min-width:0}
.cl-lb .lb-head{display:flex;align-items:baseline;flex-wrap:wrap;gap:2px 12px}
.cl-lb .lb-t{margin:0;font-size:14px;line-height:1.45}
.cl-lb.lb-code .lb-t{color:#fff;font-size:19px;font-weight:650;line-height:1.3}
.cl-lb .lb-m{margin:0;color:#a3a9b2;font-size:12.5px;font-variant-numeric:tabular-nums}
.cl-lb .lb-m a{color:#d6dae0;text-decoration:none}
.cl-lb .lb-m a:hover{color:#fff;text-decoration:underline}
.cl-lb .lb-d{margin:3px 0 0;max-width:72ch;color:#c3c8cf;font-size:13.5px;line-height:1.5;text-wrap:pretty}
.cl-lb .lb-m[hidden],.cl-lb .lb-d[hidden]{display:none}
.cl-lb .lb-acts{display:flex;gap:8px;flex-shrink:0}
.cl-lb .lb-acts:not(:has(>:not([hidden]))){display:none}
.cl-lb .lb-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 12px;border:1px solid rgba(255,255,255,.18);border-radius:9px;background:rgba(255,255,255,.08);color:#fff;font:inherit;font-size:13.5px;font-weight:600;line-height:1.3;text-decoration:none;white-space:nowrap;cursor:pointer}
.cl-lb .lb-btn:hover{background:rgba(255,255,255,.16);text-decoration:none}
.cl-lb .lb-btn:focus-visible{outline:2px solid #fff;outline-offset:2px}
.cl-lb .lb-btn[hidden]{display:none}
.cl-lb .lb-btn kbd{margin-left:2px;padding:0 5px;border:1px solid rgba(255,255,255,.28);border-radius:5px;font:inherit;font-size:11.5px;line-height:17px;color:#c3c8cf;font-variant-numeric:tabular-nums}
.cl-lb .lb-copy .ic-done{display:none}
.cl-lb .lb-copy.on{color:#5ee08f;border-color:#5ee08f}
.cl-lb .lb-copy.on .ic-copy{display:none}
.cl-lb .lb-copy.on .ic-done{display:block}
.cl-lb>button{position:absolute;display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border:0;border-radius:10px;background:rgba(255,255,255,.1);color:#fff;cursor:pointer}
.cl-lb>button:hover{background:rgba(255,255,255,.2)}
.cl-lb .lb-x{top:16px;right:16px}
.cl-lb .lb-p{left:16px;top:50%;margin-top:-22px}
.cl-lb .lb-n{right:16px;top:50%;margin-top:-22px}
.cl-lb>button[hidden]{display:none}
@media(hover:none){.cl-lb .lb-copy kbd{display:none}}
@media(max-height:520px) and (min-width:641px){.cl-lb .lb-fig{flex-direction:row;align-items:center;gap:8px}.cl-lb img{max-height:calc(100dvh - 40px);max-width:calc(100vw - 440px);border-radius:10px}.cl-lb .lb-dock{width:280px;min-width:0;max-height:calc(100dvh - 40px);overflow-y:auto;border-radius:10px;border-top:0}.cl-lb .lb-in{width:100%}}
@media(max-width:640px){.cl-lb{padding:68px 8px 76px}.cl-lb img{max-height:max(160px,calc(100dvh - 144px - var(--lb-dock,70px)))}.cl-lb .lb-p,.cl-lb .lb-n{top:auto;bottom:16px;margin:0}}`;
