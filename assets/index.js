'use strict';

// 이 페이지는 GAS 화면을 표시하는 래퍼일 뿐이며, postMessage를 인증·권한 판단에 사용하지 않습니다.
// 실제 로그인·권한 검증은 GAS 서버에서 수행됩니다.
if (window.top !== window.self) {
  document.body.replaceChildren();
  const main = document.createElement('main');
  const content = document.createElement('div');
  const title = document.createElement('h1');
  const message = document.createElement('p');

  main.className = 'blocked-access';
  title.textContent = '허용되지 않은 접근입니다.';
  message.textContent = '공식 홈페이지에서 접속해 주세요.';
  content.append(title, message);
  main.append(content);
  document.body.append(main);
}

// GAS 내부의 "보안 인증 오류" 복구 요청만 처리합니다.
// 인증·권한 정보는 메시지로 주고받지 않으며, 실제 iframe 창과 정확한 GAS 출처를 모두 확인합니다.
(function installSecureRefreshBridge() {
  const frame = document.getElementById('schoolSystemFrame');
  if (!frame) return;

  function createCacheBuster() {
    try {
      const values = new Uint32Array(4);
      crypto.getRandomValues(values);
      return Array.from(values, value => value.toString(16).padStart(8, '0')).join('');
    } catch (_) {
      return String(Date.now()) + String(Math.random()).slice(2);
    }
  }

  // 각 페이지 열기마다 부모와 GAS 화면만 공유하는 일회성 난수입니다.
  const bridgeNonce = createCacheBuster();
  // googleusercontent 중계 창은 출처만으로 신뢰하지 않고 handshake를
  // 완료한 창만 새로고침 요청을 보낼 수 있도록 추적합니다.
  const trustedMessageSources = new WeakSet();
  const gasUrl = new URL(frame.dataset.gasSrc);
  gasUrl.searchParams.set('hj_bridge_nonce', bridgeNonce);
  frame.src = gasUrl.toString();

  window.addEventListener('message', function(event) {
    const isGasOrigin = event.origin === 'https://script.google.com' ||
      /^https:\/\/[a-z0-9-]+-script\.googleusercontent\.com$/i.test(event.origin);
    if (!isGasOrigin || !event.data) return;

    // GAS 화면은 공식 GitHub 래퍼 안에 있을 때만 이 확인값을 받을 수 있습니다.
    if (event.data.type === 'HJ_PARENT_HANDSHAKE_REQUEST' &&
        typeof event.data.nonce === 'string' && event.data.nonce.length >= 16 &&
        event.data.nonce.length <= 128 && event.source) {
      trustedMessageSources.add(event.source);
      try {
        event.source.postMessage({ type: 'HJ_PARENT_HANDSHAKE_RESPONSE', nonce: event.data.nonce }, event.origin);
      } catch (_) {}
      return;
    }

    // GAS는 내부 iframe을 한 번 더 만들 수 있습니다. 직접 iframe 또는
    // GAS 전용 중계 출처만 후보로 확인한 뒤 일회성 난수까지 검증합니다.
    const isDirectFrame = event.source === frame.contentWindow;
    const isTrustedSource = isDirectFrame || trustedMessageSources.has(event.source);
    // GAS는 내부 중계 iframe을 추가할 수 있습니다. 이 경우에도 매번 새로 만든
    // bridgeNonce가 일치해야만 처리하므로, 단순히 googleusercontent 출처인
    // 다른 화면은 요청을 위조할 수 없습니다.
    if (!isTrustedSource || !event.data ||
        event.data.type !== 'HJ_FORCE_REFRESH' || event.data.nonce !== bridgeNonce) return;

    // GAS 화면이 요청을 정상 전달받았음을 알리고 곧바로 상위 페이지를 새로고침합니다.
    try {
      event.source.postMessage({ type: 'HJ_FORCE_REFRESH_ACK', nonce: bridgeNonce }, event.origin);
    } catch (_) {}
    const nextUrl = new URL('/index', window.location.origin);
    nextUrl.searchParams.set('_v', createCacheBuster());
    window.location.replace(nextUrl.toString());
  });
})();
