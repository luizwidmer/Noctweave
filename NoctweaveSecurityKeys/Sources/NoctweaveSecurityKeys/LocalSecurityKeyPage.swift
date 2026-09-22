// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

enum LocalSecurityKeyPage {
    static func html(options: Data, registration: Bool, token: String, nonce: String, brandImagePNG: Data? = nil, app: LocalSecurityKeyApp = .noctGallery) -> Data {
        // Only app-generated base64 data and random URL-safe tokens enter the document.
        // Key names, PINs, media, and other user content are never rendered here.
        let action = registration ? "Register Key" : "Verify Key"
        let ceremony = registration ? "create" : "get"
        let brand: String
        if let png = brandImagePNG, png.count <= 262_144, png.starts(with: [137, 80, 78, 71, 13, 10, 26, 10]) {
            brand = "<img class=\"mark\" src=\"data:image/png;base64,\(png.base64EncodedString())\" alt=\"\" width=\"64\" height=\"64\">"
        } else { brand = "<div class=\"mark fallback\" aria-hidden=\"true\">◇</div>" }
        let step = registration ? "Step 1 of 2 · Register" : "Security key"
        return Data("""
        <!doctype html><html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="color-scheme" content="light dark"><title>\(app.name)</title>
        <style nonce="\(nonce)">
        :root{font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;color:#1b1217;background:#faf6f2;-webkit-text-size-adjust:100%}
        *{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:24px;background:linear-gradient(145deg,#faf6f2,#f7eee9);font-size:17px;line-height:1.5}
        main{width:100%;max-width:420px;padding:28px;border:1px solid #d9c6c1;border-radius:28px;background:#fffdfb;text-align:center;box-shadow:0 12px 44px #922d350a}
        .mark{display:block;width:64px;height:64px;border-radius:16px;margin:0 auto 12px;box-shadow:0 4px 12px #1b121712}.fallback{font-size:42px;background:#2a1b21;color:#ebc7af}
        .brand{font-size:14px;font-weight:650;color:#755c60;margin:0 0 24px}.step{display:inline-block;border:1px solid #e6d2cb;background:#faf1ec;color:#922d35;border-radius:100px;padding:5px 12px;font-size:12px;font-weight:650;letter-spacing:.02em}
        h1{font-size:27px;line-height:1.2;letter-spacing:-.025em;margin:16px 0 12px;font-weight:750}p{color:#755c60;margin:0 0 20px}.intro{font-size:15px;line-height:1.55}
        button{display:block;width:100%;min-height:52px;font:650 17px/1.3 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;border:1px solid #922d35;border-radius:16px;color:#fffaf5;background:linear-gradient(130deg,#922d35,#a24448);padding:14px 16px;cursor:pointer;box-shadow:0 4px 10px #922d3514}
        button:disabled{opacity:.6;cursor:wait}button:focus-visible{outline:3px solid #c96a61;outline-offset:4px}#status{min-height:42px;font-size:13px;line-height:1.5;overflow-wrap:anywhere;margin:16px 0 0}.privacy{border-top:1px solid #eadbd5;margin:20px 0 0;padding-top:16px;font-size:12px;color:#866d70;display:flex;justify-content:center;align-items:center;gap:7px}.privacy svg{width:14px;height:14px;flex:none}
        @media(max-width:360px),(max-height:560px){body{padding:16px}main{padding:22px;border-radius:24px}.mark{width:56px;height:56px;border-radius:14px}.brand{margin-bottom:16px}h1{font-size:25px}.privacy{margin-top:16px}}
        @media(prefers-color-scheme:dark){:root{color:#faf3ea;background:#120b0f}body{background:linear-gradient(145deg,#120b0f,#1b1217)}main{background:#2a1b21;border-color:#56313a;box-shadow:0 12px 44px #0002}.brand,p{color:#cbb8b7}.step{background:#382129;border-color:#65404a;color:#ebc7af}button{border-color:#c96a6180;background:linear-gradient(130deg,#922d35,#a24448)}.privacy{border-color:#56313a;color:#c1a5a9}}
        </style></head><body><main>\(brand)<p class="brand">\(app.name)</p><div class="step" id="step">\(step)</div>
        <h1>\(action)</h1><p class="intro">Connect your security key and continue. Follow the system prompts for its PIN and touch.</p>
        <button id="continue">\(action)</button><p id="status" role="status">\(registration ? "Register first, then verify your key to finish." : "Your key is checked only on this device.")</p>
        <p class="privacy"><svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3.5" y="7" width="9" height="7" rx="2" stroke="currentColor"/><path d="M5 7V5a3 3 0 0 1 6 0v2" stroke="currentColor"/></svg>On-device · No account · No internet needed</p>
        </main><script nonce="\(nonce)">
        'use strict';
        let options=JSON.parse(atob('\(options.base64EncodedString())')),ceremony='\(ceremony)';
        const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
        const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
        function decodeOptions(options){
          options.challenge=decode(options.challenge);
          if(options.user)options.user.id=decode(options.user.id);
          for(const name of ['allowCredentials','excludeCredentials'])if(options[name])options[name]=options[name].map(c=>({...c,id:decode(c.id)}));
          return options;
        }
        options=decodeOptions(options);
        const button=document.querySelector('#continue'),status=document.querySelector('#status');
        async function complete(result){
          const response=await fetch('/\(token)/result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(result),credentials:'omit',cache:'no-store',redirect:'error'});
          if(!response.ok)throw new Error('local-session-closed');
          const reply=await response.json();
          if(reply.next){
            options=decodeOptions(JSON.parse(atob(reply.next)));ceremony='get';
            document.querySelector('h1').textContent='Verify Key';document.querySelector('#step').textContent='Step 2 of 2 · Verify';button.textContent='Finish Verification';
            document.querySelector('.intro').textContent='Your key was registered. Verify it once more to confirm that it can unlock \(app.name).';
            status.textContent='Keep your key connected. This is the final check.';
            button.disabled=false;
          }else if(reply.complete){location.href='\(app.callbackScheme)://complete/\(token)';}
          else throw new Error('local-session-closed');
        }
        button.onclick=async()=>{
          button.disabled=true;status.textContent='Follow the system prompts.';
          try{
            if(!isSecureContext||typeof PublicKeyCredential==='undefined')throw new Error('unsupported');
            const c=await navigator.credentials[ceremony]({publicKey:options});
            const r=c.response;
            const result={type:c.type,id:c.id,rawId:encode(c.rawId),authenticatorAttachment:c.authenticatorAttachment,response:{clientDataJSON:encode(r.clientDataJSON)}};
            if(r.attestationObject)result.response.attestationObject=encode(r.attestationObject);
            else{result.response.authenticatorData=encode(r.authenticatorData);result.response.signature=encode(r.signature);}
            status.textContent='Checking the key response…';await complete(result);
          }catch(error){
            try{await complete({error:['NotAllowedError','InvalidStateError','NotSupportedError','SecurityError','AbortError'].includes(error.name)?error.name:'Failed'});}
            catch{status.textContent='This check has ended. Close this sheet and try again in \(app.name).';}
          }
        };
        </script></body></html>
        """.utf8)
    }
}
