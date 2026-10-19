// Pelisjuanita GrayJay Source - con descifrado AES-CBC en JS puro

var PID = "c7e1a9f2-4b8d-4e3a-9c1f-6d5a2b8e7f41";
var UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
var BASE = "https://pelisjuanita.com/tv/app";
var TMDB_IMG = "https://image.tmdb.org/t/p/w500";

// Claves AES de la app original (si el descifrado falla, revisar que sean las reales)
var AES_KEY = "TuClaveSecretaSuperSeguraParaServidores2026!#".substring(0, 32);
var AES_IV  = "1234567890123456";

var PPID = new PlatformID("Pelisjuanita", "Pelisjuanita", PID);
var _debugLog = "";
var _channels = {};
var _jsProbed = false;
var _hostFail = {};
var _lastUrl = "";
// streamwish.to solo es un redirector (main.js hace window.location = "https://<espejo>" + ruta).
// Espejos confirmados abriendo streamwish.to/e/ID en el navegador.
var WISH_MIRRORS = ["medixiru.com", "hgplaycdn.com", "playnixes.com"];
var FAIL_ONCE_HOSTS = ["streamwish.to", "goodstream.one"];

function addDebug(msg) { _debugLog += String(msg) + "\n"; }

function httpGet(url, headers) {
    try {
        var h = headers || {};
        if (!h["User-Agent"]) h["User-Agent"] = UA;
        var r = http.GET(url, h);
        _lastUrl = (r && r.url) ? r.url : url;
        if (!r || !r.body) {
            addDebug("[http] vacío code=" + (r ? r.code : "?") + " " + String(url).substring(0, 60));
            return "";
        }
        return r.body;
    } catch (e) {
        addDebug("HTTP error: " + e);
        return "";
    }
}

function fixImg(path) {
    if (!path) return "";
    var s = String(path).trim();
    if (/^https?:\/\//i.test(s)) return s;
    s = s.replace(/^\/+/, "");
    if (!s) return "";
    if (!/\.(jpg|png|webp)$/i.test(s)) s += ".jpg";
    return TMDB_IMG + "/" + s;
}

function mkThumb(url) {
    if (!url) return new Thumbnails([]);
    return new Thumbnails([new Thumbnail(url, 100)]);
}

function mkVideo(id, title, thumb, url, author, isLive) {
    return new PlatformVideo({
        id: new PlatformID("Pelisjuanita", String(id), PID),
        name: title || "Sin título",
        thumbnails: mkThumb(thumb),
        author: new PlatformAuthorLink(PPID, author || "Pelisjuanita", "https://pelisjuanita.com", "", 0),
        uploadDate: 0, url: url, duration: 0, viewCount: 0, isLive: !!isLive
    });
}

function mkItem(type, slug, title, thumb) {
    if (type === "serie") {
        return new PlatformPlaylist({
            id: new PlatformID("Pelisjuanita", "s_" + slug, PID),
            name: "[Serie] " + (title || slug),
            thumbnail: thumb || "",
            author: new PlatformAuthorLink(PPID, "Pelisjuanita", "https://pelisjuanita.com", "", 0),
            datetime: 0, url: "pj://serie/" + slug, videoCount: -1
        });
    }
    return mkVideo(type + "_" + slug, title, thumb, "pj://" + type + "/" + slug, "Pelisjuanita");
}

function liveRequestModifier(ref) {
    ref = ref || "https://pelisjuanita.com/";
    var origin = "";
    try { origin = String(ref).match(/^(https?:\/\/[^\/?#]+)/i)[1]; } catch (e) {}
    var baseHeaders = { "User-Agent": UA, "Referer": ref };
    if (origin) baseHeaders["Origin"] = origin;
    return {
        allowByteSkip: true,
        headers: baseHeaders,
        modifyRequest: function (url, headers) {
            var h = headers || {}, k;
            for (k in baseHeaders) if (baseHeaders.hasOwnProperty(k) && !h[k]) h[k] = baseHeaders[k];
            return { url: url, headers: h };
        }
    };
}

function mkHls(url, name, ref) {
    if (!url) return null;
    var u = cleanUrl(url);
    var opts = { name: name || "HLS", url: u, duration: 0 };
    opts.requestModifier = liveRequestModifier(ref);
    try { return new HLSSource(opts); }
    catch (e) { addDebug("[live] no se pudo crear HLS: " + e); return null; }
}

function mkDash(url, name, ref) {
    if (!url || typeof DashSource === "undefined") return null;
    var u = cleanUrl(url);
    var opts = { name: name || "DASH", url: u, duration: 0 };
    opts.requestModifier = liveRequestModifier(ref);
    try { return new DashSource(opts); }
    catch (e) { addDebug("[live] no se pudo crear DASH: " + e); return null; }
}

function cleanUrl(url) {
    if (!url) return "";
    return String(url).replace(/\\u0026/g, "&").replace(/\\\//g, "/").trim();
}

function isM3u8Url(url) {
    return url && /\.m3u8(?:[?#]|$)/i.test(String(url));
}

// ========== AES-CBC EN JS PURO (128/192/256) ==========

var AESJS = (function () {
    var sbox = [], inv = [], rcon = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

    (function init() {
        function rotl(x, n) { return ((x << n) | (x >> (8 - n))) & 0xff; }
        var p = 1, q = 1;
        do {
            p = (p ^ (p << 1) ^ ((p & 0x80) ? 0x11b : 0)) & 0xff;
            q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
            if (q & 0x80) q ^= 0x09;
            sbox[p] = (q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63) & 0xff;
        } while (p !== 1);
        sbox[0] = 0x63;
        for (var i = 0; i < 256; i++) inv[sbox[i]] = i;
    })();

    function gmul(a, b) {
        var r = 0;
        while (b) {
            if (b & 1) r ^= a;
            a = ((a << 1) ^ ((a & 0x80) ? 0x11b : 0)) & 0xff;
            b >>= 1;
        }
        return r;
    }

    function expandKey(key) {
        var Nk = key.length / 4, Nr = Nk + 6, w = key.slice();
        for (var i = Nk; i < 4 * (Nr + 1); i++) {
            var t = [w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1]];
            if (i % Nk === 0) {
                t = [sbox[t[1]] ^ rcon[i / Nk - 1], sbox[t[2]], sbox[t[3]], sbox[t[0]]];
            } else if (Nk > 6 && i % Nk === 4) {
                t = [sbox[t[0]], sbox[t[1]], sbox[t[2]], sbox[t[3]]];
            }
            for (var j = 0; j < 4; j++) w[4 * i + j] = w[4 * (i - Nk) + j] ^ t[j];
        }
        return { w: w, Nr: Nr };
    }

    function decryptBlock(blk, ks) {
        var s = blk.slice(), Nr = ks.Nr, w = ks.w, r, c, i;
        function addKey(round) { for (var k = 0; k < 16; k++) s[k] ^= w[round * 16 + k]; }
        function invShiftSub() {
            var n = [];
            for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) n[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
            for (i = 0; i < 16; i++) s[i] = inv[n[i]];
        }
        function invMix() {
            for (c = 0; c < 4; c++) {
                var a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                s[4 * c]     = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
                s[4 * c + 1] = gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
                s[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11);
                s[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14);
            }
        }
        addKey(Nr);
        for (var round = Nr - 1; round >= 1; round--) { invShiftSub(); addKey(round); invMix(); }
        invShiftSub(); addKey(0);
        return s;
    }

    function cbcDecrypt(data, key, iv) {
        var ks = expandKey(key), out = [], prev = iv;
        for (var o = 0; o + 16 <= data.length; o += 16) {
            var blk = data.slice(o, o + 16), d = decryptBlock(blk, ks);
            for (var k = 0; k < 16; k++) out.push(d[k] ^ prev[k]);
            prev = blk;
        }
        var pad = out[out.length - 1];
        if (pad < 1 || pad > 16) return null; // padding inválido = clave/IV incorrectos
        return out.slice(0, out.length - pad);
    }

    return { cbcDecrypt: cbcDecrypt };
})();

function b64ToBytes(b64) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    b64 = String(b64).replace(/-/g, "+").replace(/_/g, "/").replace(/[^A-Za-z0-9+\/]/g, "");
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < b64.length; i++) {
        buf = (buf << 6) | chars.indexOf(b64.charAt(i));
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
    }
    return out;
}

function bytesToStr(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
}

function strToBytes(str) {
    var out = [];
    for (var i = 0; i < str.length; i++) out.push(str.charCodeAt(i) & 0xff);
    return out;
}

function utf8(bytes) {
    var s = bytesToStr(bytes);
    try { return decodeURIComponent(escape(s)); } catch (e) { return s; }
}

function decryptServidores(b64) {
    if (!b64 || typeof b64 !== "string") return [];
    try {
        // Doble base64: la primera capa da texto base64, la segunda el cifrado
        var inner = bytesToStr(b64ToBytes(b64));
        var cipher = b64ToBytes(inner);
        var key = strToBytes(AES_KEY);
        var iv = strToBytes(AES_IV);
        addDebug("[decrypt] cipher bytes=" + cipher.length + " key=" + key.length);

        // Intento 1: IV fijo
        var plain = cipher.length % 16 === 0 ? AESJS.cbcDecrypt(cipher, key, iv) : null;
        // Intento 2: IV en los primeros 16 bytes
        if (!plain && cipher.length > 16 && cipher.length % 16 === 0) {
            plain = AESJS.cbcDecrypt(cipher.slice(16), key, cipher.slice(0, 16));
        }
        if (!plain) { addDebug("[decrypt] fallo: clave/IV incorrectos o formato distinto"); return []; }

        var txt = utf8(plain);
        addDebug("[decrypt] OK: " + txt.substring(0, 80));
        var parsed = JSON.parse(txt);
        return Array.isArray(parsed) ? parsed : (parsed && parsed.url ? [parsed] : ((parsed && parsed.servidores) || []));
    } catch (e) {
        addDebug("[decrypt] error: " + e);
        return [];
    }
}

// La API puede devolver servidores como string cifrado, array de strings cifrados o array plano
function parseServidores(raw) {
    if (!raw) return [];
    if (typeof raw === "string") return decryptServidores(raw);
    if (Array.isArray(raw)) {
        if (!raw.length || typeof raw[0] !== "string") return raw;
        var all = [];
        for (var i = 0; i < raw.length; i++) {
            var part = decryptServidores(raw[i]);
            for (var j = 0; j < part.length; j++) all.push(part[j]);
        }
        return all;
    }
    return [];
}

// ========== EXTRACTORES ==========

function extractVideo(pageUrl) {
    if (!pageUrl) return null;
    pageUrl = cleanUrl(pageUrl);
    if (isM3u8Url(pageUrl)) return pageUrl;

    var host = "";
    try { host = pageUrl.match(/^https?:\/\/([^\/]+)/i)[1].toLowerCase(); } catch (e) {}


    if (isSeriesPlayerHost(host)) return seriesPlayerExtract(pageUrl);
    if (host.indexOf("ok.ru") !== -1 || host.indexOf("odnoklassniki") !== -1) {
        var ok = okExtract(pageUrl);
        if (ok) return ok;
        addDebug("[ok] extractor específico falló; probando genérico");
        return genericExtract(pageUrl);
    }
    if (host.indexOf("voe") !== -1) {
        var voe = voeExtract(pageUrl);
        if (voe) return voe;
        addDebug("[voe] extractor específico falló; probando genérico");
        return genericExtract(pageUrl);
    }
    if (host.indexOf("dood") !== -1 || host.indexOf("do7go") !== -1 || host.indexOf("ds2") !== -1) {
        var dood = doodExtract(pageUrl);
        if (dood) return dood;
        addDebug("[dood] extractor específico falló; probando genérico");
        return genericExtract(pageUrl);
    }
    // Los demás hosts (Filemoon, Mixdrop, Streamtape, Uqload, Vimeus,
    // Goodstream, Nuupload, etc.) pasan por el extractor genérico y sus fallbacks.
    return genericExtract(pageUrl);
}

function okExtract(pageUrl) {
    try {
        var html = httpGet(pageUrl, { "Referer": "https://ok.ru/" });
        if (!html) { addDebug("[ok] html vacío"); return null; }
        var m = html.match(/data-options="([^"]*)"/);
        if (!m) { addDebug("[ok] sin data-options. len=" + html.length + " html=" + html.substring(0, 150).replace(/\s+/g, " ")); return null; }
        var txt = m[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
        var o = JSON.parse(txt);
        var fv = o.flashvars || {};
        var meta = fv.metadata;
        if (typeof meta === "string") meta = JSON.parse(meta);
        meta = meta || {};
        var hls = meta.hlsManifestUrl || meta.ondemandHls || meta.hlsMasterPlaylistUrl || fv.hlsManifestUrl || fv.hlsMasterPlaylistUrl;
        if (hls) { if (hls.indexOf("//") === 0) hls = "https:" + hls; return cleanUrl(hls); }
        var order = ["ultra", "quad", "full", "hd", "sd", "low", "lowest", "mobile"], vids = meta.videos || [];
        for (var i = 0; i < order.length; i++) {
            for (var j = 0; j < vids.length; j++) {
                if (vids[j].name === order[i] && vids[j].url) return "mp4:" + cleanUrl(vids[j].url);
            }
        }
        addDebug("[ok] sin hls ni videos. meta=" + Object.keys(meta).join(","));
        return null;
    } catch (e) { addDebug("[ok] error: " + e); return null; }
}

function voeExtract(pageUrl) {
    try {
        var html = httpGet(pageUrl, { "Referer": pageUrl });
        if (!html) return null;
        var m = html.match(/hls\s*:\s*['"]([^'"]+\.m3u8[^'"]*)['"]/i);
        if (m && m[1]) return cleanUrl(m[1]);
        m = html.match(/file\s*:\s*['"]([^'"]+\.m3u8[^'"]*)['"]/i);
        if (m && m[1]) return cleanUrl(m[1]);
        return null;
    } catch (e) { return null; }
}

function doodPassMd5(pageUrl) {
    var html = httpGet(pageUrl, { "Referer": pageUrl });
    if (!html) return null;
    var finalUrl = _lastUrl || pageUrl;
    var origin = finalUrl.match(/^(https?:\/\/[^\/]+)/i)[1];
    var pm = html.match(/\/pass_md5\/[^'"\s]+/);
    if (!pm) { addDebug("[dood] sin pass_md5, len=" + html.length); return null; }
    var tk = pm[0].split("/").pop();
    var base = httpGet(origin + pm[0], { "Referer": finalUrl });
    if (!base || base.indexOf("http") !== 0) { addDebug("[dood] pass_md5 rara en " + origin + ": " + String(base).substring(0, 60).replace(/\s+/g, " ")); return null; }
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", rnd = "";
    for (var i = 0; i < 10; i++) rnd += chars.charAt(Math.floor(Math.random() * chars.length));
    return base + rnd + "?token=" + tk + "&expiry=" + Date.now();
}

function doodExtract(pageUrl) {
    try {
        var pm = doodPassMd5(pageUrl);
        if (pm) return pm;
        var html = httpGet(pageUrl, { "Referer": pageUrl });
        if (!html) return null;
        var m = html.match(/(?:file|link|source)\s*[:=]\s*['"]([^'"]+\.m3u8[^'"]*)['"]/i);
        if (m && m[1]) return cleanUrl(m[1]);
        m = html.match(/(?:file|link|source)\s*[:=]\s*['"]([^'"]+\.mp4[^'"]*)['"]/i);
        if (m && m[1]) return cleanUrl(m[1]);
        return null;
    } catch (e) { return null; }
}

// Desempaquetador del ofuscador clásico eval(function(p,a,c,k,e,d){...})
function unpackJs(src) {
    var m = src.match(/\}\('([\s\S]*)',\s*(\d+),\s*(\d+),\s*'([\s\S]*?)'\.split\('\|'\)/);
    if (!m) return null;
    var p = m[1].replace(/\\'/g, "'").replace(/\\\\/g, "\\");
    var a = parseInt(m[2], 10), c = parseInt(m[3], 10), k = m[4].split("|");
    function e(n) {
        return (n < a ? "" : e(parseInt(n / a, 10))) +
            ((n = n % a) > 35 ? String.fromCharCode(n + 29) : n.toString(36));
    }
    var d = {};
    while (c--) d[e(c)] = k[c] || e(c);
    return p.replace(/\b\w+\b/g, function (w) { return d[w] !== undefined ? d[w] : w; });
}

function findStreamIn(text, pageUrl) {
    var origin = "";
    try { origin = pageUrl.match(/^(https?:\/\/[^\/]+)/i)[1]; } catch (e) {}
    function abs(u) {
        u = cleanUrl(u);
        if (/^https?:\/\//i.test(u)) return u;
        if (u.indexOf("//") === 0) return "https:" + u;
        if (u.charAt(0) === "/") return origin + u;
        return u;
    }
    var m, re = /["']hls\d*["']\s*:\s*["']([^"']+)["']/gi, found = [];
    while ((m = re.exec(text)) !== null) found.push(abs(m[1]));
    if (found.length) return found[0];
    m = text.match(/file\s*:\s*["']([^"']+\.m3u8[^"']*)["']/i);
    if (m) return abs(m[1]);
    m = text.match(/https?:\/\/[^"'\s<>\\]+\.m3u8[^"'\s<>\\]*/i);
    if (m) return cleanUrl(m[0]);
    return null;
}

function genericExtract(pageUrl, depth) {
    try {
        var html = httpGet(pageUrl, { "Referer": pageUrl });
        if (!html) { addDebug("[generic] html vacío"); return null; }

        var hit = findStreamIn(html, pageUrl);
        if (hit) return hit;

        var idx = html.indexOf("eval(function(p,a,c,k,e,d)");
        if (idx !== -1) {
            var unpacked = unpackJs(html.substring(idx));
            if (unpacked) {
                hit = findStreamIn(unpacked, pageUrl);
                if (hit) return hit;
                addDebug("[generic] desempaquetado sin stream: " + unpacked.substring(0, 120).replace(/\s+/g, " "));
                return null;
            }
            addDebug("[generic] packed JS no se pudo desempaquetar");
            return null;
        }

        var rd = html.match(/(?:location(?:\.href)?\s*=|location\.replace\()\s*["']([^"']+)["']/i) ||
                 html.match(/http-equiv=["']refresh["'][^>]*url=([^"'>\s]+)/i) ||
                 html.match(/<iframe[^>]+src=["']([^"']+)["']/i);
        if (rd && (depth || 0) < 2) {
            var next = rd[1].replace(/&amp;/g, "&");
            if (next.indexOf("//") === 0) next = "https:" + next;
            else if (next.charAt(0) === "/") next = pageUrl.match(/^(https?:\/\/[^\/]+)/i)[1] + next;
            if (/^https?:\/\//i.test(next)) {
                addDebug("[generic] siguiendo redirect -> " + next);
                return genericExtract(next, (depth || 0) + 1);
            }
        }
        // Página-redirector (stub con main.js): probar los espejos con la misma ruta (/e/ID)
        if (!depth && html.length < 1200 && /\/main\.js/.test(html)) {
            var wp = pageUrl.match(/^https?:\/\/[^\/]+(\/.*)$/);
            if (wp) {
                for (var wi = 0; wi < WISH_MIRRORS.length; wi++) {
                    var cand = "https://" + WISH_MIRRORS[wi] + wp[1];
                    addDebug("[wish] probando espejo " + WISH_MIRRORS[wi]);
                    var got = genericExtract(cand, 5);
                    if (got) return got;
                }
            }
        }

        // Páginas tipo SPA ("Loading..."): mirar el JS principal para ver qué API usan
        var js = html.match(/<script[^>]+src=["'](\/[^"']+\.js[^"']*)["']/i);
        if (js && !_jsProbed) {
            _jsProbed = true;
            var jsUrl = pageUrl.match(/^(https?:\/\/[^\/]+)/i)[1] + js[1];
            var jsTxt = httpGet(jsUrl, { "Referer": pageUrl });
            var hits = [], fm, fre = /(?:fetch|axios\.get|axios\.post|\.open)\s*\(([^)]{0,90})/g;
            while ((fm = fre.exec(jsTxt)) !== null && hits.length < 5) hits.push(fm[1].replace(/\s+/g, " "));
            var urls = [], um, ure = /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}[^"'`\s\\)]{0,60}/gi;
            while ((um = ure.exec(jsTxt)) !== null && urls.length < 6) {
                if (!/cloudflare|w3\.org|reactjs|github/i.test(um[0]) && urls.indexOf(um[0]) === -1) urls.push(um[0]);
            }
            var ap = [], apm, apre = /["'`](\/api\/[^"'`\s]{1,60})["'`]/g;
            while ((apm = apre.exec(jsTxt)) !== null && ap.length < 8) if (ap.indexOf(apm[1]) === -1) ap.push(apm[1]);
            var vki = jsTxt.indexOf("view_key");
            addDebug("[generic] api=" + ap.join(" ; ") + " vk=" + (vki >= 0 ? jsTxt.substring(Math.max(0, vki - 60), vki + 90).replace(/\s+/g, " ") : "-"));
            addDebug("[generic] js=" + jsUrl + " len=" + jsTxt.length + " fetch=" + hits.join(" ; ") + " urls=" + urls.join(" ; "));
        }
        addDebug("[generic] sin m3u8 ni packed. len=" + html.length + " html=" +
            html.substring(0, 50).replace(/\s+/g, " "));
        return null;
    } catch (e) {
        addDebug("[generic] error: " + e);
        return null;
    }
}

// ========== SERIESPLAYER + WEB DE JUANITA (portado de PelisHub) ==========
// En series (ej. El Principe del rap de Bel-Air) los servidores son reproductores
// "seriesplayer.fortamomar.workers.dev/?id=..." que hay que pedir con el id re-codificado,
// Referer de pelisjuanita.com y buscar el .m3u8 dinamico dentro del HTML.

var JUANITA_WEB = "https://pelisjuanita.com";
var SP_HOSTS = /fortamomar|seriesplayer\.|onfilom\.com|playspelis\.com|321moviesfree\.com|flixlat\.com/i;
var SP_DEFAULT_REF = "https://seriesplayer.fortamomar.workers.dev/";
var _refOverride = "";
var _spCache = {};

// slug de la web que no coincide con el de la app
var JUANITA_ALIASES = {
    "the fresh prince of bel air": "el-principe-del-rap-en-bel-air",
    "el principe del rap de bel air": "el-principe-del-rap-en-bel-air",
    "el principe del rap en bel air": "el-principe-del-rap-en-bel-air"
};

function isSeriesPlayerHost(host) { return SP_HOSTS.test(host || ""); }

function normSlugWords(s) {
    return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").replace(/\s+\d{4}$/, "").trim();
}

function normalizeMediaText(t) {
    return String(t || "")
        .replace(/\\u0026/gi, "&").replace(/\\u002F/gi, "/")
        .replace(/\\u003A/gi, ":").replace(/\\u003F/gi, "?")
        .replace(/\\u003D/gi, "=").replace(/\\u0023/gi, "#")
        .replace(/\\\//g, "/").replace(/&amp;/gi, "&")
        .replace(/&quot;/gi, '"').replace(/&#39;/gi, "'");
}

// Re-codifica el parametro id (puede traer espacios, %2F, etc.) como lo hace PelisHub
function encodePlayerUrl(url) {
    url = String(url || "").replace(/&amp;/g, "&");
    var m = /^(https?:\/\/[^?]+\?id=)(.+)$/i.exec(url);
    if (!m) return url;
    try {
        var id = decodeURIComponent(m[2]);
        return m[1] + encodeURIComponent(id).replace(/%2F/gi, "/").replace(/%20/g, "+");
    } catch (e) {
        return m[1] + encodeURIComponent(m[2]).replace(/%2F/gi, "/");
    }
}

function findMediaUrls(text) {
    var out = [], t = normalizeMediaText(text), m, re, u;
    re = /https?:\/\/[^\s"'<>\\]+?\.m3u8(?:\?[^\s"'<>\\]*)?/gi;
    while ((m = re.exec(t)) !== null) { u = cleanUrl(m[0]); if (out.indexOf(u) < 0) out.push(u); }
    if (out.length) return out;
    re = /https?:\/\/[^\s"'<>\\]+?\.mp4(?:\?[^\s"'<>\\]*)?/gi;
    while ((m = re.exec(t)) !== null) { u = cleanUrl(m[0]); if (out.indexOf(u) < 0) out.push("mp4:" + u); }
    return out;
}

function seriesPlayerExtract(url) {
    var raw = cleanUrl(String(url || "").replace(/&amp;/g, "&"));
    if (!raw) return null;
    if (isM3u8Url(raw)) { _refOverride = SP_DEFAULT_REF; return raw; }
    if (/\.mp4(?:[?#]|$)/i.test(raw)) { _refOverride = SP_DEFAULT_REF; return "mp4:" + raw; }
    if (_spCache[raw]) { _refOverride = _spCache[raw].ref; return _spCache[raw].url; }

    var tries = [encodePlayerUrl(raw)], i, mfull;
    if (tries.indexOf(raw) < 0) tries.push(raw);
    mfull = /^(https?:\/\/[^?]+\?id=)(.+)$/i.exec(raw);
    if (mfull) {
        try { var full = mfull[1] + encodeURIComponent(decodeURIComponent(mfull[2])); if (tries.indexOf(full) < 0) tries.push(full); } catch (e) {}
    }
    for (i = 0; i < tries.length; i++) {
        var html = httpGet(tries[i], { "Referer": JUANITA_WEB + "/" });
        if (!html) { addDebug("[sp] intento " + (i + 1) + ": sin HTML"); continue; }
        if (/ID no v[áa]lido/i.test(html)) { addDebug("[sp] intento " + (i + 1) + ": ID no valido"); continue; }
        addDebug("[sp] intento " + (i + 1) + ": html=" + html.length + "b");
        var found = findMediaUrls(html);
        if (found.length) {
            _refOverride = tries[i];
            _spCache[raw] = { url: found[0], ref: tries[i] };
            addDebug("[sp] OK -> " + found[0].substring(0, 100));
            return found[0];
        }
        addDebug("[sp] sin media. html=" + html.substring(0, 100).replace(/\s+/g, " "));
    }
    return null;
}

// --- parseo de la pagina web serieInfo.php / movieInfo.php ---
function attrsOf(tag) {
    var out = {}, re = /([a-zA-Z0-9_:\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g, m;
    while ((m = re.exec(String(tag || ""))) !== null) out[m[1].toLowerCase()] = (m[2] != null ? m[2] : m[3]);
    return out;
}

function webB64(s) {
    try { return bytesToStr(b64ToBytes(s)); } catch (e) { return ""; }
}

function parseJuanitaWeb(html) {
    var out = [], seen = {}, m, re, tags, i;
    if (!html) return out;
    function add(u, lang, name) {
        u = cleanUrl(String(u || "").replace(/&amp;/g, "&"));
        if (u.indexOf("//") === 0) u = "https:" + u;
        if (!/^https?:\/\//i.test(u) || seen[u]) return;
        seen[u] = 1;
        out.push({ url: u, audio: lang || "", server_name: name || "Web" });
    }
    tags = html.match(/<[a-zA-Z][^>]*row-download[^>]*>/gi) || [];
    for (i = 0; i < tags.length; i++) {
        var a = attrsOf(tags[i]), tipo = (a["data-tipo"] || "").toLowerCase();
        if (tipo === "torrent" || tipo === "magnet") continue;
        var u = a["data-url"];
        if (!u) continue;
        if (!/^https?:|^\/\//i.test(u)) { var d = webB64(u); if (/^https?:\/\//i.test(d)) u = d; }
        add(u, a["data-idioma"] || "", "Web");
    }
    re = /https?:\/\/(?:seriesplayer\.)?fortamomar\.workers\.dev\/\?id=[^\s"'<>]*/gi;
    while ((m = re.exec(html)) !== null) add(m[0], "Latino", "SeriesPlayer");
    re = /https?:\/\/seriesplayer\.[a-z0-9._-]+\/\?id=[^\s"'<>]*/gi;
    while ((m = re.exec(html)) !== null) add(m[0], "Latino", "SeriesPlayer");
    re = /(?:data-url|href|src)=["']([^"']*fortamomar[^"']*|[^"']*seriesplayer[^"']*)["']/gi;
    while ((m = re.exec(html)) !== null) add(m[1], "Latino", "SeriesPlayer");
    tags = html.match(/<iframe\b[^>]*>/gi) || [];
    for (i = 0; i < tags.length; i++) {
        var a2 = attrsOf(tags[i]), src = a2["src"] || a2["data-src"] || "";
        if (/fortamomar|seriesplayer|onfilom|playspelis|flixlat/i.test(src)) add(src, "Latino", "SeriesPlayer");
    }
    return out;
}

function webPageUrl(isTv, slug, t, e) {
    return isTv
        ? JUANITA_WEB + "/series/serieInfo.php?nombreSerie=" + slug + "&nroTemporada=" + t + "&nroEpisodio=" + e
        : JUANITA_WEB + "/movies/movieInfo.php?title=" + slug;
}

// Servidores desde la web de Pelisjuanita (misma ruta que usa PelisHub)
function juanitaWebServers(isTv, slug, t, e) {
    var slugs = [], tried = {}, i, list, alias = JUANITA_ALIASES[normSlugWords(slug)];
    if (alias) slugs.push(alias);
    slugs.push(slug);
    for (i = 0; i < slugs.length; i++) {
        if (!slugs[i] || tried[slugs[i]]) continue;
        tried[slugs[i]] = 1;
        list = parseJuanitaWeb(httpGet(webPageUrl(isTv, slugs[i], t, e), { "Referer": JUANITA_WEB + "/" }));
        addDebug("[web] " + slugs[i] + " -> " + list.length + " servidor(es)");
        if (list.length) return list;
    }
    // Buscador de la web: solo se acepta un slug que comparta palabras con el pedido
    var words = normSlugWords(slug).split(" "), body = httpGet(
        JUANITA_WEB + (isTv ? "/series/search?s=" : "/movies/search?s=") + encodeURIComponent(words.join(" ")),
        { "Referer": JUANITA_WEB + "/" });
    if (body) {
        var re = isTv ? /\/series\/ver-serie\/([a-z0-9\-]+)/gi : /(?:\/movies\/(?:pelicula|movie)\/|movieInfo\.php\?title=)([a-z0-9\-]+)/gi, m, n = 0;
        while ((m = re.exec(body)) !== null && n < 2) {
            var cand = m[1];
            if (tried[cand]) continue;
            var cw = normSlugWords(cand).split(" "), hit = 0, k;
            for (k = 0; k < words.length; k++) if (cw.indexOf(words[k]) >= 0) hit++;
            if (words.length && hit / words.length < 0.6) continue;
            tried[cand] = 1; n++;
            list = parseJuanitaWeb(httpGet(webPageUrl(isTv, cand, t, e), { "Referer": JUANITA_WEB + "/" }));
            addDebug("[web] buscador " + cand + " -> " + list.length);
            if (list.length) return list;
        }
    }
    return [];
}

function mergeServers(a, b) {
    var out = [], seen = {}, i, all = (a || []).concat(b || []);
    for (i = 0; i < all.length; i++) {
        var u = cleanUrl((all[i] && (all[i].url || all[i].link)) || "");
        if (!u || seen[u]) continue;
        seen[u] = 1;
        out.push(all[i]);
    }
    return out;
}

// ========== API ==========

function apiGet(path) {
    var body = httpGet(BASE + path, { "Accept": "application/json", "Referer": "https://pelisjuanita.com/" });
    if (!body) return null;
    try { return JSON.parse(body); } catch (e) { return null; }
}

function doHome() {
    var videos = [];
    var data = apiGet("/home.php");
    if (!data || !data.sections) return videos;

    for (var s = 0; s < data.sections.length; s++) {
        var items = data.sections[s].data || [];
        for (var i = 0; i < items.length && videos.length < 60; i++) {
            var it = items[i];
            if (it.tipo === "TV" || it.m3u8 || it.dash) {
                var ckey = String(it.slug || it.nombre);
                _channels[ckey] = it;
                videos.push(mkVideo("ch_" + ckey, "[TV] " + (it.nombre || "Canal"), it.logo || "", "pj://channel/" + ckey, "TV en Vivo", true));
            } else if (it.slug) {
                var type = (it.tipo === "serie") ? "serie" : "movie";
                videos.push(mkItem(type, it.slug, (it.titulo || it.nombre || ""), fixImg(it.img_frente || it.poster)));
            }
        }
    }
    return videos;
}

function doSearch(query) {
    var videos = [];
    if (!query) return videos;
    var data = apiGet("/buscar.php?q=" + encodeURIComponent(query));
    if (!data || !data.datos) return videos;
    var list = data.datos;
    for (var i = 0; i < list.length && videos.length < 40; i++) {
        var it = list[i];
        var tipo = (it.tipo === "serie") ? "serie" : "movie";
        videos.push(mkItem(tipo, (it.slug || it.id), (it.titulo_principal || it.titulo || it.nombre || ""), fixImg(it.img_frente)));
    }
    return videos;
}

// Servidores adicionales: ya no se descartan dominios completos antes de intentar
// el extractor genérico. Si un servidor falla, resolveSources continúa con el siguiente.
// Se mantiene un límite moderado para no demorar excesivamente cada película.
var SKIP_HOSTS = [];
var MAX_SOURCES = 5;

// Familias conocidas del segundo JS. No se hace scraping de catálogo adicional:
// solo se priorizan/interpretan enlaces de servidores que ya entrega la ficha.
var EXTRA_HOST_FAMILIES = /streamwish|hlswish|wishembed|awish|vidhide|filemoon|filelions|mixdrop|mxdrop|supervideo|voe|uqload|streamtape|dood|do7go|ok\.ru|odnoklassniki|vimeus|goodstream|nupload|nuuuppp|dailymotion|odysee|archive\.org|vkvideo|vk\.com|vidmoly|vidguard|vidsrc|vidplay|vidlink|vidnest|vidrock|vidsonic|vixsrc|vixcloud|lulustream|luluvdo|plusvip|fastream|esplay/i;

function hostOf(url) {
    try { return url.match(/^https?:\/\/([^\/]+)/i)[1].toLowerCase(); } catch (e) { return ""; }
}

// Menor número = se prueba primero
function hostPriority(host) {
    if (isSeriesPlayerHost(host)) return -1;
    if (host.indexOf("ok.ru") !== -1) return 0;
    if (/wish|vidhide|callistanise|vibuxer|morencius|lulustream|filemoon|filelions|mixdrop|supervideo/.test(host)) return 1;
    if (host.indexOf("ok.ru") !== -1 || /odnoklassniki/.test(host)) return 1;
    if (/dood|do7go|ds2|voe|uqload|streamtape|vidmoly|vidguard|vidplay|vidlink/.test(host)) return 2;
    if (EXTRA_HOST_FAMILIES.test(host)) return 2;
    return 3;
}

function hostOrigin(url) {
    try { return url.match(/^(https?:\/\/[^\/]+)/i)[1] + "/"; } catch (e) { return ""; }
}

// Crea la fuente con el Referer del reproductor embebido (muchos CDN lo exigen: Dood, StreamWish)
function buildSource(url, name, ref, isMp4) {
    var rm = null;
    if (ref) {
        rm = {
            allowByteSkip: true,
            headers: (function () {
                var hh = { "Referer": ref, "User-Agent": UA }, om = String(ref).match(/^(https?:\/\/[^\/?#]+)/i);
                if (om) hh["Origin"] = om[1];
                return hh;
            })(),
            modifyRequest: function (u, headers) {
                var h = headers || {};
                h["Referer"] = ref;
                var om2 = String(ref).match(/^(https?:\/\/[^\/?#]+)/i);
                if (om2) h["Origin"] = om2[1];
                if (!h["User-Agent"]) h["User-Agent"] = UA;
                return { url: u, headers: h };
            }
        };
    }
    var o;
    if (isMp4) {
        o = { name: name, url: url, container: "video/mp4", width: 0, height: 0, duration: 0, codec: "" };
        if (rm) o.requestModifier = rm;
        return new VideoUrlSource(o);
    }
    o = { name: name, url: url, duration: 0 };
    if (rm) o.requestModifier = rm;
    return new HLSSource(o);
}

// Confirma que la URL devuelve realmente una playlist HLS (evita fuentes muertas que dejan el reproductor cargando)
function isLiveHls(url, ref) {
    var body = httpGet(url, ref ? { "Referer": ref } : {});
    if (!body) return true; // sin respuesta (p. ej. dominio no permitido): no se descarta
    var ok = body.indexOf("#EXTM3U") !== -1;
    if (!ok) addDebug("[hls] respuesta: " + body.substring(0, 80).replace(/\s+/g, " "));
    return ok;
}

function resolveSources(servidores) {
    var sources = [];
    if (!servidores || !servidores.length) return sources;

    var list = [], skipped = [], skippedHosts = {}, unverified = [];
    for (var i = 0; i < servidores.length; i++) {
        var srv = servidores[i];
        var url = cleanUrl(srv.url || srv.link || "");
        if (!url) continue;
        var host = hostOf(url), skip = false;
        for (var k = 0; k < SKIP_HOSTS.length; k++) if (host.indexOf(SKIP_HOSTS[k]) !== -1) skip = true;
        if (skip) {
            addDebug("[resolve] salteado (sin extractor): " + host);
            if (!skippedHosts[host]) { skippedHosts[host] = true; skipped.push(url); }
            continue;
        }
        list.push({ srv: srv, url: url, pr: hostPriority(host), idx: i });
    }
    list.sort(function (a, b) { return (a.pr - b.pr) || (a.idx - b.idx); });

    for (var j = 0; j < list.length && sources.length < MAX_SOURCES; j++) {
        var it = list[j], sv = it.srv;
        var name = (sv.server_name || sv["server-name"] || sv.ServerName || sv.nombre || "Servidor") + " [" + (sv.audio || sv.idioma || "") + "]";
        var h = hostOf(it.url);
        if (_hostFail[h]) { addDebug("[resolve] salteado (ya falló): " + h); continue; }
        addDebug("[resolve] probando " + name + " host=" + h);
        if (EXTRA_HOST_FAMILIES.test(h)) addDebug("[resolve] familia extra detectada: " + h);
        _refOverride = "";
        var hls = extractVideo(it.url);
        if (!hls) {
            for (var f = 0; f < FAIL_ONCE_HOSTS.length; f++) if (h.indexOf(FAIL_ONCE_HOSTS[f]) !== -1) _hostFail[h] = true;
            continue;
        }

        var refOrigin = _refOverride || hostOrigin(_lastUrl || it.url);
        var forceMp4 = hls.indexOf("mp4:") === 0;
        if (forceMp4) hls = hls.substring(4);
        var isMp4 = forceMp4 || (!isM3u8Url(hls) && (hls.indexOf(".mp4") !== -1 || hls.indexOf("token=") !== -1));
        var verified = isMp4 || isLiveHls(hls, refOrigin);

        addDebug("[resolve] url=" + hls.substring(0, 90) + " ref=" + refOrigin + (verified ? "" : " (sin verificar)"));
        var src = buildSource(hls, name, refOrigin, isMp4);
        if (!src) continue;
        if (verified) { sources.push(src); addDebug("[resolve] OK: " + name); }
        else unverified.push(src);
    }

    // Las no verificadas se ofrecen igual, al final, por si la validación fue un falso negativo
    for (var u = 0; u < unverified.length && sources.length < MAX_SOURCES; u++) sources.push(unverified[u]);

    // Diagnóstico: si no hubo ninguna fuente, inspeccionar los hosts salteados para ver cómo cargan
    if (sources.length === 0) {
        for (var d = 0; d < skipped.length && d < 2; d++) {
            _jsProbed = false;
            addDebug("[diag] " + skipped[d].substring(0, 90));
            extractVideo(skipped[d]);
        }
    }
    return sources;
}

function getEpisodes(slug) {
    var sdata = apiGet("/series.php?slug=" + encodeURIComponent(slug));
    var info = sdata ? (sdata.episodio || sdata.datos || sdata.serie || null) : null;
    if (!info) return { info: null, videos: [] };
    var total = parseInt(info.temporadas, 10) || 1;
    var vids = [], name = info.nombre || slug, thumb = fixImg(info.img_frente);
    for (var t = 1; t <= total && t <= 30; t++) {
        var f = apiGet("/series.php?slug=" + encodeURIComponent(slug) + "&t=" + t);
        if (!f) continue;
        var eps = Array.isArray(f.episodios) ? f.episodios : (Array.isArray(f.datos) ? f.datos : []);
        for (var i = 0; i < eps.length; i++) {
            var y = eps[i];
            var n = (y.enum !== undefined && y.enum !== null) ? y.enum : ((y.e !== undefined && y.e !== null) ? y.e : i + 1);
            var title = "T" + t + "E" + n + " · " + (y.titulo || y.title || ("Capítulo " + n));
            vids.push(mkVideo("e_" + slug + "_" + t + "_" + n, title, thumb, "pj://ep/" + slug + "/" + t + "/" + n, name));
        }
    }
    return { info: info, videos: vids };
}

function doDetails(url) {
    _debugLog = "";
    _jsProbed = false;
    _hostFail = {};
    _refOverride = "";
    if (!url) return mkDetail("", "Sin URL", "", "", [], "");

    var m = url.match(/pj:\/\/movie\/([^\/]+)/);
    if (m) {
        var slug = m[1];
        var data = apiGet("/movies.php?slug=" + encodeURIComponent(slug));
        if (!data || !data.datos) return mkDetail("m_" + slug, "No encontrado", "", url, [], "");
        var d = data.datos;
        var servidores = mergeServers(parseServidores(d.servidores), juanitaWebServers(false, slug, 1, 1));
        var sources = resolveSources(servidores);
        var desc = (d.sinopsis || "") + "\n\nAño: " + (d.año || "") + "\nGénero: " + (d.genero || "");
        if (sources.length === 0) {
            // Sin fuentes GrayJay muestra "video no disponible" y oculta la descripción,
            // así que el DEBUG se muestra como mensaje de error.
            throw new ScriptException("SIN FUENTES\n" + _debugLog);
        }
        return mkDetail("m_" + slug, d.titulo || slug, fixImg(d.img_frente), url, sources, desc);
    }

    var c = url.match(/pj:\/\/channel\/([^\/]+)/);
    if (c) {
        var ckey = c[1];
        var ch = _channels[ckey];
        if (!ch) { doHome(); ch = _channels[ckey]; } // si se abrió sin pasar por el home
        if (!ch) throw new ScriptException("Canal no encontrado: " + ckey + "\n" + _debugLog);
        var csrc = [];
        var liveRef = "https://pelisjuanita.com/";
        var hlsUrl = cleanUrl(ch.m3u8 || "");
        var dashUrl = cleanUrl(ch.dash || "");
        if (hlsUrl) {
            var hs = mkHls(hlsUrl, "Directo · HLS", liveRef);
            if (hs) csrc.push(hs);
        }
        if (dashUrl) {
            var ds = mkDash(dashUrl, "Directo · DASH", liveRef);
            if (ds) csrc.push(ds);
        }
        addDebug("[canal] campos=" + Object.keys(ch).join(","));
        addDebug("[canal] m3u8=" + (hlsUrl || "-"));
        addDebug("[canal] dash=" + (dashUrl || "-"));
        addDebug("[canal] fuentes_creadas=" + csrc.length);
        addDebug("[canal] referer=" + liveRef + " (User-Agent/Origin configurados)");
        if (!csrc.length) throw new ScriptException("Canal sin fuente reproducible en GrayJay (HLS/DASH). Datos: " + JSON.stringify(ch).substring(0, 400) + "\n" + _debugLog);
        return mkDetail("ch_" + ckey, ch.nombre || ckey, ch.logo || "", url, csrc, "TV en vivo", true);
    }

    var ep = url.match(/pj:\/\/ep\/([^\/]+)\/(\d+)\/(\d+)/);
    if (ep) {
        var eslug = ep[1], et = ep[2], en = ep[3];
        var edata = apiGet("/series.php?slug=" + encodeURIComponent(eslug) + "&t=" + et + "&e=" + en);
        var apiSrv = edata ? parseServidores(edata.servidores) : [];
        addDebug("[api] T" + et + "E" + en + " -> " + apiSrv.length + " servidor(es)");
        // Igual que PelisHub: se suman los servidores de la web (seriesplayer) a los de la API
        var webSrv = juanitaWebServers(true, eslug, et, en);
        var esources = resolveSources(mergeServers(apiSrv, webSrv));
        if (esources.length === 0) throw new ScriptException("SIN FUENTES\n" + _debugLog);
        return mkDetail("e_" + eslug + "_" + et + "_" + en, eslug + " T" + et + "E" + en, "", url, esources, "", false);
    }

    var s = url.match(/pj:\/\/serie\/([^\/]+)/);
    if (s) {
        var sslug = s[1];
        var sdata = apiGet("/series.php?slug=" + encodeURIComponent(sslug));
        if (!sdata || !sdata.datos) return mkDetail("s_" + sslug, "No encontrado", "", url, [], "");
        var sd = sdata.datos;
        throw new ScriptException("Las series se abren como lista de reproducción (episodios).");
    }

    return mkDetail("", "No soportado", "", url, [], "");
}

function mkDetail(id, name, thumb, url, sources, description, isLive) {
    var valid = [];
    for (var i = 0; i < (sources || []).length; i++) if (sources[i]) valid.push(sources[i]);
    var desc = description || "";
    if (_debugLog) desc += "\n\n=== DEBUG ===\n" + _debugLog;
    return new PlatformVideoDetails({
        id: new PlatformID("Pelisjuanita", String(id), PID),
        name: name || "Sin título",
        thumbnails: mkThumb(thumb),
        author: new PlatformAuthorLink(PPID, "Pelisjuanita", "https://pelisjuanita.com", "", 0),
        uploadDate: 0, url: url, duration: 0, viewCount: 0, isLive: !!isLive,
        video: new VideoSourceDescriptor(valid),
        description: desc
    });
}

// ========== BINDINGS ==========

if (typeof source !== "undefined") {
    source.enable = function(c, s) {};
    source.setSettings = function(s) {};
    source.getSearchCapabilities = function() { return { types: [2], sorts: [], filters: [] }; };

    source.search = function(query) {
        try { return new VideoPager(doSearch(query || ""), false, null); }
        catch (e) { return new VideoPager([], false, null); }
    };

    source.getHome = function() {
        try { return new VideoPager(doHome(), false, null); }
        catch (e) { return new VideoPager([], false, null); }
    };

    source.isContentDetailsUrl = function(url) { return !!url && url.indexOf("pj://") === 0 && url.indexOf("pj://serie/") !== 0; };
    source.isPlaylistUrl = function(url) { return !!url && url.indexOf("pj://serie/") === 0; };
    source.getPlaylist = function(url) {
        var slug = url.match(/pj:\/\/serie\/([^\/]+)/)[1];
        var r = getEpisodes(slug);
        if (!r.info) throw new ScriptException("Serie no encontrada: " + slug);
        return new PlatformPlaylistDetails({
            id: new PlatformID("Pelisjuanita", "s_" + slug, PID),
            name: r.info.nombre || slug,
            thumbnail: fixImg(r.info.img_frente),
            author: new PlatformAuthorLink(PPID, "Pelisjuanita", "https://pelisjuanita.com", "", 0),
            datetime: 0, url: url, videoCount: r.videos.length,
            contents: new VideoPager(r.videos, false, null)
        });
    };
    source.isVideoDetailsUrl = function(url) { return source.isContentDetailsUrl(url); };

    source.getContentDetails = function(url) {
        try { return doDetails(url); }
        catch (e) { throw new ScriptException(String(e && e.message ? e.message : e)); }
    };

    source.getVideoDetails = function(url) { return source.getContentDetails(url); };
    source.getContentRecommendations = function(url) { return new VideoPager([], false, null); };
    source.searchSuggestions = function(q) { return []; };
    source.isChannelUrl = function(url) {
        return !!url && /^https?:\/\/(www\.)?pelisjuanita\.com\/?$/i.test(url);
    };
    source.getChannel = function(url) {
        return new PlatformChannel({
            id: PPID, name: "Pelisjuanita", thumbnail: "", banner: "", subscribers: 0,
            description: "Pelisjuanita", url: "https://pelisjuanita.com", links: {}
        });
    };
    source.getChannelContents = function(url) {
        try { return new VideoPager(doHome(), false, null); }
        catch (e) { return new VideoPager([], false, null); }
    };
}
