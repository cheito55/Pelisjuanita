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

function addDebug(msg) { _debugLog += String(msg) + "\n"; }

function httpGet(url, headers) {
    try {
        var h = headers || {};
        if (!h["User-Agent"]) h["User-Agent"] = UA;
        var r = http.GET(url, h);
        return (r && r.body) ? r.body : "";
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

function mkHls(url, name) {
    if (!url) return null;
    return new HLSSource({ name: name || "HLS", url: url, duration: 0 });
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

    addDebug("[extract] host=" + host);

    if (host.indexOf("voe") !== -1) return voeExtract(pageUrl);
    if (host.indexOf("dood") !== -1 || host.indexOf("do7go") !== -1) return doodExtract(pageUrl);
    return genericExtract(pageUrl);
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
    var origin = pageUrl.match(/^(https?:\/\/[^\/]+)/i)[1];
    var html = httpGet(pageUrl, { "Referer": pageUrl });
    if (!html) return null;
    var pm = html.match(/\/pass_md5\/[^'"\s]+/);
    if (!pm) { addDebug("[dood] sin pass_md5, len=" + html.length); return null; }
    var tk = pm[0].split("/").pop();
    var base = httpGet(origin + pm[0], { "Referer": pageUrl });
    if (!base || base.indexOf("http") !== 0) { addDebug("[dood] respuesta pass_md5 rara"); return null; }
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
        // Páginas tipo SPA ("Loading..."): mirar el JS principal para ver qué API usan
        var js = html.match(/<script[^>]+src=["'](\/[^"']+\.js[^"']*)["']/i);
        if (js) {
            var jsUrl = pageUrl.match(/^(https?:\/\/[^\/]+)/i)[1] + js[1];
            var jsTxt = httpGet(jsUrl, { "Referer": pageUrl });
            var apis = [], am, are = /["'`](\/(?:api|ajax|get|embed|source|player|stream)[^"'`\s]{0,80})["'`]/gi;
            while ((am = are.exec(jsTxt)) !== null && apis.length < 8) apis.push(am[1]);
            addDebug("[generic] js=" + jsUrl + " len=" + jsTxt.length + " rutas=" + apis.join(" | "));
        }
        addDebug("[generic] sin m3u8 ni packed. len=" + html.length + " html=" +
            html.substring(0, html.length < 1200 ? 700 : 100).replace(/\s+/g, " "));
        return null;
    } catch (e) {
        addDebug("[generic] error: " + e);
        return null;
    }
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

function resolveSources(servidores) {
    var sources = [];
    if (!servidores || !servidores.length) return sources;
    var max = Math.min(servidores.length, 6);
    for (var i = 0; i < max; i++) {
        var srv = servidores[i];
        var url = srv.url || "";
        if (!url) continue;
        var name = (srv["server-name"] || srv.ServerName || "Servidor") + " [" + (srv.idioma || "") + "]";
        addDebug("[resolve] probando " + name);
        var hls = extractVideo(url);
        if (hls) {
            var isMp4 = !isM3u8Url(hls) && (hls.indexOf(".mp4") !== -1 || hls.indexOf("token=") !== -1);
            var src = isMp4
                ? new VideoUrlSource({ name: name, url: hls, container: "video/mp4", width: 0, height: 0, duration: 0, codec: "" })
                : mkHls(hls, name);
            if (src) sources.push(src);
            addDebug("[resolve] OK: " + name);
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
    if (!url) return mkDetail("", "Sin URL", "", "", [], "");

    var m = url.match(/pj:\/\/movie\/([^\/]+)/);
    if (m) {
        var slug = m[1];
        var data = apiGet("/movies.php?slug=" + encodeURIComponent(slug));
        if (!data || !data.datos) return mkDetail("m_" + slug, "No encontrado", "", url, [], "");
        var d = data.datos;
        var servidores = parseServidores(d.servidores);
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
        if (ch.m3u8) csrc.push(mkHls(cleanUrl(ch.m3u8), "Directo"));
        if (ch.dash && typeof DashSource !== "undefined") {
            csrc.push(new DashSource({ name: "DASH", url: cleanUrl(ch.dash), duration: 0 }));
        }
        if (!csrc.length) throw new ScriptException("Canal sin m3u8/dash. Datos: " + JSON.stringify(ch).substring(0, 400));
        addDebug("[canal] campos=" + Object.keys(ch).join(","));
        addDebug("[canal] m3u8=" + (ch.m3u8 || "-"));
        addDebug("[canal] dash=" + (ch.dash || "-"));
        return mkDetail("ch_" + ckey, ch.nombre || ckey, ch.logo || "", url, csrc, "TV en vivo", true);
    }

    var ep = url.match(/pj:\/\/ep\/([^\/]+)\/(\d+)\/(\d+)/);
    if (ep) {
        var eslug = ep[1], et = ep[2], en = ep[3];
        var edata = apiGet("/series.php?slug=" + encodeURIComponent(eslug) + "&t=" + et + "&e=" + en);
        if (!edata) throw new ScriptException("Sin respuesta del episodio T" + et + "E" + en);
        var esources = resolveSources(parseServidores(edata.servidores));
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
