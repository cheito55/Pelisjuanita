// Pelisjuanita GrayJay Source - con extractores completos
// Incluye: StreamWish, Nuupload, Vidhide, VOE, Dood, Uqload, Streamtape, Mixdrop, OK.ru, Generic + unpacker

var PID = "c7e1a9f2-4b8d-4e3a-9c1f-6d5a2b8e7f41";
var UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
var BASE = "https://pelisjuanita.com/tv/app";
var TMDB_IMG = "https://image.tmdb.org/t/p/w500";
var JUANITA_WEB = "https://pelisjuanita.com";

var AES_KEY = "TuClaveSecretaSuperSeguraParaServidores2026!#".substring(0, 32);
var AES_IV  = "1234567890123456";

var PPID = new PlatformID("Pelisjuanita", "Pelisjuanita", PID);
var _debugLog = "";
var _channels = {};
var _lastUrl = "";
var _refOverride = "";
var MAX_SOURCES = 8;
var SKIP_HOSTS = [];

function addDebug(msg) { _debugLog += String(msg) + "\n"; }
function log(s) { addDebug(s); }

function httpGet(url, headers) {
    try {
        var h = headers || {};
        if (!h["User-Agent"]) h["User-Agent"] = UA;
        var r = http.GET(url, h);
        _lastUrl = (r && r.url) ? r.url : url;
        if (!r || !r.body) return "";
        return r.body;
    } catch (e) {
        addDebug("HTTP error: " + e);
        return "";
    }
}

function clean(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&").replace(/"/g, '"').replace(/&#39;/g, "'")
        .replace(/\\u0026/g, "&").replace(/\\\//g, "/").replace(/\s+/g, " ").trim();
}

function cleanUrl(u) {
    return clean(String(u == null ? "" : u)).replace(/^[\s"']+/, "").replace(/[\s"'),;\\]+$/g, "");
}

function hostOf(url) {
    var m = String(url || "").match(/^https?:\/\/([^\/?#]+)/i);
    return m ? m[1].toLowerCase() : "";
}

function originOf(url) {
    var m = String(url || "").match(/^(https?:\/\/[^\/?#]+)/i);
    return m ? m[1] : "";
}

function isM3u8Url(url) {
    return url && /\.m3u8(?:[?#]|$)/i.test(String(url));
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

function mkHls(url, name, ref) {
    if (!url) return null;
    var o = { name: name || "HLS", url: url, duration: 0 };
    if (ref) {
        o.requestModifier = {
            headers: { "Referer": ref, "User-Agent": UA },
            modifyRequest: function (u, headers) {
                var h = headers || {};
                h["Referer"] = ref;
                if (!h["User-Agent"]) h["User-Agent"] = UA;
                return { url: u, headers: h };
            }
        };
    }
    return new HLSSource(o);
}

function mkMp4(url, name, ref) {
    if (!url) return null;
    var o = { name: name || "MP4", url: url, container: "video/mp4", width: 0, height: 0, duration: 0, codec: "" };
    if (ref) {
        o.requestModifier = {
            headers: { "Referer": ref, "User-Agent": UA },
            modifyRequest: function (u, headers) {
                var h = headers || {};
                h["Referer"] = ref;
                if (!h["User-Agent"]) h["User-Agent"] = UA;
                return { url: u, headers: h };
            }
        };
    }
    return new VideoUrlSource(o);
}

// ========== AES-CBC puro ==========
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
    function gmul(a, b) { var r = 0; while (b) { if (b & 1) r ^= a; a = ((a << 1) ^ ((a & 0x80) ? 0x11b : 0)) & 0xff; b >>= 1; } return r; }
    function expandKey(key) {
        var Nk = key.length / 4, Nr = Nk + 6, w = key.slice();
        for (var i = Nk; i < 4 * (Nr + 1); i++) {
            var t = [w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1]];
            if (i % Nk === 0) t = [sbox[t[1]] ^ rcon[i / Nk - 1], sbox[t[2]], sbox[t[3]], sbox[t[0]]];
            else if (Nk > 6 && i % Nk === 4) t = [sbox[t[0]], sbox[t[1]], sbox[t[2]], sbox[t[3]]];
            for (var j = 0; j < 4; j++) w[4 * i + j] = w[4 * (i - Nk) + j] ^ t[j];
        }
        return { w: w, Nr: Nr };
    }
    function decryptBlock(blk, ks) {
        var s = blk.slice(), Nr = ks.Nr, w = ks.w;
        function addKey(round) { for (var k = 0; k < 16; k++) s[k] ^= w[round * 16 + k]; }
        function invShiftSub() {
            var n = [];
            for (var r = 0; r < 4; r++) for (var c = 0; c < 4; c++) n[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
            for (var i = 0; i < 16; i++) s[i] = inv[n[i]];
        }
        function invMix() {
            for (var c = 0; c < 4; c++) {
                var a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                s[4 * c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
                s[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
                s[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
                s[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
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
        if (pad < 1 || pad > 16) return null;
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
function bytesToStr(bytes) { var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return s; }
function strToBytes(str) { var out = []; for (var i = 0; i < str.length; i++) out.push(str.charCodeAt(i) & 0xff); return out; }
function utf8(bytes) { var s = bytesToStr(bytes); try { return decodeURIComponent(escape(s)); } catch (e) { return s; } }

function decryptServidores(b64) {
    if (!b64 || typeof b64 !== "string") return [];
    try {
        var inner = bytesToStr(b64ToBytes(b64));
        var cipher = b64ToBytes(inner);
        var key = strToBytes(AES_KEY);
        var iv = strToBytes(AES_IV);
        var plain = cipher.length % 16 === 0 ? AESJS.cbcDecrypt(cipher, key, iv) : null;
        if (!plain && cipher.length > 16) plain = AESJS.cbcDecrypt(cipher.slice(16), key, cipher.slice(0, 16));
        if (!plain) return [];
        var parsed = JSON.parse(utf8(plain));
        return Array.isArray(parsed) ? parsed : [];
    } catch (e) { return []; }
}

function parseServidores(raw) {
    if (!raw) return [];
    if (typeof raw === "string") return decryptServidores(raw);
    if (Array.isArray(raw)) return raw;
    return [];
}

// ========== UNPACKER + SCAN ==========
function unpackOne(p, a, c, k) {
    function e(n) { return (n < a ? "" : e(parseInt(n / a, 10))) + ((n = n % a) > 35 ? String.fromCharCode(n + 29) : n.toString(36)); }
    var d = {}, i;
    for (i = 0; i < c; i++) d[e(i)] = (k[i] && k[i].length) ? k[i] : e(i);
    var keys = Object.keys(d).sort(function (x, y) { return y.length - x.length; });
    for (i = 0; i < keys.length; i++) {
        if (!keys[i]) continue;
        p = p.replace(new RegExp("\\b" + keys[i].replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "g"), d[keys[i]]);
    }
    return p;
}

function unpackAll(text) {
    var out = [], re = /eval\(function\(p,a,c,k,e,(?:d|r)\)[\s\S]*?\}\('([\s\S]*?)',\s*(\d+)\s*,\s*(\d+)\s*,\s*'([\s\S]*?)'\.split\('\|'\)/g, m;
    while ((m = re.exec(String(text || ""))) != null) {
        try { out.push(unpackOne(m[1], parseInt(m[2], 10), parseInt(m[3], 10), m[4].split("|"))); } catch (e) {}
        if (out.length >= 4) break;
    }
    return out;
}

function scanMedia(text, pageUrl) {
    var found = [], m, re = /https?:\/\/[^"'\s<>\\]+\.(?:m3u8|mp4)[^"'\s<>\\]*/gi;
    while ((m = re.exec(text || "")) != null) found.push(cleanUrl(m[0]));
    re = /["'](?:file|hls|source|src)["']\s*:\s*["']([^"']+)["']/gi;
    while ((m = re.exec(text || "")) != null) {
        var u = cleanUrl(m[1]);
        if (/^https?:/i.test(u) || u.indexOf("//") === 0) found.push(u.indexOf("//") === 0 ? "https:" + u : u);
    }
    return found;
}

function extractPackedSources(html, pageUrl) {
    var packs = unpackAll(html), all = [], i;
    for (i = 0; i < packs.length; i++) {
        var hits = scanMedia(packs[i], pageUrl);
        for (var j = 0; j < hits.length; j++) all.push(hits[j]);
    }
    var direct = scanMedia(html, pageUrl);
    for (i = 0; i < direct.length; i++) all.push(direct[i]);
    return all;
}

// ========== EXTRACTORES ==========
function exStreamWish(url) {
    var id = "", m = /\/(?:e|v)\/([a-zA-Z0-9]+)/i.exec(url || "");
    if (m) id = m[1];
    var hosts = [hostOf(url), "streamwish.to", "swdyu.com", "strwish.com", "playerwish.com", "flaswish.com", "hlswish.com"];
    var path = id ? "/e/" + id : "";
    for (var i = 0; i < hosts.length; i++) {
        if (!hosts[i]) continue;
        var u = path ? "https://" + hosts[i] + path : url;
        var html = httpGet(u, { "Referer": originOf(url) + "/" });
        if (!html || html.length < 300) continue;
        var hits = extractPackedSources(html, u);
        if (hits.length) return hits[0];
    }
    return null;
}

function exNuupload(url) {
    var html = httpGet(url, { "Referer": originOf(url) + "/" });
    if (!html) return null;
    var hits = extractPackedSources(html, url);
    return hits.length ? hits[0] : null;
}

function exVidhide(url) {
    var html = httpGet(url, { "Referer": originOf(url) + "/" });
    if (!html) return null;
    var hits = extractPackedSources(html, url);
    return hits.length ? hits[0] : null;
}

function exVoe(url) {
    var html = httpGet(url, { "Referer": url });
    if (!html) return null;
    var m = html.match(/hls\s*:\s*['"]([^'"]+\.m3u8[^'"]*)['"]/i) || html.match(/file\s*:\s*['"]([^'"]+\.m3u8[^'"]*)['"]/i);
    return m ? cleanUrl(m[1]) : null;
}

function exDood(url) {
    var html = httpGet(url, { "Referer": url });
    if (!html) return null;
    var pm = html.match(/\/pass_md5\/[^'"\s]+/);
    if (pm) {
        var origin = originOf(_lastUrl || url);
        var base = httpGet(origin + pm[0], { "Referer": _lastUrl || url });
        if (base && base.indexOf("http") === 0) {
            var rnd = "";
            for (var i = 0; i < 10; i++) rnd += "abcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.floor(Math.random() * 36));
            return base + rnd + "?token=" + pm[0].split("/").pop() + "&expiry=" + Date.now();
        }
    }
    var m = html.match(/(?:file|link|source)\s*[:=]\s*['"]([^'"]+\.(?:m3u8|mp4)[^'"]*)['"]/i);
    return m ? cleanUrl(m[1]) : null;
}

function exUqload(url) {
    var html = httpGet(url, { "Referer": originOf(url) + "/" });
    if (!html) return null;
    var hits = extractPackedSources(html, url);
    return hits.length ? hits[0] : null;
}

function exStreamtape(url) {
    var html = httpGet(url, { "Referer": originOf(url) + "/" });
    if (!html) return null;
    var m = html.match(/document\.getElementById\('norobotlink'\)\.innerHTML\s*=\s*['"]([^'"]+)['"]/i);
    if (m) return "https:" + m[1];
    var hits = extractPackedSources(html, url);
    return hits.length ? hits[0] : null;
}

function exMixdrop(url) {
    var html = httpGet(url, { "Referer": originOf(url) + "/" });
    if (!html) return null;
    var hits = extractPackedSources(html, url);
    return hits.length ? hits[0] : null;
}

function exOkRu(url) {
    var html = httpGet(url, { "Referer": "https://ok.ru/" });
    if (!html) return null;
    var m = html.match(/data-options="([^"]*)"/);
    if (!m) return null;
    try {
        var txt = m[1].replace(/"/g, '"').replace(/&/g, "&");
        var o = JSON.parse(txt);
        var meta = o.flashvars && o.flashvars.metadata;
        if (typeof meta === "string") meta = JSON.parse(meta);
        if (meta && meta.hlsManifestUrl) return cleanUrl(meta.hlsManifestUrl);
    } catch (e) {}
    return null;
}

function exGeneric(url, depth) {
    depth = depth || 0;
    if (depth > 2) return null;
    var html = httpGet(url, { "Referer": originOf(url) + "/" });
    if (!html) return null;
    var hits = extractPackedSources(html, url);
    if (hits.length) return hits[0];
    var rd = html.match(/(?:location(?:\.href)?\s*=|location\.replace\()\s*["']([^"']+)["']/i);
    if (rd) {
        var next = cleanUrl(rd[1]);
        if (next.indexOf("//") === 0) next = "https:" + next;
        else if (next.charAt(0) === "/") next = originOf(url) + next;
        if (/^https?:/i.test(next)) return exGeneric(next, depth + 1);
    }
    return null;
}

function extractVideo(pageUrl) {
    if (!pageUrl) return null;
    pageUrl = cleanUrl(pageUrl);
    if (isM3u8Url(pageUrl)) return pageUrl;
    var host = hostOf(pageUrl);
    addDebug("[extract] " + host);

    if (/wish|streamwish|strwish|playerwish|swdyu|flaswish|goodstream/i.test(host)) return exStreamWish(pageUrl);
    if (/nupload|nuupload/i.test(host)) return exNuupload(pageUrl);
    if (/vidhide|callistanise|filelions|morencius/i.test(host)) return exVidhide(pageUrl);
    if (/voe\./i.test(host)) return exVoe(pageUrl);
    if (/dood|do7go/i.test(host)) return exDood(pageUrl);
    if (/uqload/i.test(host)) return exUqload(pageUrl);
    if (/streamtape|tape\./i.test(host)) return exStreamtape(pageUrl);
    if (/mixdrop/i.test(host)) return exMixdrop(pageUrl);
    if (/ok\.ru|odnoklassniki/i.test(host)) return exOkRu(pageUrl);
    if (/vimeus/i.test(host)) return exGeneric(pageUrl);

    return exGeneric(pageUrl);
}

// ========== WEB SCRAPER (fallback) ==========
function parseJuanitaWeb(html) {
    var out = [], seen = {}, tags = html.match(/<[a-zA-Z][^>]*row-download[^>]*>/gi) || [];
    for (var i = 0; i < tags.length; i++) {
        var a = {}, re = /([a-zA-Z0-9_:\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g, m;
        while ((m = re.exec(tags[i])) != null) a[m[1].toLowerCase()] = m[2] || m[3];
        var u = a["data-url"];
        if (!u) continue;
        if (!/^https?:|^\/\//i.test(u)) {
            try { u = bytesToStr(b64ToBytes(u)); } catch (e) {}
        }
        u = cleanUrl(u);
        if (/^https?:/i.test(u) && !seen[u]) { seen[u] = 1; out.push({ url: u, server_name: "Web", audio: a["data-idioma"] || "" }); }
    }
    return out;
}

function juanitaWebServers(isTv, slug) {
    var path = isTv ? "/series/ver-serie/" + slug : "/movies/pelicula/" + slug;
    var html = httpGet(JUANITA_WEB + path, { "Referer": JUANITA_WEB + "/" });
    return parseJuanitaWeb(html || "");
}

function mergeServers(a, b) {
    var out = [], seen = {}, all = (a || []).concat(b || []);
    for (var i = 0; i < all.length; i++) {
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
                videos.push(mkItem(type, it.slug, it.titulo || it.nombre || "", fixImg(it.img_frente || it.poster)));
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
        videos.push(mkItem(tipo, it.slug || it.id, it.titulo_principal || it.titulo || it.nombre || "", fixImg(it.img_frente)));
    }
    return videos;
}

function resolveSources(servidores) {
    var sources = [], list = [];
    for (var i = 0; i < (servidores || []).length; i++) {
        var srv = servidores[i];
        var url = cleanUrl(srv.url || srv.link || "");
        if (!url) continue;
        var host = hostOf(url), skip = false;
        for (var k = 0; k < SKIP_HOSTS.length; k++) if (host.indexOf(SKIP_HOSTS[k]) !== -1) skip = true;
        if (skip) continue;
        list.push({ srv: srv, url: url });
    }
    for (var j = 0; j < list.length && sources.length < MAX_SOURCES; j++) {
        var it = list[j];
        var name = (it.srv.server_name || it.srv["server-name"] || it.srv.ServerName || "Servidor") + " [" + (it.srv.audio || it.srv.idioma || "") + "]";
        addDebug("[resolve] " + name);
        var hls = extractVideo(it.url);
        if (!hls) continue;
        var isMp4 = !isM3u8Url(hls) && (hls.indexOf(".mp4") !== -1 || hls.indexOf("token=") !== -1);
        var src = isMp4 ? mkMp4(hls, name, originOf(_lastUrl || it.url)) : mkHls(hls, name, originOf(_lastUrl || it.url));
        if (src) { sources.push(src); addDebug("[resolve] OK " + name); }
    }
    return sources;
}

function getEpisodes(slug) {
    var sdata = apiGet("/series.php?slug=" + encodeURIComponent(slug));
    var info = sdata ? (sdata.datos || null) : null;
    if (!info) return { info: null, videos: [] };
    var total = parseInt(info.temporadas, 10) || 1;
    var vids = [], name = info.nombre || slug, thumb = fixImg(info.img_frente);
    for (var t = 1; t <= total && t <= 20; t++) {
        var f = apiGet("/series.php?slug=" + encodeURIComponent(slug) + "&t=" + t);
        if (!f) continue;
        var eps = Array.isArray(f.episodios) ? f.episodios : [];
        for (var i = 0; i < eps.length; i++) {
            var n = eps[i].enum || eps[i].e || (i + 1);
            vids.push(mkVideo("e_" + slug + "_" + t + "_" + n, "T" + t + "E" + n + " · " + (eps[i].titulo || "Capítulo " + n), thumb, "pj://ep/" + slug + "/" + t + "/" + n, name));
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
        var servidores = mergeServers(parseServidores(d.servidores), juanitaWebServers(false, slug));
        var sources = resolveSources(servidores);
        var desc = (d.sinopsis || "") + "\n\nAño: " + (d.año || "");
        if (!sources.length) throw new ScriptException("SIN FUENTES\n" + _debugLog);
        return mkDetail("m_" + slug, d.titulo || slug, fixImg(d.img_frente), url, sources, desc);
    }

    var ep = url.match(/pj:\/\/ep\/([^\/]+)\/(\d+)\/(\d+)/);
    if (ep) {
        var eslug = ep[1], et = ep[2], en = ep[3];
        var edata = apiGet("/series.php?slug=" + encodeURIComponent(eslug) + "&t=" + et + "&e=" + en);
        var apiSrv = edata ? parseServidores(edata.servidores) : [];
        var webSrv = juanitaWebServers(true, eslug);
        var esources = resolveSources(mergeServers(apiSrv, webSrv));
        if (!esources.length) throw new ScriptException("SIN FUENTES\n" + _debugLog);
        return mkDetail("e_" + eslug + "_" + et + "_" + en, eslug + " T" + et + "E" + en, "", url, esources, "");
    }

    var c = url.match(/pj:\/\/channel\/([^\/]+)/);
    if (c) {
        var ckey = c[1], ch = _channels[ckey];
        if (!ch) { doHome(); ch = _channels[ckey]; }
        if (!ch) throw new ScriptException("Canal no encontrado");
        var csrc = [];
        if (ch.m3u8) csrc.push(mkHls(cleanUrl(ch.m3u8), "Directo"));
        if (ch.dash && typeof DashSource !== "undefined") csrc.push(new DashSource({ name: "DASH", url: cleanUrl(ch.dash), duration: 0 }));
        if (!csrc.length) throw new ScriptException("Canal sin stream");
        return mkDetail("ch_" + ckey, ch.nombre || ckey, ch.logo || "", url, csrc, "TV en vivo", true);
    }

    var s = url.match(/pj:\/\/serie\/([^\/]+)/);
    if (s) throw new ScriptException("Las series se abren como lista de episodios.");

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
    source.enable = function () {};
    source.setSettings = function () {};
    source.getSearchCapabilities = function () { return { types: [2], sorts: [], filters: [] }; };
    source.search = function (query) {
        try { return new VideoPager(doSearch(query || ""), false, null); }
        catch (e) { return new VideoPager([], false, null); }
    };
    source.getHome = function () {
        try { return new VideoPager(doHome(), false, null); }
        catch (e) { return new VideoPager([], false, null); }
    };
    source.isContentDetailsUrl = function (url) { return !!url && url.indexOf("pj://") === 0 && url.indexOf("pj://serie/") !== 0; };
    source.isPlaylistUrl = function (url) { return !!url && url.indexOf("pj://serie/") === 0; };
    source.getPlaylist = function (url) {
        var slug = url.match(/pj:\/\/serie\/([^\/]+)/)[1];
        var r = getEpisodes(slug);
        if (!r.info) throw new ScriptException("Serie no encontrada");
        return new PlatformPlaylistDetails({
            id: new PlatformID("Pelisjuanita", "s_" + slug, PID),
            name: r.info.nombre || slug,
            thumbnail: fixImg(r.info.img_frente),
            author: new PlatformAuthorLink(PPID, "Pelisjuanita", "https://pelisjuanita.com", "", 0),
            datetime: 0, url: url, videoCount: r.videos.length,
            contents: new VideoPager(r.videos, false, null)
        });
    };
    source.isVideoDetailsUrl = function (url) { return source.isContentDetailsUrl(url); };
    source.getContentDetails = function (url) {
        try { return doDetails(url); }
        catch (e) { throw new ScriptException(String(e && e.message ? e.message : e)); }
    };
    source.getVideoDetails = function (url) { return source.getContentDetails(url); };
    source.getContentRecommendations = function () { return new VideoPager([], false, null); };
    source.searchSuggestions = function () { return []; };
    source.isChannelUrl = function () { return false; };
}
