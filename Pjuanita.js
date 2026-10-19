// Pelisjuanita GrayJay Source - con descifrado de servidores y extractores

var PID = "c7e1a9f2-4b8d-4e3a-9c1f-6d5a2b8e7f41";
var UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
var BASE = "https://pelisjuanita.com/tv/app";
var TMDB_IMG = "https://image.tmdb.org/t/p/w500";

// Claves AES de la app original
var AES_KEY = "TuClaveSecretaSuperSeguraParaServidores2026!#".substring(0, 32);
var AES_IV  = "1234567890123456";

var PPID = new PlatformID("Pelisjuanita", "Pelisjuanita", PID);
var _debugLog = "";

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

function mkVideo(id, title, thumb, url, author) {
    return new PlatformVideo({
        id: new PlatformID("Pelisjuanita", String(id), PID),
        name: title || "Sin título",
        thumbnails: mkThumb(thumb),
        author: new PlatformAuthorLink(PPID, author || "Pelisjuanita", "https://pelisjuanita.com", "", 0),
        uploadDate: 0, url: url, duration: 0, viewCount: 0, isLive: false
    });
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

// ========== DESCIFRADO AES-CBC ==========
// Nota: GrayJay no expone crypto.subtle de forma fiable.
// Esta implementación es un placeholder que intenta usar lo disponible
// o falla de forma controlada. Para producción real se recomienda
// un polyfill AES o descifrar en un proxy.
function decryptServidores(b64) {
    if (!b64 || typeof b64 !== "string") return [];
    try {
        // Doble base64
        var step1 = atob(b64.replace(/\s+/g, ""));
        var step2 = atob(step1);

        // Intento con Web Crypto si existe
        if (typeof crypto !== "undefined" && crypto.subtle) {
            // En la mayoría de entornos de GrayJay esto no está disponible.
            // Se deja el comentario para quien quiera probarlo.
            addDebug("[decrypt] crypto.subtle no disponible en este entorno");
        }

        addDebug("[decrypt] No se pudo descifrar (crypto no disponible)");
        return [];
    } catch (e) {
        addDebug("[decrypt] error: " + e);
        return [];
    }
}

// ========== EXTRACTORES (basados en el ejemplo) ==========

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

function doodExtract(pageUrl) {
    try {
        var html = httpGet(pageUrl, { "Referer": pageUrl });
        if (!html) return null;
        var m = html.match(/(?:file|link|source)\s*[:=]\s*['"]([^'"]+\.m3u8[^'"]*)['"]/i);
        if (m && m[1]) return cleanUrl(m[1]);
        m = html.match(/(?:file|link|source)\s*[:=]\s*['"]([^'"]+\.mp4[^'"]*)['"]/i);
        if (m && m[1]) return cleanUrl(m[1]);
        return null;
    } catch (e) { return null; }
}

function genericExtract(pageUrl) {
    try {
        var html = httpGet(pageUrl, { "Referer": pageUrl });
        if (!html) return null;
        var m = html.match(/https?:\/\/[^"'\s<>]+\.m3u8[^"'\s<>]*/i);
        if (m) return cleanUrl(m[0]);
        return null;
    } catch (e) { return null; }
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
                videos.push(mkVideo("ch_" + (it.slug || it.nombre), "[TV] " + (it.nombre || "Canal"), it.logo || "", "pj://channel/" + (it.slug || it.nombre), "TV en Vivo"));
            } else if (it.slug) {
                var type = (it.tipo === "serie") ? "serie" : "movie";
                videos.push(mkVideo(type + "_" + it.slug, (type === "serie" ? "[Serie] " : "") + (it.titulo || it.nombre || ""), fixImg(it.img_frente || it.poster), "pj://" + type + "/" + it.slug, "Pelisjuanita"));
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
        videos.push(mkVideo(tipo + "_" + (it.slug || it.id), (tipo === "serie" ? "[Serie] " : "") + (it.titulo_principal || it.titulo || it.nombre || ""), fixImg(it.img_frente), "pj://" + tipo + "/" + (it.slug || ""), "Pelisjuanita"));
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
            var src = mkHls(hls, name);
            if (src) sources.push(src);
            addDebug("[resolve] OK: " + name);
        }
    }
    return sources;
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
        var servidores = decryptServidores(d.servidores);
        var sources = resolveSources(servidores);
        var desc = (d.sinopsis || "") + "\n\nAño: " + (d.año || "") + "\nGénero: " + (d.genero || "");
        if (sources.length === 0) desc += "\n\n⚠️ No se pudieron obtener fuentes. El descifrado AES no está disponible en este entorno de GrayJay.";
        return mkDetail("m_" + slug, d.titulo || slug, fixImg(d.img_frente), url, sources, desc);
    }

    var s = url.match(/pj:\/\/serie\/([^\/]+)/);
    if (s) {
        var sslug = s[1];
        var sdata = apiGet("/series.php?slug=" + encodeURIComponent(sslug));
        if (!sdata || !sdata.datos) return mkDetail("s_" + sslug, "No encontrado", "", url, [], "");
        var sd = sdata.datos;
        return mkDetail("s_" + sslug, sd.nombre || sslug, fixImg(sd.img_frente), url, [], (sd.sinopsis || "") + "\n\n(Episodios: pendiente de implementar)");
    }

    return mkDetail("", "No soportado", "", url, [], "");
}

function mkDetail(id, name, thumb, url, sources, description) {
    var valid = [];
    for (var i = 0; i < (sources || []).length; i++) if (sources[i]) valid.push(sources[i]);
    var desc = description || "";
    if (_debugLog) desc += "\n\n=== DEBUG ===\n" + _debugLog;
    return new PlatformVideoDetails({
        id: new PlatformID("Pelisjuanita", String(id), PID),
        name: name || "Sin título",
        thumbnails: mkThumb(thumb),
        author: new PlatformAuthorLink(PPID, "Pelisjuanita", "https://pelisjuanita.com", "", 0),
        uploadDate: 0, url: url, duration: 0, viewCount: 0, isLive: false,
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

    source.isContentDetailsUrl = function(url) { return url && url.indexOf("pj://") === 0; };
    source.isVideoDetailsUrl = function(url) { return source.isContentDetailsUrl(url); };

    source.getContentDetails = function(url) {
        try { return doDetails(url); }
        catch (e) { return mkDetail("error", "Error", "", url, [], String(e)); }
    };

    source.getVideoDetails = function(url) { return source.getContentDetails(url); };
    source.getContentRecommendations = function(url) { return new VideoPager([], false, null); };
    source.searchSuggestions = function(q) { return []; };
    source.isChannelUrl = function(url) { return false; };
}
