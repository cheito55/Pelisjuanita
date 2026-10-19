// Pelisjuanita GrayJay Source
// Basado en la estructura del ejemplo PlPro

var PID = "c7e1a9f2-4b8d-4e3a-9c1f-6d5a2b8e7f41";
var UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
var BASE = "https://pelisjuanita.com/tv/app";
var TMDB_IMG = "https://image.tmdb.org/t/p/w500";

var PPID = new PlatformID("Pelisjuanita", "Pelisjuanita", PID);
var _debugLog = "";

function addDebug(msg) {
    _debugLog += String(msg) + "\n";
}

function httpGet(url) {
    try {
        var r = http.GET(url, {
            "User-Agent": UA,
            "Accept": "application/json",
            "Referer": "https://pelisjuanita.com/"
        });
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
        uploadDate: 0,
        url: url,
        duration: 0,
        viewCount: 0,
        isLive: false
    });
}

function mkHls(url, name) {
    if (!url) return null;
    return new HLSSource({
        name: name || "HLS",
        url: url,
        duration: 0
    });
}

// --- API helpers ---

function apiGet(path) {
    var body = httpGet(BASE + path);
    if (!body) return null;
    try { return JSON.parse(body); } catch (e) { return null; }
}

function doHome() {
    var videos = [];
    var data = apiGet("/home.php");
    if (!data || !data.sections) return videos;

    for (var s = 0; s < data.sections.length; s++) {
        var sec = data.sections[s];
        var items = sec.data || [];
        for (var i = 0; i < items.length && videos.length < 60; i++) {
            var it = items[i];
            if (it.tipo === "TV" || it.m3u8 || it.dash) {
                // Canal en vivo
                videos.push(mkVideo(
                    "ch_" + (it.slug || it.nombre),
                    "[TV] " + (it.nombre || "Canal"),
                    it.logo || "",
                    "pj://channel/" + (it.slug || it.nombre),
                    "TV en Vivo"
                ));
            } else if (it.slug) {
                // Película / serie en home
                var type = (it.tipo === "serie") ? "serie" : "movie";
                videos.push(mkVideo(
                    type + "_" + it.slug,
                    (type === "serie" ? "[Serie] " : "") + (it.titulo || it.nombre || ""),
                    fixImg(it.img_frente || it.poster),
                    "pj://" + type + "/" + it.slug,
                    "Pelisjuanita"
                ));
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
        videos.push(mkVideo(
            tipo + "_" + (it.slug || it.id),
            (tipo === "serie" ? "[Serie] " : "") + (it.titulo_principal || it.titulo || it.nombre || ""),
            fixImg(it.img_frente),
            "pj://" + tipo + "/" + (it.slug || ""),
            "Pelisjuanita"
        ));
    }
    return videos;
}

function doDetails(url) {
    _debugLog = "";
    if (!url) return mkDetail("", "Sin URL", "", "", [], "");

    // Canal
    if (url.indexOf("pj://channel/") === 0) {
        var slug = url.replace("pj://channel/", "");
        return mkDetail("ch_" + slug, slug, "", url, [], "Canal en vivo (usa la app original o revisa canales_json.php para streams)");
    }

    // Película
    var m = url.match(/pj:\/\/movie\/([^\/]+)/);
    if (m) {
        var slug = m[1];
        var data = apiGet("/movies.php?slug=" + encodeURIComponent(slug));
        if (!data || !data.datos) return mkDetail("m_" + slug, "No encontrado", "", url, [], "");
        var d = data.datos;
        var sources = [];
        // Nota: el campo "servidores" viene cifrado (AES-CBC). 
        // Claves en la app original: key="TuClaveSecretaSuperSeguraParaServidores2026!#".slice(0,32) iv="1234567890123456"
        // Aquí devolvemos el detalle y dejamos la extracción para extender.
        var desc = (d.sinopsis || "") + "\n\nAño: " + (d.año || "") + "\nGénero: " + (d.genero || "");
        return mkDetail(
            "m_" + slug,
            d.titulo || d.titulo2 || slug,
            fixImg(d.img_frente),
            url,
            sources,
            desc + "\n\n(Servidores cifrados en la API — se pueden descifrar con las claves de la app)"
        );
    }

    // Serie
    var s = url.match(/pj:\/\/serie\/([^\/]+)/);
    if (s) {
        var sslug = s[1];
        var sdata = apiGet("/series.php?slug=" + encodeURIComponent(sslug));
        if (!sdata || !sdata.datos) return mkDetail("s_" + sslug, "No encontrado", "", url, [], "");
        var sd = sdata.datos;
        var sdesc = (sd.sinopsis || "") + "\n\nTemporadas: " + (sd.temporadas || "?");
        return mkDetail(
            "s_" + sslug,
            sd.nombre || sslug,
            fixImg(sd.img_frente),
            url,
            [],
            sdesc
        );
    }

    return mkDetail("", "No soportado", "", url, [], "");
}

function mkDetail(id, name, thumb, url, sources, description) {
    var valid = [];
    for (var i = 0; i < (sources || []).length; i++) {
        if (sources[i]) valid.push(sources[i]);
    }
    var desc = description || "";
    if (_debugLog) desc += "\n\n=== DEBUG ===\n" + _debugLog;

    return new PlatformVideoDetails({
        id: new PlatformID("Pelisjuanita", String(id), PID),
        name: name || "Sin título",
        thumbnails: mkThumb(thumb),
        author: new PlatformAuthorLink(PPID, "Pelisjuanita", "https://pelisjuanita.com", "", 0),
        uploadDate: 0,
        url: url,
        duration: 0,
        viewCount: 0,
        isLive: false,
        video: new VideoSourceDescriptor(valid),
        description: desc
    });
}

// --- Bindings GrayJay ---

if (typeof source !== "undefined") {
    source.enable = function(c, s) {};
    source.setSettings = function(s) {};

    source.getSearchCapabilities = function() {
        return { types: [2], sorts: [], filters: [] };
    };

    source.search = function(query) {
        try {
            return new VideoPager(doSearch(query || ""), false, null);
        } catch (e) {
            return new VideoPager([], false, null);
        }
    };

    source.getHome = function() {
        try {
            return new VideoPager(doHome(), false, null);
        } catch (e) {
            return new VideoPager([], false, null);
        }
    };

    source.isContentDetailsUrl = function(url) {
        return url && url.indexOf("pj://") === 0;
    };
    source.isVideoDetailsUrl = function(url) {
        return source.isContentDetailsUrl(url);
    };

    source.getContentDetails = function(url) {
        try {
            return doDetails(url);
        } catch (e) {
            return mkDetail("error", "Error", "", url, [], String(e));
        }
    };

    source.getVideoDetails = function(url) {
        return source.getContentDetails(url);
    };

    source.getContentRecommendations = function(url) {
        return new VideoPager([], false, null);
    };

    source.searchSuggestions = function(q) { return []; };
    source.isChannelUrl = function(url) { return false; };
}
