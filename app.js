"use strict";
const eleman = id => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", {fatal: true});
const cerceve = eleman("cerceve");
const paketSiniri = 10 * 1024 * 1024;
const zipSiniri = paketSiniri + 1024 * 1024;
const githubHavuzu = "https://api.github.com/repos/emre5528/AI-Dijital-Ajans/actions";
const calistirmaKodu = /^[1-9][0-9]{0,19}$/;
let githubIslemSuruyor = false;
const durumlar = {
    olusturuldu: "Oluşturuldu", sirada: "Sırada", calisiyor: "Çalışıyor",
    tamamlandi: "Tamamlandı", basarisiz: "Başarısız", kismen_tamamlandi: "Kısmen tamamlandı",
    bekliyor: "Bekliyor", atlandi: "Atlandı", claude_bekliyor: "Uzman bekliyor",
    devam_ediyor: "Devam ediyor", yeni: "Yeni"
};

function parola() {
    const deger = eleman("parola").value;
    if (deger.length < 32 || !crypto.subtle) {
        throw new Error("HTTPS ve en az 32 karakterli mobil paket parolası gerekli.");
    }
    return deger;
}

async function anahtar(deger, salt) {
    const kaynak = await crypto.subtle.importKey("raw", encoder.encode(deger), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        {name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256"},
        kaynak, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]
    );
}

async function istekSifrele(istek, deger) {
    const tuz = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sifreli = new Uint8Array(await crypto.subtle.encrypt(
        {name: "AES-GCM", iv, additionalData: encoder.encode("ajans-talep-v1")},
        await anahtar(deger, tuz), encoder.encode(JSON.stringify(istek))
    ));
    const paket = new Uint8Array(29 + sifreli.length);
    paket[0] = 1;
    paket.set(tuz, 1);
    paket.set(iv, 17);
    paket.set(sifreli, 29);
    return btoa(Array.from(paket, bayt => String.fromCharCode(bayt)).join(""))
        .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function paketAc(paket, deger) {
    if (paket.length < 45 || paket[0] !== 1) throw new Error("Paket biçimi geçersiz.");
    const sonuc = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv: paket.slice(17, 29), additionalData: encoder.encode("ajans-sunum-v1")},
        await anahtar(deger, paket.slice(1, 17)), paket.slice(29)
    );
    return JSON.parse(decoder.decode(sonuc));
}

async function zipPaketiOku(baytlar) {
    const hata = () => new Error("ZIP geçersiz. Yalnızca Ajans Mobil çalıştırmasının özgün ZIP çıktısını seçin.");
    const gorunum = new DataView(baytlar.buffer, baytlar.byteOffset, baytlar.byteLength);
    const u16 = konum => gorunum.getUint16(konum, true);
    const u32 = konum => gorunum.getUint32(konum, true);
    let son = baytlar.length - 22;
    const enErken = Math.max(0, son - 65535);
    while (son >= enErken && (u32(son) !== 0x06054b50 || son + 22 + u16(son + 20) !== baytlar.length)) son--;
    if (son < enErken || u16(son + 4) || u16(son + 6) || u16(son + 8) !== 1 || u16(son + 10) !== 1) throw hata();

    const merkezBoyut = u32(son + 12);
    const merkez = u32(son + 16);
    if (merkezBoyut < 46 || merkez + merkezBoyut !== son || u32(merkez) !== 0x02014b50) throw hata();
    const bayrak = u16(merkez + 8);
    const yontem = u16(merkez + 10);
    const sikisik = u32(merkez + 20);
    const boyut = u32(merkez + 24);
    const adBoyutu = u16(merkez + 28);
    const yerel = u32(merkez + 42);
    if (bayrak & ~0x080e || ![0, 8].includes(yontem) || u16(merkez + 34) ||
        boyut < 45 || boyut > paketSiniri || sikisik < 1 || sikisik > zipSiniri ||
        46 + adBoyutu + u16(merkez + 30) + u16(merkez + 32) !== merkezBoyut ||
        yerel + 30 > merkez || u32(yerel) !== 0x04034b50) throw hata();

    const ad = decoder.decode(baytlar.subarray(merkez + 46, merkez + 46 + adBoyutu));
    if (!["ajans-sunum.ajans", "ajans-durum.ajans", "ajans-prova.ajans"].includes(ad) ||
        u16(yerel + 6) !== bayrak || u16(yerel + 8) !== yontem ||
        u16(yerel + 26) !== adBoyutu || yerel + 30 + adBoyutu > merkez ||
        decoder.decode(baytlar.subarray(yerel + 30, yerel + 30 + adBoyutu)) !== ad) throw hata();
    const baslangic = yerel + 30 + adBoyutu + u16(yerel + 28);
    if (baslangic + sikisik > merkez) throw hata();

    const akimBaytlari = baytlar.subarray(baslangic, baslangic + sikisik);
    if (yontem === 0) {
        if (boyut !== sikisik) throw hata();
        return akimBaytlari;
    }

    let acici;
    try {
        acici = new DecompressionStream("deflate-raw");
    } catch {
        throw new Error("Bu tarayıcı ZIP açamıyor. Dosyalar uygulamasında ZIP’i açın ve .ajans dosyasını seçin.");
    }
    const okuyucu = new Blob([akimBaytlari]).stream().pipeThrough(acici).getReader();
    const acilmis = new Uint8Array(boyut);
    let yazilan = 0;
    try {
        while (true) {
            const {done, value} = await okuyucu.read();
            if (done) break;
            if (yazilan + value.length > boyut) throw hata();
            acilmis.set(value, yazilan);
            yazilan += value.length;
        }
    } catch {
        await okuyucu.cancel().catch(() => {});
        throw hata();
    }
    if (yazilan !== boyut) throw hata();
    return acilmis;
}

async function dosyaOku(dosya) {
    if (!dosya || dosya.size > zipSiniri) throw new Error("Ajans Mobil ZIP çıktısını veya 10 MB’a kadar bir .ajans dosyasını seçin.");
    const baytlar = new Uint8Array(await dosya.arrayBuffer());
    if (baytlar[0] === 0x50 && baytlar[1] === 0x4b) return zipPaketiOku(baytlar);
    if (baytlar.length > paketSiniri) throw new Error(".ajans dosyası 10 MB sınırını aşıyor.");
    return baytlar;
}

const gorunum = {musteriler: [], gorevler: [], yuklendi: false};

function ekran(ad) {
    const hedef = document.querySelector(`[data-ekran="${ad}"]`);
    if (!hedef) return;
    for (const sayfa of document.querySelectorAll("[data-ekran]")) sayfa.hidden = sayfa !== hedef;
    for (const link of document.querySelectorAll(".alt a")) {
        if (link.hash === "#" + ad || ad === "musteri" && link.hash === "#musteriler")
            link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
    }
    document.title = (hedef.querySelector("h1")?.textContent || "Ajans paneli") + " · Ajans Mobil";
    window.scrollTo(0, 0);
}

function gezin(ad) {
    if (location.hash === "#" + ad) rota();
    else location.hash = ad;
}

function rota() {
    const hash = location.hash.slice(1);
    if (/^musteri\/IS-[0-9]{4,}$/.test(hash)) {
        musteriGoster(hash.split("/")[1]);
        ekran("musteri");
    } else if (hash.startsWith("calistirma=")) {
        const kod = new URLSearchParams(hash).get("calistirma");
        if (kod && calistirmaKodu.test(kod)) eleman("calistirma").value = kod;
        eleman("teknik").open = true;
        ekran("ayarlar");
    } else {
        ekran(["ana", "yeni", "musteriler", "devam-eden", "tamamlanan", "raporlar", "sunum", "ayarlar"].includes(hash) ? hash : "ana");
    }
}

function yazi(tur, metin, sinif) {
    const e = document.createElement(tur);
    e.textContent = metin;
    if (sinif) e.className = sinif;
    return e;
}

function dugme(ad, islem) {
    const e = yazi("button", ad, "ikincil");
    e.type = "button";
    e.addEventListener("click", islem);
    return e;
}

function satir(ana, ek) {
    const e = document.createElement("article");
    e.append(yazi("strong", ana), yazi("p", ek));
    return e;
}

function durumuYaz(durum) {
    return durumlar[durum] || durum || "Durum yok";
}

function gorevSatiri(g, proje = false) {
    const e = satir(g.isletme || g.id, [g.id, durumuYaz(g.durum), g.guncelleme?.slice(0, 10)].filter(Boolean).join(" · "));
    if (Array.isArray(g.asamalar) && g.asamalar.length) {
        const ayrinti = document.createElement("details");
        ayrinti.append(yazi("summary", "Aşamalar"));
        const liste = document.createElement("ul");
        for (const a of g.asamalar) liste.append(yazi("li", `${a.ad} · ${durumuYaz(a.durum)}`));
        ayrinti.append(liste);
        e.append(ayrinti);
    }
    if (proje && /^IS-[0-9]{4,}$/.test(g.kod)) {
        e.append(dugme("Müşteri dosyasını aç", () => gezin("musteri/" + g.kod)));
    } else if (/^AJ-[0-9]{8}-[0-9]{3,}$/.test(g.id)) {
        e.append(dugme("Sürdür", () => {
            gezin("devam-eden");
            eleman("devam-alani").open = true;
            eleman("gorev").value = g.id;
            requestAnimationFrame(() => eleman("gorev").focus());
        }));
    }
    return e;
}

function listele(id, elemanlar, bos) {
    eleman(id).replaceChildren(...(elemanlar.length ? elemanlar : [yazi("p", gorunum.yuklendi ? bos :
        "Kayıtları açmak için güvenli bağlantıyı girin ve Yenile’yi seçin.", "panel")]));
}

function panoGuncelle(paket) {
    if (!Array.isArray(paket.gorevler) && !Array.isArray(paket.musteriler)) return;
    const gorevler = Array.isArray(paket.gorevler) ? paket.gorevler : [];
    if (Array.isArray(paket.musteriler)) {
        gorunum.musteriler = paket.musteriler;
        gorunum.gorevler = gorevler;
    } else {
        const yeni = new Set(gorevler.map(g => g.id));
        gorunum.gorevler = [...gorevler, ...gorunum.gorevler.filter(g => !yeni.has(g.id))];
        for (const g of gorevler) {
            if (g.kod && !gorunum.musteriler.some(m => m.kod === g.kod))
                gorunum.musteriler.push({kod: g.kod, ad: g.isletme || g.kod});
        }
    }
    gorunum.yuklendi = true;
    panoCiz();
    const musteriRotasi = /^#musteri\/(IS-[0-9]{4,})$/.exec(location.hash);
    if (musteriRotasi) musteriGoster(musteriRotasi[1]);
}

function panoCiz() {
    const acik = gorunum.gorevler.filter(g => !["tamamlandi","basarisiz"].includes(g.durum));
    const proje = gorunum.gorevler.filter(g => g.asamalar?.some(a => a.ad === "rapor" && a.durum === "tamamlandi"));
    listele("musteriler", gorunum.musteriler.filter(m => /^IS-[0-9]{4,}$/.test(m.kod)).map(m => {
        const e = satir(m.ad || m.kod, [m.kod, m.sektor, m.guncelleme?.slice(0, 10)].filter(Boolean).join(" · "));
        e.append(dugme("Dosyayı aç", () => gezin("musteri/" + m.kod)));
        return e;
    }), "Henüz müşteri kaydı bulunamadı.");
    listele("acik-isler", acik.map(g => gorevSatiri(g)), "Devam eden iş yok.");
    listele("biten-isler", proje.map(g => gorevSatiri(g, true)), "Tamamlanan sunum bulunamadı.");
    listele("raporlar", gorunum.yuklendi ? [
        ["Müşteriler", gorunum.musteriler.length], ["Listelenen görevler", gorunum.gorevler.length],
        ["Devam eden işler", acik.length], ["Sunumu hazır görevler", proje.length],
    ].map(([ad, sayi]) => {
        const e = yazi("article", "", "kart");
        e.append(yazi("span", ad), yazi("h2", String(sayi)));
        return e;
    }) : [], "Rapor bulunamadı.");
}

function musteriGoster(kod) {
    const m = gorunum.musteriler.find(x => x.kod === kod);
    const ana = eleman("musteri-icerik");
    eleman("musteri-baslik").textContent = m?.ad || "Müşteri dosyası";
    const bilgi = satir(kod, [m?.sektor, m?.guncelleme?.slice(0, 10)].filter(Boolean).join(" · "));
    bilgi.className = "panel";
    bilgi.append(dugme("Sunum ve demoları aç", () => githubAkisi("musteri-dosyasi", {musteri: kod})));
    const baslik = yazi("h2", "Görev geçmişi");
    const gecmis = document.createElement("div");
    gecmis.className = "liste";
    const gorevler = gorunum.gorevler.filter(g => g.kod === kod);
    gecmis.append(...(gorevler.length ? gorevler.map(g => gorevSatiri(g)) : [yazi("p", "Listelenen görev yok.")]));
    const projeler = yazi("div", "", "liste");
    const turler = {web_sitesi: "Web sitesi", yonetim_paneli: "Yönetim paneli", ai_asistan: "Yapay zekâ asistanı"};
    for (const p of m?.projeler || []) {
        const e = satir(turler[p.tur] || "Demo", `v${p.surum} · ${p.tarih?.slice(0, 10) || ""}`);
        if (Number.isSafeInteger(p.id) && p.id > 0)
            e.append(dugme("Projeyi görüntüle", () => githubAkisi("musteri-dosyasi", {musteri: kod, proje: p.id})));
        projeler.append(e);
    }
    if (!projeler.children.length) projeler.append(yazi("p", "Listelenen demo sürümü yok."));
    ana.replaceChildren(bilgi, yazi("h2", "Projeler"), projeler, baslik, gecmis);
}

function goster(paket) {
    panoGuncelle(paket);
    if (!paket.sunum) return;
    gezin("sunum");
    const sayfalar = [{ad: "Sunum", html: paket.sunum}, ...paket.demolar];
    const dugmeler = eleman("sayfalar");
    const politika = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'\">";
    const yatayKaydirma = `<style>
        @media(max-width: 720px) {
            body { min-width: 0; }
            main, section, .duzen { min-width: 0; max-width: 100%; }
            .ajans-tablo { display: block; max-width: 100%; min-width: 0; overflow-x: auto; }
            .ajans-tablo > table { display: table; width: max-content; min-width: 100%; max-width: none; }
            .ajans-tablo th, .ajans-tablo td { white-space: normal; min-width: 5rem; max-width: 16rem; }
        }
    </style>`;
    function sec(sira) {
        const sayfa = sayfalar[sira];
        // Tarayıcı pasif kaynakları önceden yüklemeden önce içeriği etkisiz bir şablonda işle.
        const icerik = document.createElement("template");
        icerik.innerHTML = sayfa.html;
        icerik.content.querySelectorAll("base, link, meta, iframe, frame, object, embed, audio, video, source, track")
            .forEach(eleman => eleman.remove());
        icerik.content.querySelectorAll("[src], [srcset], [poster], [background]").forEach(eleman => {
            for (const ad of ["src", "srcset", "poster", "background"]) {
                if (ad === "src" && eleman.tagName === "IMG" && /^data:image\/(png|jpeg|gif|webp);base64,/i.test(eleman.getAttribute(ad) || "")) continue;
                eleman.removeAttribute(ad);
            }
        });
        icerik.content.querySelectorAll("[href], [xlink\\:href]").forEach(eleman => {
            for (const ad of ["href", "xlink:href"]) {
                const hedef = eleman.getAttribute(ad);
                if (hedef !== null && !hedef.startsWith("#")) eleman.removeAttribute(ad);
            }
        });
        icerik.content.querySelectorAll("table").forEach(tablo => {
            const varOlan = tablo.parentElement?.matches(".tablo-kap");
            const cerceve = varOlan ? tablo.parentElement : document.createElement("div");
            if (!varOlan) {
                tablo.replaceWith(cerceve);
                cerceve.append(tablo);
            }
            cerceve.classList.add("ajans-tablo");
            cerceve.tabIndex = 0;
            cerceve.setAttribute("role", "region");
            cerceve.setAttribute("aria-label", "Yatay kaydırılabilen tablo");
        });
        const baglantiBetigi = sira === 0 ? `<script>
            document.addEventListener("click", event => {
                const bag = event.target.closest("a[href^='#demo-']");
                if (!bag) return;
                event.preventDefault();
                parent.postMessage({demo: Number(bag.getAttribute("href").slice(6))}, "*");
            });
        <\/script>` : "";
        const geciciDepo = sira > 0 ? `<script>
            try { void window.localStorage; }
            catch {
                const kayitlar = new Map();
                Object.defineProperty(window, "localStorage", {value: {
                    getItem: key => kayitlar.get(key) ?? null,
                    setItem: (key, value) => kayitlar.set(key, String(value)),
                    removeItem: key => kayitlar.delete(key)
                }});
            }
        <\/script>` : "";
        cerceve.srcdoc = "<!doctype html><html lang=tr><head><meta charset=utf-8>" +
            '<meta name="viewport" content="width=device-width, initial-scale=1">' +
            politika + geciciDepo + "</head><body>" + icerik.innerHTML + yatayKaydirma + baglantiBetigi + "</body></html>";
        cerceve.title = sayfa.ad;
        Array.from(dugmeler.children).forEach((dugme, i) => dugme.setAttribute("aria-pressed", String(i === sira)));
    }
    dugmeler.replaceChildren(...sayfalar.map((sayfa, i) => {
        const dugme = document.createElement("button");
        dugme.textContent = sayfa.ad;
        dugme.addEventListener("click", () => sec(i));
        return dugme;
    }));
    eleman("gosterim").hidden = false;
    sec(paket.acilis === 1 && sayfalar.length > 1 ? 1 : 0);
}

window.addEventListener("message", event => {
    if (event.source !== cerceve.contentWindow || event.origin !== "null") return;
    const sira = event.data?.demo;
    if (Number.isInteger(sira) && sira >= 0) eleman("sayfalar").children[sira + 1]?.click();
});

function githubBelirteci() {
    const belirtec = eleman("github-token").value.trim();
    if (!/^github_pat_[A-Za-z0-9_]+$/.test(belirtec)) {
        throw new Error("Bu oturum için fine-grained GitHub belirtecini girin.");
    }
    return belirtec;
}

async function github(rota, belirtec, veri, zip = false) {
    const basliklar = {Authorization: "Bearer " + belirtec};
    if (!zip) {
        basliklar.Accept = "application/vnd.github+json";
        basliklar["X-GitHub-Api-Version"] = "2026-03-10";
    }
    if (veri) basliklar["Content-Type"] = "application/json";
    let donus;
    try {
        donus = await fetch(githubHavuzu + rota, {
            method: veri ? "POST" : "GET", headers: basliklar,
            body: veri ? JSON.stringify(veri) : undefined, credentials: "omit",
            cache: "no-store", referrerPolicy: "no-referrer", redirect: zip ? "follow" : "error",
            signal: AbortSignal.timeout?.(20000)
        });
    } catch {
        throw new Error("GitHub bağlantısı doğrulanamadı. Tekrar göndermeden önce özel çalıştırmaları kontrol edin.");
    }
    if (donus.status === 404 || donus.status === 403 || donus.status === 401) {
        throw new Error("GitHub erişimi reddedildi. Belirtecin bu özel depoya ve Actions’a yetkisini kontrol edin.");
    }
    if (!donus.ok) throw new Error(`GitHub isteği tamamlanamadı (HTTP ${donus.status}).`);
    return donus;
}

async function githubPaketi(donus) {
    if (!donus.body || Number(donus.headers.get("Content-Length")) > zipSiniri) {
        throw new Error("GitHub paketi boyut sınırını aşıyor veya okunamıyor.");
    }
    const okuyucu = donus.body.getReader();
    const parcalar = [];
    let toplam = 0;
    try {
        while (true) {
            const {done, value} = await okuyucu.read();
            if (done) break;
            toplam += value.length;
            if (toplam > zipSiniri) throw new Error("GitHub paketi boyut sınırını aşıyor.");
            parcalar.push(value);
        }
    } finally {
        await okuyucu.cancel().catch(() => {});
    }
    return zipPaketiOku(new Uint8Array(await new Blob(parcalar).arrayBuffer()));
}

function sunumuTemizle() {
    eleman("gosterim").hidden = true;
    eleman("sayfalar").replaceChildren();
    cerceve.removeAttribute("srcdoc");
}

async function githubSonucu(kod, belirtec, paketParolasi, bekle) {
    if (!calistirmaKodu.test(kod)) throw new Error("Geçerli çalıştırma numarasını girin.");
    const durum = eleman("durum");
    for (let deneme = 0; deneme < (bekle ? 18 : 1); deneme++) {
        const is = await (await github("/runs/" + kod, belirtec)).json();
        if (is.path?.split("@")[0] !== ".github/workflows/mobil.yml" ||
            is.head_branch !== "main" || is.event !== "workflow_dispatch") {
            throw new Error("Bu çalıştırma Ajans Mobil’e ait değil.");
        }
        if (is.status === "completed") {
            const liste = await (await github("/runs/" + kod + "/artifacts", belirtec)).json();
            const paket = liste.artifacts.find(a => !a.expired &&
                ["ajans-sunum", "ajans-durum", "ajans-prova"].includes(a.name));
            if (!paket || !calistirmaKodu.test(String(paket.id))) {
                durum.textContent = is.conclusion === "success"
                    ? "Çalıştırma bitti. Açılabilecek paket bulunamadı."
                    : "Çalıştırma tamamlanamadı. Ayrıntıları özel GitHub çalıştırmalarından açın.";
                return;
            }
            const indir = await github("/artifacts/" + paket.id + "/zip", belirtec, null, true);
            goster(await paketAc(await githubPaketi(indir), paketParolasi));
            durum.textContent = is.conclusion === "success" ? "Şifreli sonuç açıldı." : "Kısmi şifreli sonuç açıldı.";
            if (!eleman("gosterim").hidden) eleman("gosterim").scrollIntoView({block: "start"});
            return;
        }
        durum.textContent = "Görev GitHub’da çalışıyor. Bu sayfayı kapatsanız da devam eder.";
        if (bekle && deneme < 17) await new Promise(tamam => setTimeout(tamam, 10000));
    }
    durum.textContent = "Görev sürüyor. Daha sonra GitHub sonucunu aç düğmesiyle tekrar kontrol edin.";
}

function githubKilit(durum) {
    githubIslemSuruyor = durum;
    for (const id of ["github-ac", "ac", "talep-gonder", "devam-gonder", "github-token", "kilitle"]) eleman(id).disabled = durum;
    for (const e of document.querySelectorAll(".esitle")) e.disabled = durum;
}

eleman("github-token").addEventListener("input", () => {
    const bagli = Boolean(eleman("github-token").value.trim());
    eleman("talep-gonder").textContent = bagli ? "Görevi başlat" : "Talebi şifrele";
    eleman("devam-gonder").textContent = bagli ? "Görevi sürdür" : "Görev kodunu şifrele";
});

async function baslat(islem, kod, belirtec, paketParolasi) {
    const girdiler = kod ? {islem, paket: kod} : {islem};
    const cevap = await github("/workflows/mobil.yml/dispatches", belirtec, {ref: "main", inputs: girdiler});
    const kayit = await cevap.json().catch(() => ({}));
    const numara = String(kayit.workflow_run_id);
    if (!calistirmaKodu.test(numara))
        throw new Error("İstek kabul edildi ancak çalıştırma numarası alınamadı. GitHub çalıştırmalarını kontrol edin.");
    eleman("calistirma").value = numara;
    sunumuTemizle();
    await githubSonucu(numara, belirtec, paketParolasi, true);
}

async function githubAkisi(islem, istek) {
    if (githubIslemSuruyor) return;
    githubKilit(true);
    try {
        if (!eleman("github-token").value.trim() || !eleman("parola").value) {
            gezin("ayarlar");
            throw new Error("Ayarlar’dan güvenli bağlantıyı girin ve yeniden deneyin.");
        }
        const paketParolasi = parola();
        const kod = istek ? await istekSifrele(istek, paketParolasi) : "";
        await baslat(islem, kod, githubBelirteci(), paketParolasi);
    } catch (hata) {
        eleman("durum").textContent = hata instanceof DOMException ? "Şifreli sonuç açılamadı." : hata.message;
    } finally {
        githubKilit(false);
    }
}

window.addEventListener("hashchange", rota);
panoCiz();
rota();
for (const e of document.querySelectorAll(".esitle")) e.addEventListener("click", () => githubAkisi("durum-listesi"));

eleman("baglanti-kaydet").addEventListener("click", () => {
    try {
        parola();
        if (eleman("github-token").value.trim()) githubBelirteci();
        eleman("durum").textContent = "Güvenli erişim bilgileri bu sekmede hazır.";
        gezin("ana");
    } catch (hata) {
        eleman("durum").textContent = hata.message;
    }
});
eleman("kilitle").addEventListener("click", () => {
    for (const id of ["parola", "github-token", "calistirma", "kod", "paket"]) eleman(id).value = "";
    for (const id of ["talep", "devam"]) eleman(id).reset();
    eleman("metin").dispatchEvent(new Event("input"));
    eleman("github-token").dispatchEvent(new Event("input"));
    eleman("cikti").hidden = true;
    Object.assign(gorunum, {musteriler: [], gorevler: [], yuklendi: false});
    eleman("musteri-baslik").textContent = "Müşteri dosyası";
    eleman("musteri-icerik").replaceChildren();
    sunumuTemizle();
    panoCiz();
    eleman("durum").textContent = "Bu oturumdaki erişim ve müşteri verileri temizlendi.";
});

const metinKutusu = eleman("metin");
metinKutusu.addEventListener("input", () => {
    eleman("karakter").textContent = `${metinKutusu.value.length.toLocaleString("tr-TR")} / 12.000`;
});
const tanima = window.SpeechRecognition || window.webkitSpeechRecognition;
const mikrofon = eleman("mikrofon");
const mikrofonBilgi = eleman("mikrofon-bilgi");
if (!tanima) {
    mikrofon.textContent = "Klavye diktesine geç";
    mikrofon.addEventListener("click", () => {
        metinKutusu.focus();
        mikrofonBilgi.textContent = "Doğrudan mikrofon bu tarayıcıda yok. Klavyedeki mikrofon simgesine dokunun.";
    });
} else {
    let kayit = null;
    mikrofon.addEventListener("click", () => {
        if (kayit) return kayit.stop();
        try {
            kayit = new tanima();
            kayit.lang = "tr-TR";
            kayit.interimResults = false;
            kayit.onresult = event => {
                const parcalar = [];
                for (let i = event.resultIndex; i < event.results.length; i++) {
                    if (event.results[i].isFinal) parcalar.push(event.results[i][0].transcript);
                }
                metinKutusu.value = [metinKutusu.value, parcalar.join(" ")].filter(Boolean).join(" ").slice(0, 12000);
                metinKutusu.dispatchEvent(new Event("input"));
            };
            kayit.onerror = () => {
                mikrofonBilgi.textContent = "Mikrofon kullanılamadı. iPhone klavye diktesini deneyin.";
            };
            kayit.onend = () => { kayit = null; mikrofon.textContent = "Mikrofonla yaz"; };
            kayit.start();
            mikrofon.textContent = "Dinlemeyi durdur";
        } catch {
            kayit = null;
            mikrofonBilgi.textContent = "Mikrofon kullanılamadı. iPhone klavye diktesini deneyin.";
        }
    });
}

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});

eleman("github-ac").addEventListener("click", async () => {
    if (githubIslemSuruyor) return;
    githubKilit(true);
    sunumuTemizle();
    try {
        const kod = eleman("calistirma").value.trim();
        await githubSonucu(kod, githubBelirteci(), parola(), false);
    } catch (hata) {
        eleman("durum").textContent = hata instanceof DOMException ? "Şifreli sonuç açılamadı." : hata.message;
    } finally {
        githubKilit(false);
    }
});

eleman("ac").addEventListener("click", async () => {
    const durum = eleman("durum");
    eleman("ac").disabled = true;
    sunumuTemizle();
    try {
        const dosya = eleman("paket").files[0];
        durum.textContent = "Paket açılıyor…";
        goster(await paketAc(await dosyaOku(dosya), parola()));
        durum.textContent = "";
    } catch (hata) {
        durum.textContent = hata instanceof DOMException ? "Paket açılamadı. Parolayı ve dosyayı kontrol edin." : hata.message;
    } finally {
        eleman("ac").disabled = false;
    }
});

for (const id of ["talep", "devam"]) {
    eleman(id).addEventListener("submit", async event => {
        event.preventDefault();
        if (githubIslemSuruyor) return;
        githubKilit(true);
        const durum = eleman("durum");
        eleman("cikti").hidden = true;
        eleman("kod").value = "";
        try {
            const istek = Object.fromEntries(new FormData(event.currentTarget));
            if (id === "talep") istek.claude_plan = eleman("claude-plan").checked;
            if (!eleman("parola").value) {
                gezin("ayarlar");
                throw new Error("Ayarlar’dan mobil paket parolasını girin; talimat formda kalır.");
            }
            const paketParolasi = parola();
            const kod = await istekSifrele(istek, paketParolasi);
            if (kod.length > 60000) throw new Error("Şifreli talep fazla uzun. Metni kısaltın.");
            if (eleman("github-token").value.trim()) {
                await baslat("sifreli-talep", kod, githubBelirteci(), paketParolasi);
            } else {
                eleman("kod").value = kod;
                eleman("cikti").hidden = false;
                eleman("teknik").open = true;
                gezin("ayarlar");
                durum.textContent = "Şifreli talep hazır.";
            }
        } catch (hata) {
            durum.textContent = hata instanceof DOMException ? "Şifreli sonuç açılamadı." : hata.message;
        } finally {
            githubKilit(false);
        }
    });
}

eleman("kopyala").addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(eleman("kod").value);
        eleman("durum").textContent = "Şifreli talep kopyalandı.";
    } catch {
        eleman("kod").select();
        eleman("durum").textContent = "Seçili şifreli metni kopyalayın.";
    }
});
