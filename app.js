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
    if (!deger) return null;                      // parolasız cihaz kipi
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
    if (v2Mi(paket)) return zarfAc(paket);          // parolasız cihaz paketi
    if (!deger) throw new Error("Bu eski paket mobil paket parolası ister (Ayarlar → Eski paketler).");
    if (paket.length < 45 || paket[0] !== 1) throw new Error("Paket biçimi geçersiz.");
    const sonuc = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv: paket.slice(17, 29), additionalData: encoder.encode("ajans-sunum-v1")},
        await anahtar(deger, paket.slice(1, 17)), paket.slice(29)
    );
    return JSON.parse(decoder.decode(sonuc));
}


// ---------------------------------------------------------------- Cihaz oturumu (parolasız, zarf v2)
// GitHub belirteci, dışa aktarılamayan bir AES-GCM anahtarıyla şifrelenip IndexedDB'de saklanır.
// Cihazın ECDH P-256 özel anahtarı dışa aktarılamaz; sonuçlar yalnızca bu cihazda açılır.
const TUZ = encoder.encode("ajans-cihaz-v2-tuz");
const GOREV_AMAC = encoder.encode("ajans-gorev-v2");
const SONUC_AMAC = encoder.encode("ajans-sonuc-v2");
const b64u = baytlar => btoa(Array.from(new Uint8Array(baytlar), b => String.fromCharCode(b)).join(""))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const b64uCoz = metin => {
    if (!/^[A-Za-z0-9_-]+$/.test(metin)) throw new Error("Paket biçimi geçersiz.");
    const s = atob(metin.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((metin.length + 3) % 4));
    return Uint8Array.from(s, c => c.charCodeAt(0));
};
const birlestir = (...parcalar) => {
    const sonuc = new Uint8Array(parcalar.reduce((t, p) => t + p.length, 0));
    let i = 0;
    for (const p of parcalar) { sonuc.set(p, i); i += p.length; }
    return sonuc;
};

function depo(islem) {
    return new Promise((tamam, hata) => {
        const ac = indexedDB.open("ajans-cihaz", 1);
        ac.onupgradeneeded = () => ac.result.createObjectStore("oturum");
        ac.onerror = () => hata(new Error("Cihaz deposu açılamadı (özel tarama kapalı olmalı)."));
        ac.onsuccess = () => {
            const tx = ac.result.transaction("oturum", "readwrite");
            const s = tx.objectStore("oturum");
            const r = islem(s);
            tx.oncomplete = () => { ac.result.close(); tamam(r?.result); };
            tx.onerror = () => { ac.result.close(); hata(new Error("Cihaz deposu yazılamadı.")); };
        };
    });
}
const depoAl = ad => depo(s => s.get(ad));
const depoYaz = (ad, deger) => depo(s => s.put(deger, ad));

async function cihazAnahtari() {
    let cift = await depoAl("cihaz");
    if (!cift) {
        cift = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, false, ["deriveBits"]);
        await depoYaz("cihaz", cift);
    }
    return {cift, ham: new Uint8Array(await crypto.subtle.exportKey("raw", cift.publicKey))};
}

async function belirtecKaydet(belirtec) {
    if (!/^github_pat_[A-Za-z0-9_]{20,}$/.test(belirtec)) throw new Error("Fine-grained GitHub belirteci (github_pat_…) girin.");
    const anahtar = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sifreli = await crypto.subtle.encrypt({name: "AES-GCM", iv}, anahtar, encoder.encode(belirtec));
    await depoYaz("belirtec", {anahtar, iv, sifreli});
}

async function kayitliBelirtec() {
    const k = await depoAl("belirtec").catch(() => null);
    if (!k) return "";
    try {
        return decoder.decode(await crypto.subtle.decrypt({name: "AES-GCM", iv: k.iv}, k.anahtar, k.sifreli));
    } catch { return ""; }
}

async function oturumKapat() {
    await new Promise(tamam => { const r = indexedDB.deleteDatabase("ajans-cihaz"); r.onsuccess = r.onerror = r.onblocked = () => tamam(); });
}

async function ortakAnahtar(gizli, karsiHam, e, aliciHam, amac) {
    const karsi = await crypto.subtle.importKey("raw", karsiHam, {name: "ECDH", namedCurve: "P-256"}, false, []);
    const bitler = await crypto.subtle.deriveBits({name: "ECDH", public: karsi}, gizli, 256);
    const kaynak = await crypto.subtle.importKey("raw", bitler, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name: "HKDF", hash: "SHA-256", salt: TUZ, info: birlestir(amac, e, aliciHam)},
        kaynak, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
}

async function zarfSifrele(veri, sunucuHam) {
    const {ham: cihazHam} = await cihazAnahtari();
    const gecici = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, false, ["deriveBits"]);
    const e = new Uint8Array(await crypto.subtle.exportKey("raw", gecici.publicKey));
    const anahtar = await ortakAnahtar(gecici.privateKey, sunucuHam, e, sunucuHam, GOREV_AMAC);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const c = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: GOREV_AMAC}, anahtar,
        encoder.encode(JSON.stringify(veri)));
    return b64u(encoder.encode(JSON.stringify({v: 2, e: b64u(e), iv: b64u(iv), c: b64u(c), d: b64u(cihazHam)})));
}

async function zarfAc(baytlar) {
    const zarf = JSON.parse(decoder.decode(b64uCoz(decoder.decode(baytlar).trim())));
    if (zarf?.v !== 2) throw new Error("Paket biçimi geçersiz.");
    const {cift, ham} = await cihazAnahtari();
    const e = b64uCoz(zarf.e);
    const anahtar = await ortakAnahtar(cift.privateKey, e, e, ham, SONUC_AMAC);
    const duz = await crypto.subtle.decrypt({name: "AES-GCM", iv: b64uCoz(zarf.iv), additionalData: SONUC_AMAC},
        anahtar, b64uCoz(zarf.c));
    return JSON.parse(decoder.decode(duz));
}

const v2Mi = baytlar => baytlar.length > 20 && baytlar[0] !== 1 && /^[A-Za-z0-9_-]/.test(String.fromCharCode(baytlar[0]));

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
    if (!["ajans-sunum.ajans", "ajans-durum.ajans", "ajans-prova.ajans", "ajans-anahtar.txt"].includes(ad) ||
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

const gorunum = {musteriler: [], gorevler: [], firsatlar: [], yuklendi: false};
let talimatKipi = "yeni-gorev";
const taslaklar = new Map();

function ekran(ad) {
    const hedef = document.querySelector(`[data-ekran="${ad}"]`);
    if (!hedef) return;
    for (const sayfa of document.querySelectorAll("[data-ekran]")) sayfa.hidden = sayfa !== hedef;
    const form = eleman("talep");
    form.hidden = !hedef.hasAttribute("data-talimat");
    if (!form.hidden) {
        const kip = ad === "musteri-bul" ? ad : "yeni-gorev";
        if (kip !== talimatKipi) {
            taslaklar.set(talimatKipi, eleman("metin").value);
            talimatKipi = kip;
            eleman("metin").value = taslaklar.get(kip) || "";
            eleman("metin").dispatchEvent(new Event("input"));
        }
        const hero = hedef.querySelector(".hero");
        if (hero) hero.after(form); else hedef.append(form);
    }
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
        ekran(["ana", "yeni", "musteri-bul", "musteriler", "devam-eden", "tamamlanan", "firsatlar", "raporlar", "sunum", "ayarlar", "teslimatlar", "urun-uret"].includes(hash) ? hash : "ana");
        if (hash === "teslimatlar") teslimatlariYukle();
        if (hash === "urun-uret") uretimGecmisi();
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
    } else if (!g.kod && g.asamalar?.some(a => a.ad === "genel-arastirma") && /^AJ-[0-9]{8}-[0-9]{3,}$/.test(g.id)) {
        e.append(dugme("Araştırmayı aç", () => githubAkisi("musteri-dosyasi", {genel: g.id})));
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
    if (Array.isArray(paket.firsatlar)) {
        const kimlikler = new Set(paket.firsatlar.map(f => f.id));
        gorunum.firsatlar = Array.isArray(paket.musteriler) ? paket.firsatlar :
            [...paket.firsatlar, ...gorunum.firsatlar.filter(f => !kimlikler.has(f.id))];
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
    listele("firsatlar", gorunum.firsatlar.map(f => {
        const e = satir([f.sektor, f.konum].filter(Boolean).join(" · "), f.id + " · " + f.aday_sayisi + " aday");
        if (/^AJ-[0-9]{8}-[0-9]{3,}$/.test(f.id)) e.append(dugme("Araştırmayı aç", () => githubAkisi("musteri-dosyasi", {genel:f.id})));
        return e;
    }), "Henüz kayıtlı satış araştırması yok.");
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

let oturumBelirteci = "";
function githubBelirteci() {
    const belirtec = oturumBelirteci || eleman("github-token").value.trim();
    if (!/^github_pat_[A-Za-z0-9_]+$/.test(belirtec)) {
        gezin("ayarlar");
        throw new Error("Bu cihazı bir kez bağlayın: Ayarlar → Cihazı bağla.");
    }
    return belirtec;
}

async function oturumuYukle() {
    oturumBelirteci = await kayitliBelirtec();
    const bitis = localStorage.getItem("ajans-belirtec-bitis");
    eleman("oturum-durum").textContent = oturumBelirteci
        ? "Bu cihaz bağlı." + (bitis ? ` Belirteç bitişi: ${bitis}. Süre dolunca yeniden bağlamanız gerekir.` : "")
        : "Cihaz bağlı değil. Görev başlatmak için bir kez bağlayın.";
    eleman("oturum-kapat").hidden = !oturumBelirteci;
}

async function sunucuAnahtari(belirtec) {
    const kayitli = localStorage.getItem("ajans-sunucu-anahtari");
    if (kayitli && /^[A-Za-z0-9_-]{86,88}$/.test(kayitli)) return b64uCoz(kayitli);
    eleman("durum").textContent = "Cihaz güvenli anahtarı GitHub'dan alınıyor (yalnızca ilk kez)…";
    const cevap = await github("/workflows/mobil.yml/dispatches", belirtec, {ref: "main", inputs: {islem: "cihaz-anahtari"}});
    const numara = String((await cevap.json().catch(() => ({}))).workflow_run_id);
    if (!calistirmaKodu.test(numara)) throw new Error("Anahtar çalıştırması başlatılamadı.");
    for (let deneme = 0; deneme < 30; deneme++) {
        await new Promise(tamam => setTimeout(tamam, deneme ? 6000 : 3000));
        const is = await (await github("/runs/" + numara, belirtec)).json();
        if (is.status !== "completed") continue;
        if (is.conclusion !== "success") throw new Error("Anahtar çalıştırması başarısız oldu.");
        const liste = await (await github("/runs/" + numara + "/artifacts", belirtec)).json();
        const a = liste.artifacts.find(x => x.name === "ajans-anahtar" && !x.expired);
        if (!a) throw new Error("Anahtar dosyası bulunamadı.");
        const metin = decoder.decode(await githubPaketi(await github("/artifacts/" + a.id + "/zip", belirtec, null, true))).trim();
        if (!/^[A-Za-z0-9_-]{86,88}$/.test(metin)) throw new Error("Sunucu anahtarı biçimi geçersiz.");
        localStorage.setItem("ajans-sunucu-anahtari", metin);
        return b64uCoz(metin);
    }
    throw new Error("Anahtar çalıştırması zamanında bitmedi; birazdan tekrar deneyin.");
}

async function istekPaketi(istek, belirtec, paketParolasi) {
    if (paketParolasi) return istekSifrele(istek, paketParolasi);   // eski parola kipi (isteğe bağlı)
    return zarfSifrele(istek, await sunucuAnahtari(belirtec));
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
    const bitis = donus.headers.get("github-authentication-token-expiration");
    if (bitis) localStorage.setItem("ajans-belirtec-bitis", bitis.slice(0, 16));
    if (donus.status === 401) {
        throw new Error("Oturum süresi doldu veya belirteç geçersiz. Ayarlar → Cihazı bağla ile yeniden yetkilendirin.");
    }
    if (donus.status === 404 || donus.status === 403) {
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
    for (const id of ["github-ac", "ac", "talep-gonder", "devam-gonder", "github-token", "kilitle", "cihaz-bagla"]) eleman(id).disabled = durum;
    for (const e of document.querySelectorAll(".esitle")) e.disabled = durum;
}

eleman("github-token").addEventListener("input", () => {
    eleman("talep-gonder").textContent = "Başlat";
    eleman("devam-gonder").textContent = "Görevi sürdür";
});

eleman("cihaz-bagla").addEventListener("click", async () => {
    const durum = eleman("durum");
    githubKilit(true);
    try {
        const belirtec = eleman("github-token").value.trim();
        await belirtecKaydet(belirtec);
        await github("/workflows/mobil.yml", belirtec);          // yetki doğrulaması
        eleman("github-token").value = "";
        await oturumuYukle();
        await sunucuAnahtari(oturumBelirteci);
        durum.textContent = "Cihaz bağlandı. Artık yalnızca komutunuzu yazıp Başlat’a dokunun.";
        gezin("ana");
    } catch (hata) {
        durum.textContent = hata.message;
    } finally {
        githubKilit(false);
    }
});
eleman("oturum-kapat").addEventListener("click", async () => {
    await oturumKapat();
    for (const a of ["ajans-sunucu-anahtari", "ajans-belirtec-bitis"]) localStorage.removeItem(a);
    oturumBelirteci = "";
    await oturumuYukle();
    eleman("durum").textContent = "Bu cihazın oturumu kapatıldı; kayıtlı belirteç ve cihaz anahtarı silindi.";
});
oturumuYukle().catch(() => {});

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
        const belirtec = githubBelirteci();
        const paketParolasi = parola();
        const kod = istek ? await istekPaketi(istek, belirtec, paketParolasi)
            : (paketParolasi ? "" : await istekPaketi({}, belirtec, null));   // yanıt bu cihaza şifrelenir
        await baslat(islem, kod, belirtec, paketParolasi);
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
        if (!parola()) throw new Error("Eski paketler için mobil paket parolasını girin.");
        eleman("durum").textContent = "Parola yalnızca bu sekmede, eski paketleri açmak için hazır.";
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
    taslaklar.clear();
    Object.assign(gorunum, {musteriler: [], gorevler: [], firsatlar: [], yuklendi: false});
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

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js?v=3").catch(() => {});

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
            if (id === "talep") {
                istek.claude_plan = true;
                istek.kip = talimatKipi;
            }
            const paketParolasi = parola();
            const belirtecVar = Boolean(oturumBelirteci || eleman("github-token").value.trim());
            if (!belirtecVar && !paketParolasi) {
                gezin("ayarlar");
                throw new Error("Bu cihazı bir kez bağlayın (Ayarlar → Cihazı bağla); talimat formda kalır.");
            }
            const kod = belirtecVar ? await istekPaketi(istek, githubBelirteci(), paketParolasi)
                : await istekSifrele(istek, paketParolasi);
            if (kod.length > 60000) throw new Error("Şifreli talep fazla uzun. Metni kısaltın.");
            if (belirtecVar) {
                durum.textContent = "Görev başlatıldı. Bilgisayarınız kapalı olsa da GitHub'da çalışır.";
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

// Teslimatlar: ürünler panel içinde değil, ayrı HTTPS adreslerinde tarayıcıda açılır.
const TESLIM_KATALOG = "https://emre5528.github.io/ajans-urunler/urunler.json";
const TESLIM_TABAN = "https://emre5528.github.io/ajans-urunler/";
async function teslimatlariYukle() {
    const kutu = eleman("teslim-liste");
    try {
        const yanit = await fetch(TESLIM_KATALOG, {cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer"});
        if (!yanit.ok) throw new Error("HTTP " + yanit.status);
        const veri = await yanit.json();
        const urunler = Array.isArray(veri.urunler) ? veri.urunler : [];
        kutu.replaceChildren();
        if (!urunler.length) { kutu.textContent = "Henüz yayımlanmış ürün yok."; return; }
        for (const u of urunler) {
            const adres = String(u.url || "");
            if (!adres.startsWith(TESLIM_TABAN)) continue;   // yalnızca ürün alanındaki adresler
            const kart = document.createElement("article");
            const baslik = document.createElement("strong"); baslik.textContent = String(u.ad || u.slug);
            const aciklama = document.createElement("p"); aciklama.textContent = String(u.aciklama || "");
            const etiket = document.createElement("small");
            etiket.textContent = (u.statik ? "Statik prototip · kurgusal işletme" : "Canlı uygulama") +
                (Array.isArray(u.canli_icin) && u.canli_icin.length ? " · Canlı için gerekir: " + u.canli_icin.join(", ") : "");
            const ac = document.createElement("a");
            ac.href = adres; ac.target = "_blank"; ac.rel = "noopener noreferrer"; ac.className = "dugme"; ac.textContent = "Tarayıcıda aç ↗";
            kart.append(baslik, aciklama, etiket, ac);
            kutu.appendChild(kart);
        }
        if (veri.guncelleme) { const n = document.createElement("small"); n.textContent = "Son yayın: " + String(veri.guncelleme); kutu.appendChild(n); }
    } catch (hata) {
        kutu.textContent = "Teslimat listesi alınamadı (" + hata.message + "). Bağlantıyı kontrol edip Yenile’ye dokunun.";
    }
}
eleman("teslim-yenile").addEventListener("click", teslimatlariYukle);

// Ürün üret (Issue #9): bulut üretim zinciri. Talep cihaz zarfıyla şifrelenir; ilerleme GitHub adımlarından,
// sonuç ajans-urunler/durum/<kod>.json'dan (kişisel veri içermez) okunur.
const URETIM_DURUM = "https://emre5528.github.io/ajans-urunler/durum/";
const ASAMA_AD = {plan: "Plan", arastirma: "Araştırma (Gemini)", iskele: "İskele", fotograf: "Lisanslı fotoğraflar", uretim: "Tasarım ve kod (Claude)",
    kalite: "Kalite kapısı", gorsel_inceleme: "Görsel inceleme", teknik_inceleme: "Teknik inceleme", senaryo: "Uçtan uca test",
    testler: "Python testleri", imza: "CI imzası", yayin: "Yayın", dogrulama: "Canlı doğrulama"};
const DURUM_AD = {tamamlandi: "Tamamlandı", basarisiz: "Başarısız", calisiyor: "Çalışıyor", yayin_bekliyor: "Yayın bekliyor"};
const ASAMA_DURUM = {tamamlandi: "✓", basarisiz: "✗ başarısız", atlandi: "atlandı", onariliyor: "onarılıyor", calisiyor: "…"};
function uretimKayitlari() { try { return JSON.parse(localStorage.getItem("ajans-uretimler") || "[]"); } catch { return []; } }
function uretimKaydet(k) {
    const l = uretimKayitlari().filter(x => x.kod !== k.kod);
    l.unshift(k);
    localStorage.setItem("ajans-uretimler", JSON.stringify(l.slice(0, 12)));
}
async function uretimDurumuOku(kod) {
    if (!/^UR-[0-9a-f]{8}$/.test(kod)) return null;
    try {
        const y = await fetch(URETIM_DURUM + kod + ".json", {cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer"});
        return y.ok ? await y.json() : null;
    } catch { return null; }
}
function uretimCiz(kutu, d, adimlar) {
    kutu.replaceChildren();
    const baslik = document.createElement("article");
    const b = document.createElement("strong");
    b.textContent = d ? (d.urun?.ad ? String(d.urun.ad) + " · " : "") + (DURUM_AD[d.durum] || String(d.durum)) : "Bulutta çalışıyor";
    baslik.append(b);
    if (d?.hata) { const h = document.createElement("p"); h.textContent = "Durduğu yer: " + String(d.hata); baslik.append(h); }
    if (d?.url && String(d.url).startsWith(TESLIM_TABAN)) {
        const a = document.createElement("a");
        a.href = d.url; a.target = "_blank"; a.rel = "noopener noreferrer"; a.className = "dugme";
        a.textContent = d.durum === "tamamlandi" ? "Ürünü aç ↗" : "Yayın adresi ↗";
        a.dataset.testid = "uretim-baglanti";
        baslik.append(a);
    }
    const tur = document.createElement("small");
    tur.textContent = d?.tur ? String(d.tur) : "DEMO · kurgusal ürün · statik prototip";
    baslik.append(tur);
    kutu.append(baslik);
    const liste = document.createElement("ol");
    if (d?.asamalar?.length) {
        for (const a of d.asamalar) {
            const li = document.createElement("li");
            li.textContent = (ASAMA_AD[a.ad] || String(a.ad)) + " — " + (ASAMA_DURUM[a.durum] || String(a.durum)) + (a.not ? " · " + String(a.not) : "");
            liste.append(li);
        }
    } else if (adimlar?.length) {
        for (const s of adimlar) {
            const li = document.createElement("li");
            li.textContent = String(s.name) + " — " + String(s.conclusion || s.status);
            liste.append(li);
        }
    }
    kutu.append(liste);
}
async function uretimIzle(kayit, belirtec) {
    const kutu = eleman("uretim-durum");
    for (let i = 0; i < 480; i++) {   // en fazla ~2 saat (15 sn aralık)
        let adimlar = null, is = null;
        if (belirtec && kayit.calistirma) {
            try {
                is = await (await github("/runs/" + kayit.calistirma, belirtec)).json();
                const isler = await (await github("/runs/" + kayit.calistirma + "/jobs", belirtec)).json();
                adimlar = (isler.jobs || []).flatMap(j => (j.steps || []).filter(s => !/^(Set up|Post |Complete|Run actions)/.test(s.name)));
            } catch { /* çevrimdışı olabilir; durum dosyasıyla devam */ }
        }
        const d = await uretimDurumuOku(kayit.kod);
        uretimCiz(kutu, d, adimlar);
        if (d && ["tamamlandi", "basarisiz"].includes(d.durum) && (!is || is.status === "completed")) return d;
        if (is && is.status === "completed" && !d) {
            uretimCiz(kutu, {durum: "basarisiz", hata: "Çalıştırma durum kaydı yazmadan bitti (" + is.conclusion + ")"}, adimlar);
            return null;
        }
        await new Promise(t => setTimeout(t, 15000));
    }
}
async function uretimGecmisi() {
    const kutu = eleman("uretim-gecmis");
    kutu.replaceChildren();
    for (const k of uretimKayitlari()) {
        const b = document.createElement("button");
        b.type = "button"; b.className = "ikincil";
        b.textContent = k.kod + " · " + new Date(k.zaman).toLocaleString("tr-TR");
        b.addEventListener("click", () => uretimIzle(k, oturumBelirteci || null));
        kutu.append(b);
    }
    if (!kutu.children.length) kutu.textContent = "Henüz üretim yok.";
}
eleman("uretim-baslat").addEventListener("click", async () => {
    if (githubIslemSuruyor) return;
    const talep = eleman("uretim-talep").value.trim(), sektor = eleman("uretim-sektor").value;
    const kutu = eleman("uretim-durum");
    if (talep.length < 10) { kutu.textContent = "Talebi en az 10 karakterle yazın."; return; }
    githubKilit(true);
    eleman("uretim-baslat").disabled = true;
    try {
        const belirtec = githubBelirteci();
        const kod = "UR-" + Array.from(crypto.getRandomValues(new Uint8Array(4)), x => x.toString(16).padStart(2, "0")).join("");
        const paket = await istekPaketi({kip: "urun-uret", talep, sektor, kod}, belirtec, null);
        const cevap = await github("/workflows/uretim.yml/dispatches", belirtec, {ref: "main", inputs: {paket}});
        const numara = String((await cevap.json().catch(() => ({}))).workflow_run_id || "");
        const kayit = {kod, calistirma: calistirmaKodu.test(numara) ? numara : null, zaman: Date.now()};
        uretimKaydet(kayit);
        uretimGecmisi();
        kutu.textContent = "Görev " + kod + " buluta gönderildi. Sayfayı kapatabilirsiniz; Ürün üret ekranından tekrar izleyebilirsiniz.";
        eleman("uretim-talep").value = "";
        githubKilit(false);
        await uretimIzle(kayit, belirtec);
    } catch (hata) {
        kutu.textContent = hata.message || "Üretim başlatılamadı.";
    } finally {
        githubKilit(false);
        eleman("uretim-baslat").disabled = false;
    }
});
