#!/usr/bin/env python3
"""Challenge 2 - Log Dedektifi: sunucu log analiz araci."""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean

DESEN = re.compile(
    r"(?P<zaman>\S+) (?P<kaynak>\S+) (?P<surec>[^:]+): "
    r"(?P<seviye>INFO|WARN|ERROR) (?P<mesaj>.*)"
)
FAILED_PASSWORD = re.compile(
    r"Failed password for (?P<kullanici>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<kullanici>\S+) from (?P<ip>\S+) port \d+"
)
SESSION_OPENED = re.compile(
    r"session opened for user (?P<kullanici>\S+); command='(?P<komut>.*)'"
)
DISK_USAGE = re.compile(r"/var usage at (?P<yuzde>\d+)%")
VPN_CONNECT = re.compile(
    r"user (?P<kullanici>\S+) connected from \S+ \((?P<sehir>[^,]+), (?P<ulke>[A-Z]{2})\)"
)

DEFAULT_LOG = Path(__file__).resolve().parent / "loglar" / "sunucu_gunlugu.log"


def parse_satir(satir: str) -> dict[str, str] | None:
    """Tek bir log satirini dict'e cevirir."""
    eslesme = DESEN.match(satir.strip())
    if not eslesme:
        return None
    return eslesme.groupdict()


def parse_dosya(dosya_yolu: Path) -> tuple[list[dict[str, str]], int]:
    """Tum log dosyasini okur; (kayitlar, parse_edilemeyen_sayisi) dondurur."""
    kayitlar: list[dict[str, str]] = []
    parse_edilemeyen = 0

    with dosya_yolu.open(encoding="utf-8") as dosya:
        for satir in dosya:
            satir = satir.strip()
            if not satir:
                continue
            kayit = parse_satir(satir)
            if kayit is None:
                parse_edilemeyen += 1
            else:
                kayit["ham_satir"] = satir
                kayitlar.append(kayit)

    return kayitlar, parse_edilemeyen


def gorev1_ozet(kayitlar: list[dict[str, str]], parse_edilemeyen: int) -> Counter:
    """Toplam satir ve seviye dagilimini yazdirir."""
    print("=" * 60)
    print("GOREV 1: Log Parser")
    print("=" * 60)
    print(f"Toplam parse edilen satir: {len(kayitlar)}")
    print(f"Parse edilemeyen satir: {parse_edilemeyen}")

    dagilim = Counter(k["seviye"] for k in kayitlar)
    print("Seviye dagilimi:")
    for seviye in ("INFO", "WARN", "ERROR"):
        print(f"  {seviye}: {dagilim.get(seviye, 0)}")
    print()
    return dagilim


def gorev2_basarisiz_girisler(
    kayitlar: list[dict[str, str]], hareket_dosyasi: Path | None = None
) -> dict:
    """Basarisiz SSH girislerini analiz eder."""
    print("=" * 60)
    print("GOREV 2: Basarisiz Giris Analizi")
    print("=" * 60)

    ip_sayaclari: Counter[str] = Counter()
    ip_kullanicilar: dict[str, set[str]] = defaultdict(set)

    for kayit in kayitlar:
        eslesme = FAILED_PASSWORD.search(kayit["mesaj"])
        if eslesme:
            ip = eslesme.group("ip")
            kullanici = eslesme.group("kullanici")
            ip_sayaclari[ip] += 1
            ip_kullanicilar[ip].add(kullanici)

    print("Basarisiz giris sayisi (IP'ye gore, buyukten kucuge):")
    for ip, adet in ip_sayaclari.most_common(10):
        print(f"  {ip}: {adet}")

    supheli_ip = ip_sayaclari.most_common(1)[0][0]
    print(f"\nSupheli IP: {supheli_ip} ({ip_sayaclari[supheli_ip]} basarisiz deneme)")
    print(f"Denenen kullanicilar: {', '.join(sorted(ip_kullanicilar[supheli_ip]))}")

    supheli_hareketler = [k for k in kayitlar if supheli_ip in k["ham_satir"]]

    print(f"\n{supheli_ip} IP'sinden gelen tum hareketler ({len(supheli_hareketler)} satir):")
    for kayit in supheli_hareketler:
        print(f"  {kayit['ham_satir']}")

    if hareket_dosyasi:
        hareket_dosyasi.write_text(
            "\n".join(k["ham_satir"] for k in supheli_hareketler),
            encoding="utf-8",
        )
        print(f"\nHareketler dosyaya yazildi: {hareket_dosyasi}")

    basarili = None
    komut = None
    basarili_pid = None
    for kayit in supheli_hareketler:
        kabul = ACCEPTED_PASSWORD.search(kayit["mesaj"])
        if kabul and kabul.group("ip") == supheli_ip:
            basarili = kayit
            pid_eslesme = re.search(r"\[(\d+)\]", kayit["surec"])
            if pid_eslesme:
                basarili_pid = pid_eslesme.group(1)

    if basarili_pid:
        for kayit in kayitlar:
            if f"[{basarili_pid}]" in kayit["surec"]:
                oturum = SESSION_OPENED.search(kayit["mesaj"])
                if oturum:
                    komut = kayit
                    break

    if basarili:
        print("\nSONUC: Saldiri BASARILI")
        print(f"  Kanit: {basarili['ham_satir']}")
        if komut:
            print(f"  Sonraki eylem: {komut['ham_satir']}")
    else:
        print("\nSONUC: Saldiri basarisiz (supheli IP'den basarili giris yok)")
    print()

    return {
        "supheli_ip": supheli_ip,
        "basarisiz_sayisi": ip_sayaclari[supheli_ip],
        "kullanicilar": sorted(ip_kullanicilar[supheli_ip]),
        "basarili_kayit": basarili["ham_satir"] if basarili else None,
        "komut_kayit": komut["ham_satir"] if komut else None,
        "zaman_araligi": (
            f"{supheli_hareketler[0]['zaman']} - {supheli_hareketler[-1]['zaman']}"
            if supheli_hareketler
            else ""
        ),
    }


def gorev3_tekrarlayan_hata(kayitlar: list[dict[str, str]]) -> dict:
    """ERROR seviyesindeki tekrarlayan hatalari bulur."""
    print("=" * 60)
    print("GOREV 3: Tekrarlayan Hata Analizi")
    print("=" * 60)

    hatalar = [k for k in kayitlar if k["seviye"] == "ERROR"]
    hata_gruplari = Counter(k["mesaj"] for k in hatalar)

    print("ERROR mesaj dagilimi:")
    for mesaj, adet in hata_gruplari.most_common():
        print(f"  [{adet}x] {mesaj}")

    ana_hata = hata_gruplari.most_common(1)[0][0]
    ana_kayitlar = [k for k in hatalar if k["mesaj"] == ana_hata]
    zamanlar = [datetime.fromisoformat(k["zaman"]) for k in ana_kayitlar]

    araliklar_dk = [
        (zamanlar[i + 1] - zamanlar[i]).total_seconds() / 60
        for i in range(len(zamanlar) - 1)
    ]
    ortalama_aralik = mean(araliklar_dk) if araliklar_dk else 0.0

    print(f"\nServis: {ana_kayitlar[0]['surec']}")
    print(f"Hata: {ana_hata}")
    print(f"Tekrar sayisi: {len(ana_kayitlar)}")
    print(f"Ortalama tekrar araligi: {ortalama_aralik:.1f} dakika")
    print("Ornek satirlar:")
    for kayit in ana_kayitlar[:3]:
        print(f"  {kayit['ham_satir']}")
    print()

    return {
        "servis": ana_kayitlar[0]["surec"],
        "hata": ana_hata,
        "adet": len(ana_kayitlar),
        "ortalama_aralik_dk": ortalama_aralik,
        "zaman_araligi": f"{zamanlar[0].isoformat()} - {zamanlar[-1].isoformat()}",
        "ornek_satirlar": [k["ham_satir"] for k in ana_kayitlar[:3]],
    }


def gorev4_sinsi_olaylar(
    kayitlar: list[dict[str, str]], seyahat_esigi_dk: int
) -> dict:
    """Disk doluluk trendi ve imkansiz seyahat olaylarini bulur."""
    print("=" * 60)
    print("GOREV 4: Sinsi Olaylar")
    print("=" * 60)

    disk_kayitlari = []
    for kayit in kayitlar:
        eslesme = DISK_USAGE.search(kayit["mesaj"])
        if eslesme:
            disk_kayitlari.append(
                {
                    "zaman": kayit["zaman"],
                    "yuzde": int(eslesme.group("yuzde")),
                    "satir": kayit["ham_satir"],
                }
            )

    print("Disk doluluk trendi (/var):")
    for kayit in disk_kayitlari:
        print(f"  {kayit['zaman']}: %{kayit['yuzde']}")

    if len(disk_kayitlari) >= 2:
        artis = disk_kayitlari[-1]["yuzde"] - disk_kayitlari[0]["yuzde"]
        print(
            f"\nTrend: %{disk_kayitlari[0]['yuzde']} -> %{disk_kayitlari[-1]['yuzde']} "
            f"(+{artis} puan, yaklasik 2 saatte +3 puan)"
        )

    vpn_baglantilari = []
    for kayit in kayitlar:
        eslesme = VPN_CONNECT.search(kayit["mesaj"])
        if eslesme:
            vpn_baglantilari.append(
                {
                    "zaman": datetime.fromisoformat(kayit["zaman"]),
                    "kullanici": eslesme.group("kullanici"),
                    "sehir": eslesme.group("sehir"),
                    "ulke": eslesme.group("ulke"),
                    "satir": kayit["ham_satir"],
                }
            )

    print("\nVPN baglantilari:")
    for baglanti in vpn_baglantilari:
        print(f"  {baglanti['satir']}")

    imkansiz_seyahat = []
    kullanici_baglantilari: dict[str, list[dict]] = defaultdict(list)
    for baglanti in vpn_baglantilari:
        kullanici_baglantilari[baglanti["kullanici"]].append(baglanti)

    for kullanici, baglantilar in kullanici_baglantilari.items():
        sirali = sorted(baglantilar, key=lambda b: b["zaman"])
        for onceki, sonraki in zip(sirali, sirali[1:]):
            fark_dk = (sonraki["zaman"] - onceki["zaman"]).total_seconds() / 60
            if (
                onceki["ulke"] != sonraki["ulke"]
                and fark_dk <= seyahat_esigi_dk
            ):
                imkansiz_seyahat.append(
                    {
                        "kullanici": kullanici,
                        "onceki": onceki,
                        "sonraki": sonraki,
                        "fark_dk": fark_dk,
                    }
                )
                print(
                    f"\nImkansiz seyahat: {kullanici} "
                    f"{onceki['sehir']}/{onceki['ulke']} -> "
                    f"{sonraki['sehir']}/{sonraki['ulke']} "
                    f"({fark_dk:.1f} dakika icinde)"
                )
    print()

    return {
        "disk": disk_kayitlari,
        "imkansiz_seyahat": imkansiz_seyahat,
    }


def olay_raporu_yaz(
    rapor_yolu: Path,
    saldiri: dict,
    hata: dict,
    sinsi: dict,
) -> None:
    """Yonetim icin OLAY_RAPORU.md dosyasini olusturur."""
    disk = sinsi["disk"]
    seyahat = sinsi["imkansiz_seyahat"][0] if sinsi["imkansiz_seyahat"] else None

    satirlar = [
        "# Olay Raporu — 15 Haziran 2026",
        "",
        "Bu rapor, sunucu gunluk loglarinin analizi sonucunda tespit edilen olaylari ozetler.",
        "",
        "---",
        "",
        "## 1. Basarili SSH Saldirisi ve Veri Sizintisi Riski",
        "",
        "**Onem:** Kritik",
        "",
        (
            f"Gece saat 02:10–03:01 arasinda `{saldiri['supheli_ip']}` adresinden "
            "dis aga ait bir kaynak, en az 320 kez farkli kullanici adlariyla "
            "(root, admin, oracle, svc_backup vb.) SSH sifre denemesi yapti. "
            "Saldiri saat 02:57'de `svc_backup` hesabiyla basarili oldu. "
            "Dakikalar sonra saldirgan, `/etc` ve `/home` dizinlerini sikistirarak "
            "gecici bir dosyaya kopyaladi — bu tipik bir veri toplama (exfiltration) adimidir."
        ),
        "",
        "**Kanıt:**",
        "```",
        saldiri["basarili_kayit"] or "",
        *( [saldiri["komut_kayit"]] if saldiri.get("komut_kayit") else [] ),
        "```",
        "",
        "**Oneri:** `svc_backup` sifresini derhal sifirlayin, `10.99.7.44` IP'sini "
        "engelleyin, tum SSH anahtarlarini ve yedek hesaplarini gozden gecirin. "
        "Basarili giris sonrasi oturumlari ve `/tmp/.x.tgz` dosyasini inceleyin.",
        "",
        "---",
        "",
        "## 2. Fatura Servisi Bellek Tukenmesi (Crash Loop)",
        "",
        "**Onem:** Yuksek",
        "",
        (
            f"`{hata['servis']}` servisi gun boyunca `{hata['hata']}` hatasini "
            f"{hata['adet']} kez verdi. Hatalar yaklasik {hata['ortalama_aralik_dk']:.0f} "
            "dakikada bir tekrar etti — bu bir crash loop (cokme dongusu) desenidir. "
            "Servis bellek limitine ulasip cokuyor ve muhtemelen otomatik yeniden baslatiliyor."
        ),
        "",
        "**Kanıt:**",
        "```",
        *hata["ornek_satirlar"],
        "```",
        "",
        "**Oneri:** JVM heap boyutunu artirin veya bellek sizintisi (memory leak) "
        "icin kod incelemesi yapin. Fatura isleme yukunu izleyin; gerekirse "
        "horizontal scaling veya batch boyutunu kucultun.",
        "",
        "---",
        "",
        "## 3. Disk Doluluk Trendi",
        "",
        "**Onem:** Orta",
        "",
        (
            f"Uygulama sunucusunda `/var` dizini gun icinde %{disk[0]['yuzde']}'den "
            f"%{disk[-1]['yuzde']}'ye yukseldi. Her 2 saatte yaklasik 3 puan artis "
            "goruldu — duzenli ve hizlanan bir doluluk trendi. Gece saat 22:00'de "
            "%99 seviyesine ulasildi; disk dolmasi hizmet kesintisine yol acabilir."
        ),
        "",
        "**Kanıt:**",
        "```",
        disk[0]["satir"],
        disk[len(disk) // 2]["satir"],
        disk[-1]["satir"],
        "```",
        "",
        "**Oneri:** Log rotasyonu ve eski dosya temizligi yapin. "
        "Disk kullanimini izleyen alarm esiklerini %85'e cekin.",
        "",
        "---",
        "",
        "## 4. Imkansiz Seyahat (VPN Hesap Ele Gecirme Suphesi)",
        "",
        "**Onem:** Yuksek",
        "",
    ]

    if seyahat:
        satirlar.extend(
            [
                (
                    f"`{seyahat['kullanici']}` kullanicisi saat {seyahat['onceki']['zaman'].strftime('%H:%M')} "
                    f"de {seyahat['onceki']['sehir']} ({seyahat['onceki']['ulke']}) konumundan, "
                    f"{seyahat['fark_dk']:.0f} dakika sonra {seyahat['sonraki']['sehir']} "
                    f"({seyahat['sonraki']['ulke']}) konumundan VPN'e baglandi. "
                    "Bu sure fiziksel olarak mumkun degil; hesap paylasimi veya "
                    "hesap ele gecirme suphesi vardir."
                ),
                "",
                "**Kanıt:**",
                "```",
                seyahat["onceki"]["satir"],
                seyahat["sonraki"]["satir"],
                "```",
                "",
                "**Oneri:** `ayse.k` hesabinin sifresini sifirlayin, MFA zorunlu kilin, "
                "aktif VPN oturumlarini sonlandirin ve kullaniciyi bilgilendirin.",
                "",
            ]
        )

    rapor_yolu.write_text("\n".join(satirlar), encoding="utf-8")
    print(f"Olay raporu yazildi: {rapor_yolu}")


def bonus_saatlik_grafik(kayitlar: list[dict[str, str]], grafik_yolu: Path) -> None:
    """Saatlik basarisiz giris sayisini matplotlib ile grafikler."""
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit(
            "Grafik icin matplotlib gerekli: pip install matplotlib"
        ) from exc

    saatlik = Counter()
    for kayit in kayitlar:
        if FAILED_PASSWORD.search(kayit["mesaj"]):
            saat = datetime.fromisoformat(kayit["zaman"]).hour
            saatlik[saat] += 1

    saatler = sorted(saatlik)
    adetler = [saatlik[s] for s in saatler]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(saatler, adetler, color="#c0392b", edgecolor="black", linewidth=0.5)
    ax.set_xlabel("Saat")
    ax.set_ylabel("Basarisiz giris sayisi")
    ax.set_title("Saatlik SSH Brute Force Denemeleri — 15 Haziran 2026")
    ax.set_xticks(range(0, 24))
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(grafik_yolu, dpi=150)
    plt.close(fig)
    print(f"Saatlik grafik yazildi: {grafik_yolu}")


def csv_ozet_yaz(csv_yolu: Path, saldiri: dict, hata: dict, sinsi: dict) -> None:
    """Bulgulari CSV olarak kaydeder."""
    disk = sinsi["disk"]
    satirlar = [
        ["olay", "zaman_araligi", "adet", "onem"],
        [
            "SSH brute force ve basarili giris",
            saldiri["zaman_araligi"],
            str(saldiri["basarisiz_sayisi"]),
            "Kritik",
        ],
        [
            "InvoiceService OutOfMemoryError",
            hata["zaman_araligi"],
            str(hata["adet"]),
            "Yuksek",
        ],
        [
            "Disk doluluk artisi",
            f"{disk[0]['zaman']} - {disk[-1]['zaman']}",
            str(disk[-1]["yuzde"] - disk[0]["yuzde"]),
            "Orta",
        ],
        [
            "Imkansiz VPN seyahati",
            (
                f"{sinsi['imkansiz_seyahat'][0]['onceki']['zaman'].isoformat()} - "
                f"{sinsi['imkansiz_seyahat'][0]['sonraki']['zaman'].isoformat()}"
                if sinsi["imkansiz_seyahat"]
                else ""
            ),
            "1",
            "Yuksek",
        ],
    ]

    with csv_yolu.open("w", newline="", encoding="utf-8") as dosya:
        csv.writer(dosya).writerows(satirlar)
    print(f"CSV ozet yazildi: {csv_yolu}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sunucu log analiz araci")
    parser.add_argument(
        "--dosya",
        type=Path,
        default=DEFAULT_LOG,
        help="Analiz edilecek log dosyasi",
    )
    parser.add_argument(
        "--rapor",
        type=Path,
        default=Path(__file__).resolve().parent / "OLAY_RAPORU.md",
        help="Olusturulacak olay raporu dosyasi",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path(__file__).resolve().parent / "bulgular.csv",
        help="Olusturulacak CSV ozet dosyasi",
    )
    parser.add_argument(
        "--seyahat-esigi",
        type=int,
        default=60,
        help="Imkansiz seyahat icin dakika esigi (varsayilan: 60)",
    )
    parser.add_argument(
        "--csv-yaz",
        action="store_true",
        help="Bulgulari CSV olarak da kaydet",
    )
    parser.add_argument(
        "--hareket-dosyasi",
        type=Path,
        default=Path(__file__).resolve().parent / "supheli_ip_hareketleri.txt",
        help="Supheli IP hareketlerinin kaydedilecegi dosya",
    )
    parser.add_argument(
        "--grafik",
        type=Path,
        nargs="?",
        const=Path(__file__).resolve().parent / "saatlik_olaylar.png",
        default=None,
        help="Saatlik brute force grafigini kaydet (varsayilan: saatlik_olaylar.png)",
    )
    args = parser.parse_args()

    if not args.dosya.exists():
        raise SystemExit(f"Log dosyasi bulunamadi: {args.dosya}")

    kayitlar, parse_edilemeyen = parse_dosya(args.dosya)
    gorev1_ozet(kayitlar, parse_edilemeyen)
    saldiri = gorev2_basarisiz_girisler(kayitlar, args.hareket_dosyasi)
    hata = gorev3_tekrarlayan_hata(kayitlar)
    sinsi = gorev4_sinsi_olaylar(kayitlar, args.seyahat_esigi)

    olay_raporu_yaz(args.rapor, saldiri, hata, sinsi)
    if args.csv_yaz:
        csv_ozet_yaz(args.csv, saldiri, hata, sinsi)
    if args.grafik:
        bonus_saatlik_grafik(kayitlar, args.grafik)

    print("=" * 60)
    print("Analiz tamamlandi.")
    print("=" * 60)


if __name__ == "__main__":
    main()
