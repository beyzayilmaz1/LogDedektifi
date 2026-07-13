# Log Dedektifi — Challenge 2

KONSALT Staj Programi 2026: sunucu loglarini analiz ederek guvenlik ve operasyonel olaylari tespit eden Python araci.

## Gereksinimler

- Python 3.10+
- Opsiyonel (grafik icin): `matplotlib`

```bash
pip install matplotlib
```

## Proje Yapisi

```
LogDedektifi-main/
├── log_analiz.py              # Ana analiz scripti
├── OLAY_RAPORU.md             # Yonetim olay raporu
├── bulgular.csv               # Olay ozet tablosu
├── supheli_ip_hareketleri.txt # Supheli IP'nin tum log satirlari
├── saatlik_olaylar.png        # Bonus: saatlik brute force grafigi
└── loglar/
    └── sunucu_gunlugu.log     # Analiz edilen log dosyasi
```

## Kullanim

Temel calistirma (varsayilan log dosyasi ile):

```bash
python log_analiz.py
```

CSV ozeti ve grafik ile birlikte:

```bash
python log_analiz.py --csv-yaz --grafik
```

Farkli log dosyasi ve esik degerleri:

```bash
python log_analiz.py --dosya loglar/sunucu_gunlugu.log --seyahat-esigi 60 --csv-yaz --grafik
```

### Komut satiri argumanlari

| Arguman | Aciklama | Varsayilan |
|---------|----------|------------|
| `--dosya` | Analiz edilecek log dosyasi | `loglar/sunucu_gunlugu.log` |
| `--rapor` | Olusturulacak olay raporu | `OLAY_RAPORU.md` |
| `--csv` | CSV cikti dosyasi | `bulgular.csv` |
| `--csv-yaz` | CSV ozetini kaydet | kapali |
| `--seyahat-esigi` | Imkansiz seyahat esigi (dakika) | 60 |
| `--hareket-dosyasi` | Supheli IP hareket listesi | `supheli_ip_hareketleri.txt` |
| `--grafik` | Saatlik brute force grafigi | kapali (`saatlik_olaylar.png`) |

## Tespit Edilen Olaylar

1. **SSH brute force ve basarili giris** (Kritik) — `10.99.7.44`
2. **InvoiceService bellek tukenmesi** (Yuksek) — crash loop
3. **Disk doluluk artisi** (Orta) — `/var` %78 → %99
4. **Imkansiz VPN seyahati** (Yuksek) — `ayse.k` TR → BR

Detaylar icin `OLAY_RAPORU.md` dosyasina bakin.
