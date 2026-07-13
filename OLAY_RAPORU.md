# Olay Raporu — 15 Haziran 2026

Bu rapor, sunucu gunluk loglarinin analizi sonucunda tespit edilen olaylari ozetler.

---

## 1. Basarili SSH Saldirisi ve Veri Sizintisi Riski

**Onem:** Kritik

Gece saat 02:10–03:01 arasinda `10.99.7.44` adresinden dis aga ait bir kaynak, en az 320 kez farkli kullanici adlariyla (root, admin, oracle, svc_backup vb.) SSH sifre denemesi yapti. Saldiri saat 02:57'de `svc_backup` hesabiyla basarili oldu. Dakikalar sonra saldirgan, `/etc` ve `/home` dizinlerini sikistirarak gecici bir dosyaya kopyaladi — bu tipik bir veri toplama (exfiltration) adimidir.

**Kanıt:**
```
2026-06-15T02:57:12 auth-server sshd[7741]: INFO Accepted password for svc_backup from 10.99.7.44 port 51873
2026-06-15T03:01:44 auth-server sshd[7741]: INFO session opened for user svc_backup; command='tar czf /tmp/.x.tgz /etc /home'
```

**Oneri:** `svc_backup` sifresini derhal sifirlayin, `10.99.7.44` IP'sini engelleyin, tum SSH anahtarlarini ve yedek hesaplarini gozden gecirin. Basarili giris sonrasi oturumlari ve `/tmp/.x.tgz` dosyasini inceleyin.

---

## 2. Fatura Servisi Bellek Tukenmesi (Crash Loop)

**Onem:** Yuksek

`InvoiceService[312]` servisi gun boyunca `java.lang.OutOfMemoryError: Java heap space` hatasini 12 kez verdi. Hatalar yaklasik 40 dakikada bir tekrar etti — bu bir crash loop (cokme dongusu) desenidir. Servis bellek limitine ulasip cokuyor ve muhtemelen otomatik yeniden baslatiliyor.

**Kanıt:**
```
2026-06-15T11:00:03 app-server InvoiceService[312]: ERROR java.lang.OutOfMemoryError: Java heap space
2026-06-15T11:40:03 app-server InvoiceService[312]: ERROR java.lang.OutOfMemoryError: Java heap space
2026-06-15T12:20:03 app-server InvoiceService[312]: ERROR java.lang.OutOfMemoryError: Java heap space
```

**Oneri:** JVM heap boyutunu artirin veya bellek sizintisi (memory leak) icin kod incelemesi yapin. Fatura isleme yukunu izleyin; gerekirse horizontal scaling veya batch boyutunu kucultun.

---

## 3. Disk Doluluk Trendi

**Onem:** Orta

Uygulama sunucusunda `/var` dizini gun icinde %78'den %99'ye yukseldi. Her 2 saatte yaklasik 3 puan artis goruldu — duzenli ve hizlanan bir doluluk trendi. Gece saat 22:00'de %99 seviyesine ulasildi; disk dolmasi hizmet kesintisine yol acabilir.

**Kanıt:**
```
2026-06-15T08:00:00 app-server diskmon: WARN /var usage at 78%
2026-06-15T16:00:00 app-server diskmon: WARN /var usage at 90%
2026-06-15T22:00:00 app-server diskmon: WARN /var usage at 99%
```

**Oneri:** Log rotasyonu ve eski dosya temizligi yapin. Disk kullanimini izleyen alarm esiklerini %85'e cekin.

---

## 4. Imkansiz Seyahat (VPN Hesap Ele Gecirme Suphesi)

**Onem:** Yuksek

`ayse.k` kullanicisi saat 14:02 de Istanbul (TR) konumundan, 8 dakika sonra Sao Paulo (BR) konumundan VPN'e baglandi. Bu sure fiziksel olarak mumkun degil; hesap paylasimi veya hesap ele gecirme suphesi vardir.

**Kanıt:**
```
2026-06-15T14:02:10 vpn-gw openvpn[88]: INFO user ayse.k connected from 88.241.12.7 (Istanbul, TR)
2026-06-15T14:09:51 vpn-gw openvpn[88]: INFO user ayse.k connected from 189.14.77.203 (Sao Paulo, BR)
```

**Oneri:** `ayse.k` hesabinin sifresini sifirlayin, MFA zorunlu kilin, aktif VPN oturumlarini sonlandirin ve kullaniciyi bilgilendirin.
