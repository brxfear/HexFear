# HexFear

**Yerel çalışan, AI destekli tersine mühendislik analiz aracı.**
İçine bir dosya sürükle → kendi API anahtarınla seçtiğin yapay zeka modelini bağla → amacı seç → araç, dosyadan çıkardığı gerçek statik verilerle analiz yapıp bir rapor üretsin.

CTF, crackme ve **yetkili** güvenlik analizi (kendi yazılımın / sahip olduğun hedef / izinli sızma testi) için tasarlandı.

> ⚠️ **Durum:** erken geliştirme (v0.1.0). Şu an statik analiz çekirdeği + arayüz çalışıyor. AI ajan katmanı bir sonraki aşamada.

---

## Ne yapar

- **Dosya sürükle-bırak:** PE (exe/dll), ELF, Mach-O, APK/ZIP, ham ikili.
- **Statik çıkarım:** dosya türü, hash (MD5/SHA-1/SHA-256), Shannon entropisi (paketleme tespiti), string'ler (ASCII + UTF-16, offset'li, ilgi etiketli), PE başlıkları + section'lar + import tablosu, ELF başlıkları + section'lar + bağımlı kütüphaneler.
- **(Yakında) AI ajan:** çıkarılan veriyle flag / crackme anahtarı bulma ve açık denetimi.

## Sorumlu kullanım — kapsam

Bu araç **savunma ve eğitim** amaçlıdır. Yalnızca şunlar için kullanılır:

- CTF flag'lerini çözme
- Kendi çözdüğün **crackme / challenge** anahtarını bulma
- **Sahip olduğun veya analiz izni olduğun** yazılımda açığın yerini ve türünü raporlama

**Araç şunları yapmaz:** ticari/üçüncü taraf yazılım lisansı kırma, veritabanına sızma, veri çekme, bir uygulamadan özel/kişisel bilgi çıkarma. Açık denetiminde bulunan gizli değerler rapora yazılmaz; yalnızca konumu belirtilir ve açık **kullanılmaz**.

Hedefi analiz etme hakkına sahip olduğundan emin ol. Sorumluluk kullanıcıya aittir.

## Çalıştırma

```bash
npm install
npm start
```

Geliştirme (DevTools açık):

```bash
npm run dev
```

## Gizlilik

Dosyalar **bu makinede** analiz edilir, hiçbir sunucuya gönderilmez. AI katmanı eklendiğinde, modele yalnızca senin onayladığın veri parçaları (string'ler, başlıklar, seçtiğin bölgeler) senin API anahtarınla gönderilir. API anahtarları cihazda şifreli saklanır ve asla depoya yazılmaz.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
