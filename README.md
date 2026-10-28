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

Testler ve Windows kurulum/portable exe:

```bash
npm test
npm run dist
```

## MCP sunucusu (API anahtarsız kullanım)

HexFear'ın analiz araçları bir MCP sunucusu olarak da sunulur. Böylece Claude Code, Claude Desktop, Gemini CLI, Cursor gibi istemciler dosyayı **kendi aboneliğinle** inceleyebilir; uygulamaya API anahtarı girmen gerekmez. Sunucu yerel ve salt-okunurdur.

Araçlar: `open_file`, `get_overview`, `list_strings`, `read_bytes`, `read_at_rva`, `search_bytes`, `get_sections`, `get_imports`, `get_exports`, `get_capabilities`, `get_indicators`, `disassemble`. Analiz modları (`flag`, `crackme_key`, `vuln_audit`, `general`) MCP prompt'u olarak gelir.

### Tek tıkla kurulum (önerilen)

HexFear'ı aç → üst çubukta **⚡ MCP** → kullandığın uygulamanın yanında **Kur**. Desteklenenler: Claude Code, Claude Desktop (Microsoft Store sürümü dahil), Cursor, Antigravity, Gemini CLI, Windsurf. Bilgisayarda bulunamayan uygulamalar soluk görünür.

- Ayar dosyasında yalnızca `mcpServers.hexfear` eklenir/güncellenir; diğer her şey korunur. İlk yazımdan önce dosyanın yedeği `.bak-hexfear` uzantısıyla alınır. Bozuk bir ayar dosyasına dokunulmaz.
- Kurulum (Setup) sürümünde HexFear.exe'nin kendisi sunucu olarak kaydedilir (`ELECTRON_RUN_AS_NODE=1`) — **Node.js gerekmez**.
- Portable exe her açılışta geçici klasöre açıldığı için sunucu dosyaları `%APPDATA%\hexfear\mcp-runtime` altına kopyalanır ve sistemdeki Node.js kullanılır; Node yoksa Setup sürümü önerilir.
- HexFear'ı güncelledikten ya da taşıdıktan sonra durum **◐ farklı ayar var** görünürse **Güncelle**'ye bas.
- Kurulumdan sonra ilgili uygulamayı yeniden başlat. Listede olmayan bir istemci için **JSON'u kopyala** ile yapılandırmayı al.

### Elle kurulum

Bu klasörde açılan Claude Code oturumları sunucuyu `.mcp.json` sayesinde otomatik bulur. Kaynak koddan, her yerden kullanmak için:

```bash
claude mcp add --scope user hexfear -- node "C:/yol/HexFear/src/mcp/server.js"
```

Diğer istemcilerde yapılandırma (`mcpServers`) aynıdır:

```json
{ "mcpServers": { "hexfear": { "command": "node", "args": ["C:/yol/HexFear/src/mcp/server.js"] } } }
```

Bir dosyayı baştan açık başlatmak için yolu argüman olarak ver (`node src/mcp/server.js hedef.exe`) ya da `HEXFEAR_FILE` ortam değişkenini kullan.

## Gizlilik

Dosyalar **bu makinede** analiz edilir, hiçbir sunucuya gönderilmez. AI katmanı eklendiğinde, modele yalnızca senin onayladığın veri parçaları (string'ler, başlıklar, seçtiğin bölgeler) senin API anahtarınla gönderilir. API anahtarları cihazda şifreli saklanır ve asla depoya yazılmaz.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
