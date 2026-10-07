# secagent va GitHub'dagi o'xshash 17 ta loyiha: solishtiruv

Sana: 2026-10-07. Bu hujjat `secagent` (shu repodagi agent, v5) ni GitHub'dagi
17 ta ochiq loyiha bilan birma-bir solishtiradi: har biri qanday ishlaydi,
nimaga asoslangan, menikidan nimasi bilan farq qiladi va undan qaysi g'oyani
olish mumkin.

**Manba va ishonchlilik.** Har bir loyihaning README, hujjat va (kerak
joyda) manba fayllari o'qildi. Sahifalar avtomatik o'qish vositasi orqali
olingan, shuning uchun raqam yoki iqtibosga qaror bog'liq bo'lsa, manbani
o'zingiz ochib tekshiring. Tasdiqlab bo'lmagan narsalar "tasdiqlanmagan" deb
yozilgan va 7-bo'limda yig'ilgan. Yulduzlar soni 2026-10-07 holatiga.
Loyihalarning birortasi ishga tushirib sinalmagan; bu hujjat ularning o'zi
yozgan tavsifiga tayanadi.

---

## 1. Qisqa xulosa

1. **Menikiga chinakam o'xshash loyiha uchta:** Vulnhuntr, OpenAnt va
   claude-code-security-review. Uchalasi ham manba kodni o'qib zaiflik
   qidiradi. Qolganlari boshqa ish qiladi: ishlab turgan ilovaga hujum qiladi
   (pentest agentlari), yoki agent emas (ko'nikma to'plami, benchmark,
   qoidaga asoslangan skaner).
2. **Eng katta farq: model va o'lchov.** Deyarli hamma loyiha katta bulut
   modellariga (Claude, GPT) tayanadi va kichik mahalliy modellar yomon
   ishlashini o'zi yozadi (Strix: 30B dan kichik modellar tool chaqiruvini
   buzadi; Vulnhuntr: ochiq modellar javob tuzilishini ushlay olmagan). Meniki
   8B modelda ishlaydi. Shuning uchun menda boshqaruv kodda, modelda emas.
3. **Hech biri precision/recall e'lon qilmagan.** Pentest agentlari XBOW
   benchmarkidagi "nechta bayroq olindi" foizini beradi (Strix 96%,
   PentestGPT 86.5%, Cyber-AutoAgent 85%), OpenAnt "tasdiqlangan topilmalar"
   sonini, Vulnhuntr topilgan CVE'larni. Soxta signallar ulushini qotirilgan
   mustaqil to'plamda o'lchagan loyiha topilmadi. Bu menikining kuchli tomoni.
4. **Ular kuchli bo'lgan joy: tasdiqlash.** Pentest agentlari topilmani
   haqiqiy ekspluatatsiya bilan isbotlaydi ("ekspluatatsiya yo'q, hisobot
   yo'q"). Meniki kodni ishga tushirmaydi, shuning uchun bu darajadagi isbot
   yo'q.
5. **Olishga arziydigan eng foydali 5 ta g'oya** (to'liq ro'yxat 5-bo'limda):
   - yo'ldan (route) yetib borish mumkin bo'lgan kodnigina tekshirish
     (OpenAnt);
   - model so'ragan funksiyani nomi bo'yicha topib berish (Vulnhuntr);
   - verifier'ni "cheklangan hujumchi" sifatida qo'yish, zarar boshqa
     odamga yetishi shart (OpenAnt). Bu IDOR uchun aniq mezon;
   - beshta javobli hukm: zaif / chetlab o'tsa bo'ladi / noaniq / himoyalangan
     / xavfsiz (OpenAnt);
   - tuzatilgan CVE'lardan yangi test to'plami yasash: zaif commit'da topishi,
     tuzatilgan commit'da jim turishi kerak (mythos-agent, CyberGym). Bu
     "ko'rilmagan Python ma'lumoti qolmadi" muammosini hal qilishi mumkin.
6. **Yangi tayyor test ma'lumoti topilmadi.** CyberGym faqat C/C++ xotira
   xatolari; boshqa loyihalar dataset bermaydi.

---

## 2. Mening agentim (secagent v5) qanday ishlaydi

Solishtirish uchun asos. Batafsil: `README.md`, `docs/experiments.md`.

| Xususiyat | secagent v5 |
|---|---|
| Vazifa | Python veb-ilova manba kodini o'qib, zaiflik topish |
| Kirish | Mahalliy papka (faqat o'qish) |
| Model | qwen3:8b, Ollama, 8 GB GPU; hech narsa tashqariga chiqmaydi |
| Zaiflik turlari | SQL injection, path traversal, IDOR / autentifikatsiya yo'qligi |
| Kodni ishga tushiradimi | Yo'q. Shell yo'q, tarmoq yo'q (faqat localhost model) |
| Baholash | 4 ta oldindan qotirilgan mustaqil to'plam, precision / recall / F1 va ishonch oralig'i bilan |

**Ish tartibi:**

1. **Deterministik tahlil (modelsiz).**
   - `authz.py`: qaysi jadval foydalanuvchiga tegishli, qaysi route egani
     tekshiradi, qaysi biri qo'shnilari talab qilgan autentifikatsiyani
     tashlab ketgan. Yordamchi funksiyalar nomidan emas, tanasidan tasniflanadi.
   - `sinks.py`: AST orqali xavfli amallarni topadi (matndan yasalgan SQL,
     so'rovdan kelgan Mongo filtri, hisoblangan yo'l bilan fayl amali) va
     qiymat qayerdan kelganini funksiya ichida kuzatadi.
2. **Model sweep.** Controller har bir faylning har bir oynasini modelga
   AST'dan olingan route xaritasi bilan ko'rsatadi; model nomzodlarni yozadi.
3. **Verifier.** Har bir da'vo alohida chaqiruvda tekshiriladi. Da'voni rad
   etish uchun model ko'rsatilgan koddagi aniq nazorat satrini ko'rsatishi
   shart. Statik dalil aniq bo'lgan sink topilmalari verifier'siz qabul
   qilinadi.
4. **Dalil qoidasi.** Topilma faqat haqiqatan o'qilgan satrga bog'lansa qabul
   qilinadi; har bir tool chaqiruvi `trace.jsonl` ga yoziladi.
5. **Prompt-injection himoyasi.** Izoh va docstring'lar modelga
   ko'rsatilmaydi, yashirin Unicode olib tashlanadi, repo matni "ishonchsiz
   ma'lumot" bloklariga o'raladi.

**Mustaqil sinov natijalari (har biri o'sha paytdagi eng yangi versiya uchun):**

| To'plam | Agent | Agent F1 | Single-shot LLM F1 |
|---|---|---|---|
| Flask, 15 ilova | v2 | 0.46 | 0.41 |
| FastAPI, 21 ilova | v3 | 0.24 | 0.14 |
| Django, 23 ilova | v4 | 0.10 | 0.18 |
| Boshqa freymvorklar, 5 ilova | v5 | 0.46 | 0.21 |

**Ma'lum zaif joylari:** IDOR aniqligi notanish kodda 0.1 atrofida; path
traversal yangi to'plamda 13 tadan 2 ta; Python 2 kodini o'qiy olmaydi;
ekspluatatsiya bilan tasdiqlash yo'q.

---

## 3. Umumiy jadval

| # | Loyiha | Turi | Yulduz | Nimani tahlil qiladi | Mahalliy model | Hujum qiladimi | E'lon qilingan o'lchov |
|---|---|---|---|---|---|---|---|
| – | **secagent v5** | kod ko'rib chiquvchi | – | Python manba kodi | ha, 8B | yo'q | precision/recall, 4 mustaqil to'plam |
| 1 | Vulnhuntr | kod ko'rib chiquvchi | 2.8 ming | Python manba kodi | tajriba holida | yo'q | CVE ro'yxati, benchmark yo'q |
| 2 | claude-code-security-review | kod ko'rib chiquvchi | 6.3 ming | PR diff va repo | yo'q | yo'q | yo'q |
| 3 | OpenAnt | kod ko'rib chiquvchi | 0.8 ming | manba kodi | ha (tool'li model kerak) | konteynerda sinaydi | 8 loyiha, tasdiqlangan topilmalar soni |
| 4 | Semgrep | qoidali skaner | 16.9 ming | manba kodi | model kerak emas | yo'q | faqat sotuvchi raqamlari |
| 5 | numasec | pentest/AppSec konsoli | 0.8 ming | ishlab turgan nishon | ha | ha | yo'q |
| 6 | Strix | pentest agenti | 67 ming | URL, repo yoki ikkalasi | ha, lekin tavsiya etilmaydi | ha | XBOW 96% (o'zi e'lon qilgan) |
| 7 | Shannon | pentest agenti | 48.6 ming | URL va manba kodi | ha, ogohlantirish bilan | ha | hozirgi README'da yo'q |
| 8 | PentAGI | pentest platformasi | 25.3 ming | nishon tavsifi | ha, lekin og'ir | ha | yo'q |
| 9 | PentestGPT | pentest/CTF agenti | 15.8 ming | IP yoki URL | ha (eski rejim) | ha | XBOW 86.5% (tarixiy) |
| 10 | CAI | agent freymvorki, arxivlangan | 9.8 ming | operator tanlaydi | ha | ha | CTF natijalari (o'zi e'lon qilgan) |
| 11 | Anthropic-Cybersecurity-Skills | ko'nikma to'plami | 33.9 ming | – | – | – | yo'q |
| 12 | CyberGym | benchmark | 0.9 ming | C/C++ loyihalar | – | PoC ishga tushiradi | 1 507 ta vazifa |
| 13 | Cyber-AutoAgent | pentest agenti, arxivlangan | 0.55 ming | nishon | ha (30B) | ha | XBOW 85% (o'zi e'lon qilgan) |
| 14 | cyber-harness | pentest va audit harness | 0.3 ming | nishon yoki repo | tasdiqlanmagan | ha (audit rejimi statik) | yo'q |
| 15 | ai-cyber-agent | veb skaner | 34 | URL | faqat distilgpt2 | ha | yo'q |
| 16 | CyberStrike | pentest harness | 3.0 ming | nishon | ha | ha | yo'q |
| 17 | mythos-agent | SAST + LLM | 44 | manba kodi | ha | tasdiqlanmagan | CVE Replay 2/5 |

---

## 4. Loyihalar birma-bir

Har birida: nima, qanday ishlaydi, nimaga asoslangan, menikidan farqi, nimani
olish mumkin.

### A guruh: manba kodni o'qib zaiflik topadiganlar

#### 4.1 Vulnhuntr (`protectai/vulnhuntr`) — menikiga eng yaqin

- **Nima:** Python kod bazasida masofadan ekspluatatsiya qilinadigan, ko'p
  qadamli zaifliklarni LLM bilan topadi. AGPL-3.0. 2025-yil fevraldan beri
  deyarli yangilanmagan.
- **Qanday ishlaydi:**
  1. 40 ga yaqin regex bilan tarmoq kirish nuqtalari bor fayllarni tanlaydi
     (Flask, FastAPI, Django route'lari).
  2. README'ni LLM'ga xulosa qildirib, tizim promptiga qo'shadi.
  3. Butun faylni LLM'ga yuboradi; javob tuzilgan (Pydantic) shaklda keladi.
  4. Har bir topilgan zaiflik turi uchun alohida prompt bilan 7 martagacha
     aylanadi.
  5. Har aylanishda model o'ziga kerakli funksiya yoki klassni nomi bilan
     so'raydi; Jedi kutubxonasi uni loyihadan topib promptga qo'shadi.
  6. Model boshqa kontekst so'ramasa yoki bir xil narsani qayta so'rasa,
     to'xtaydi.
- **Nimaga asoslangan:** LLM'ning iterativ kontekst so'rovi va Jedi orqali
  deterministik belgi qidirish. Call graph, taint tahlili, RAG yo'q.
- **Model:** Claude (tavsiya), GPT, Ollama tajriba holida. README: ochiq
  modellar javob tuzilishini to'g'ri ushlay olmagan.
- **Soxta signalni kamaytirish:** 0–10 ishonch bali; PoC masofaviy
  foydalanuvchi kirishidan boshlanmasa, bal 6 dan oshmasligi kerak. Alohida
  verifier yo'q.
- **O'lchov:** benchmark yo'q. 8 ta repoda topilmalar, 6 ta CVE raqami
  (masalan, CVE-2024-10100, CVE-2024-10044).
- **Menikidan farqi:**
  - U butun faylni yuboradi va katta modelga tayanadi; meniki oynalarga bo'lib
    8B modelga ko'rsatadi.
  - Unda fayllararo kontekst bor (model so'raydi, Jedi topadi); menda
    yordamchi funksiyalar faqat avtorizatsiya uchun va oldindan hisoblab
    beriladi.
  - Unda verifier yo'q, menda bor.
  - U 7 turni qidiradi (LFI, AFO, RCE, XSS, SQLi, SSRF, IDOR), meniki 3 turni.
  - Unda precision/recall yo'q, menda bor.
- **Olish mumkin:**
  1. "Nomi bo'yicha kontekst so'rash" aylanishi, takroriy so'rovda to'xtash
     sharti bilan. Bu menda yo'q va fayllararo holatlarga yordam beradi.
  2. Faqat birinchi o'tishda belgilangan tur uchun ishga tushadigan,
     turga xos ikkinchi prompt.
  3. Tuzilma shartiga bog'langan ishonch chegarasi (so'rovdan kelmagan qiymat
     yuqori bal ololmaydi). Menda shunga o'xshash narsa sink skanerida bor.

#### 4.2 claude-code-security-review (`anthropics/claude-code-security-review`)

- **Nima:** pull request o'zgarishlarini Claude bilan xavfsizlik nuqtai
  nazaridan ko'rib chiqadigan GitHub Action va `/security-review` buyrug'i.
  MIT.
- **Qanday ishlaydi:**
  1. PR ma'lumoti, fayllar ro'yxati va diff'dan prompt tuziladi.
  2. Claude Code CLI repo papkasida ishga tushadi, ya'ni model diff'dan
     tashqari fayllarni ham o'zi ochib ko'ra oladi.
  3. Prompt uch bosqichni belgilaydi: repo kontekstini o'rganish, mavjud
     xavfsiz naqshlar bilan taqqoslash, ma'lumot oqimini kuzatib baholash.
  4. JSON topilmalar qaytadi (fayl, satr, jiddiylik, tavsif, ekspluatatsiya
     ssenariysi, ishonch).
  5. Filtr: avval regex bilan qat'iy istisnolar, keyin har bir qolgan topilma
     uchun alohida Claude chaqiruvi.
  6. Qolganlari PR'ga satr izohi sifatida yoziladi.
- **Nimaga asoslangan:** agentli LLM qidiruvi. AST, CodeQL, Semgrep, call
  graph yo'q.
- **Model:** faqat Claude. Mahalliy model qo'llab-quvvatlanmaydi.
- **Soxta signalni kamaytirish:** prompt 80% dan yuqori ishonchni talab
  qiladi; qat'iy istisnolar ro'yxati (DoS, rate limiting, open redirect va
  boshqalar); "pretsedentlar" ro'yxati; har topilmaga alohida filtr.
- **O'lchov:** yo'q. `evals/` papkasi berilgan PR'da ishga tushirish uchun
  vosita, raqam e'lon qilinmagan.
- **Xavfsizlik:** README ochiq yozadi: prompt injection'ga qarshi
  mustahkamlanmagan, faqat ishonchli PR'larda ishlatilsin.
- **Menikidan farqi:**
  - U o'zgarishni (diff) ko'radi, meniki butun kod bazasini.
  - U modelga erkin qidirish beradi; menda controller nimani o'qishni o'zi
    belgilaydi (8B model erkin qidiruvda yomon ishlagan: 45 qidiruv, 1 o'qish).
  - Menda prompt-injection himoyasi bor va o'lchangan; unda yo'q.
- **Olish mumkin:**
  1. Versiyalangan qat'iy istisnolar va pretsedentlar ro'yxati (masalan, "UUID
     taxmin qilib bo'lmaydi", "muhit o'zgaruvchilari ishonchli"), verifier'ga
     beriladi va LLM'dan oldin regex filtr sifatida ishlaydi.
  2. Avval loyihaning o'z xavfsizlik odatlarini ajratib olish (sanitizer'lar,
     auth dekoratorlari), keyin ulardan chetga chiqishni baholash. IDOR uchun
     foydali.
  3. Har topilmada majburiy "ekspluatatsiya ssenariysi" maydoni.
  4. PR rejimi: faqat o'zgargan fayllarni tekshirish.

#### 4.3 OpenAnt (`knostic/OpenAnt`) — g'oyalari eng foydali

- **Nima:** LLM asosidagi zaiflik qidiruvchi: "1-bosqich topadi, 2-bosqich
  hujum qiladi, omon qolgani haqiqiy". Apache 2.0. Juda faol.
- **Qanday ishlaydi:**
  1. Kodni funksiya darajasidagi birliklarga ajratadi (Python va Go uchun
     AST, boshqa tillar uchun tree-sitter); har birlikka bog'liqliklarini
     3 daraja chuqurlikkacha qo'shadi.
  2. Fayllararo call graph quradi va kirish nuqtalaridan yetib borish
     mumkin bo'lmagan birliklarni tashlab yuboradi (OpenSSL'da 15 232
     funksiyadan 390 ta qolgan, 97% qisqarish).
  3. Tool chaqiradigan LLM chaqiruvchilarni qidirib, har birlikning
     tashqaridan ochiqligini tasniflaydi.
  4. Har birlik uchun hukm: zaif / chetlab o'tsa bo'ladi / noaniq /
     himoyalangan / xavfsiz.
  5. Raqib tekshiruvi: model cheklangan masofaviy hujumchi rolini o'ynaydi,
     bir necha usulni sinashi shart, zarar hujumchidan boshqa odamga yetishi
     kerak.
  6. Ixtiyoriy dinamik test: LLM Dockerfile va test skript yozadi, cheklangan
     konteynerda ishga tushadi.
- **Nimaga asoslangan:** AST va call graph bo'yicha yetib borish tahlili,
  ustiga ikki bosqichli LLM.
- **Model:** har bosqichga alohida sozlanadi; Ollama orqali to'liq mahalliy
  ishlaydi, lekin tool chaqira oladigan model kerak. Kichik modellar yaxshi
  ishlashi haqida da'vo yo'q.
- **O'lchov (arXiv:2606.19149, 8 loyiha):** 64 132 funksiya, 2 281 tasi yetib
  boriladigan, 376 tasi belgilangan, 190 tasi tekshiruvdan o'tgan, 144 tasi
  dinamik tasdiqlangan. Raqib bosqichi 1-bosqich belgilarining 49.5% ini olib
  tashlagan. Ground truth'ga nisbatan precision/recall yo'q.
- **Menikidan farqi:**
  - Unda yetib borish filtri bor; menda yo'q (men hamma oynani ko'rsataman,
    80 ta oyna chegarasi bilan).
  - Uning verifier'i "hujumchi" rolida; meniki "nazorat satrini top" rolida.
  - U dinamik sinaydi (konteynerda); meniki hech narsani ishga tushirmaydi.
  - U ko'p tilli; meniki faqat Python.
  - Uning topilmalari ichida IDOR/avtorizatsiya eng ko'p (29 ta), ya'ni
    menda eng zaif bo'lgan turda u natija ko'rsatgan.
- **Olish mumkin:**
  1. **Route'dan yetib borish filtri** AST call graph ustida: model faqat
     kirish nuqtasidan yetib boriladigan kodni ko'radi. Django'da oyna
     budjeti muammosini (T13) to'g'ridan-to'g'ri hal qiladi.
  2. **Besh javobli hukm**, ayniqsa "himoyalangan" va "noaniq". Hozir menda
     verifier faqat "ushlab qoladi" yoki "rad etadi".
  3. **Verifier cheklangan hujumchi sifatida:** hisob ma'lumoti yo'q, serverga
     kirish yo'q, zarar boshqa odamga yetishi shart. Oxirgi shart IDOR uchun
     aniq mezon.

#### 4.4 Semgrep (`semgrep/semgrep`) — LLM'siz baseline

- **Nima:** qoidaga asoslangan tez statik tahlil. LGPL-2.1. Model yo'q.
- **Qanday ishlaydi:** qoidalar kodga o'xshash naqsh sifatida yoziladi va
  tahlil qilingan dastur ustida moslanadi. Taint rejimida manba, sink,
  sanitizer va tarqatuvchilar belgilanadi. Bepul versiyada tahlil bitta
  funksiya yoki fayl ichida; fayllararo oqim pullik versiyada.
- **Menikidan farqi:** deterministik va tez, lekin qoida yozilmagan narsani
  ko'rmaydi. Avtorizatsiya mantig'ini (IDOR) qoida kodlamasa tushunmaydi.
  Mening to'rtta sinovimda loyiha qoidalari bilan 0–9 ta topilma bergan.
- **Olish mumkin:**
  1. Manba / sink / sanitizer uchligi deklarativ formatda: mening
     `sinks.py` dagi ro'yxatlar hozir Python kodida qotirilgan, ularni YAML'ga
     chiqarish kengaytirishni osonlashtiradi.
  2. Tekshirilgan soxta signalni kodda belgilash (`nosemgrep` kabi izoh).

#### 4.5 numasec (`FrancescoStabile/numasec`)

- **Nima:** terminaldagi "AI xavfsizlik agenti" konsoli. AGPL-3.0. Asosan
  ishlab turgan nishonga qarshi ishlaydi (HTTP, brauzer, skanerlar); manba
  kodni o'qish uning bir rejimi, xolos.
- **Qanday ishlaydi:** operator rejim tanlaydi (xavfsizlik, pentest, AppSec,
  OSINT, CTF), nishon va doirani belgilaydi; agent fayl, HTTP, brauzer va
  skaner tool'lari ustida aylanadi. Hamma narsa faqat qo'shiladigan
  jurnalga yoziladi.
- **Soxta signalni kamaytirish:** topilma hayot sikli: nomzod → kuzatilgan →
  tekshirilgan → hisobotga yaroqli (yoki rad etilgan). "Hisobotga yaroqli"
  bo'lish uchun dalil va qayta ijro kerak. Shiori: "model ishonchli gapirgani
  uchun hisobot oshirib yubormasligi kerak".
- **Menikidan farqi:** u hujum qiladi va odam boshqaradi; meniki avtomatik va
  faqat o'qiydi. Unda AST tahlili yo'q. O'lchov e'lon qilinmagan.
- **Olish mumkin:**
  1. Topilma holatlari mashinasi va bosqichlar bo'yicha yo'qotish jadvali
     (nechta seed, nechta model da'vosi, nechta verifier qabul qildi).
  2. Kerakli dalil yetishmasa, jimgina qabul qilish o'rniga tuzilgan
     "istisno" yozuvi. Menda verifier'siz qabul qilingan sink topilmalari
     uchun aynan shu kerak.

### B guruh: pentest agentlari (ishlab turgan ilovaga hujum qiladi)

Bular menikidan tubdan boshqa ish qiladi: nishonni ishga tushirib, haqiqiy
so'rov va ekspluatatsiya yuboradi. Ularning asosiy afzalligi (isbotlangan
topilma) nishonni ishga tushirmasdan olinmaydi.

#### 4.6 Strix (`usestrix/strix`) — eng mashhuri

- **Nima:** "haqiqiy xakerdek ishlaydigan" avtonom pentest agentlari.
  Apache-2.0, Python.
- **Qanday ishlaydi:**
  - Ko'p agentli: razvedka, ekspluatatsiya va keyingi bosqichlar uchun
    ixtisoslashgan agentlar parallel ishlaydi va topilmalarni bo'lishadi.
  - Tool'lar: brauzer (Playwright), HTTP proksi (Caido), terminal, Python,
    va sandbox ichida nuclei, ffuf, nmap, sqlmap, semgrep.
  - "Ko'nikmalar" (skills): har zaiflik turi va freymvork uchun Markdown
    fayl; har yangi agentga eng mos 5 tagachasi qo'shiladi.
  - Rejimlar: tez, standart, chuqur. Chuqur rejimda avval semgrep va AST
    qidiruvi, keyin eng yaxshi nomzodlarni dinamik tekshirish.
- **Model:** bulut modellari tavsiya etiladi. Mahalliy mumkin, lekin hujjatda
  ogohlantirish: 70B dan kichik modellar qiynaladi, 30B dan kichiklari tool
  chaqiruvini tez-tez buzadi.
- **Tasdiqlash:** har topilmada ishlaydigan PoC va qayta ijro qadamlari.
- **O'lchov:** XBOW benchmarki, 104 topshiriqdan 100 tasi (96%), qora quti
  rejimi, jami 337 dollar atrofida. O'zi e'lon qilgan; ishlatilgan model
  tasdiqlanmagan.
- **Menikidan farqi:** u ilovani ishga tushirib hujum qiladi va Docker talab
  qiladi; meniki faqat o'qiydi. U katta modelga muhtoj. U 18 ga yaqin turni
  qamraydi, meniki 3 turni. U "bayroq olindi"ni o'lchaydi, meniki
  precision/recall'ni.
- **Olish mumkin:**
  1. Tur va freymvork bo'yicha ko'nikma fayllari, har chaqiruvga faqat
     keraklisi yuklanadi. Menda bilim kartalari bor; ularni freymvork
     bo'yicha ham ajratish (Django, FastAPI) foydali bo'lardi.
  2. Tez / standart / chuqur rejimlar.
  3. "Avval statik saralash, keyin tekshirish" tartibi menda allaqachon bor.

#### 4.7 Shannon (`KeygraphHQ/shannon`)

- **Nima:** veb-ilova va API uchun avtonom pentester: manba kodni tahlil
  qiladi, hujum yo'llarini topadi va haqiqiy ekspluatatsiya bilan isbotlaydi.
  AGPL-3.0, TypeScript.
- **Qanday ishlaydi:**
  - Qat'iy pipeline (Temporal boshqaradi, to'xtab qolsa davom ettiriladi):
    manba tahlili → razvedka → 5 ta parallel tahlil agenti (injection, XSS,
    autentifikatsiya, avtorizatsiya, SSRF) → 5 ta ekspluatatsiya agenti →
    hisobot.
  - Agentlar bir-biriga tuzilgan fayl orqali uzatadi: har tahlil agenti
    "ekspluatatsiya navbati" JSON'ini topshiradi.
  - Nomzodlar tekshiruvdan oldin birlashtiriladi va takrorlar olib
    tashlanadi.
- **Model:** sukut bo'yicha Claude Sonnet; mahalliy mumkin, lekin "ko'rsatmaga
  ishonchli amal qilmaydigan model zaifroq natija beradi" degan ogohlantirish
  bilan.
- **Tasdiqlash:** faqat qayta ijro qilinadigan PoC bilan tasdiqlangan
  zaifliklar hisobotga kiradi.
- **O'lchov:** hozirgi README'da XBOW bali yo'q. Uchinchi tomon maqolalari
  eski README'da 96.15% bo'lganini yozadi; repodagi natijalar papkasi hozir
  ochilmaydi.
- **Xavfsizlik:** "ishonchsiz yoki dushman kod bazasini tekshirmang" (manba
  orqali prompt injection); ishlab chiqarish tizimida ishlatmaslik.
- **Menikidan farqi:** u ham kodni o'qiydi, lekin keyin hujum qiladi va
  holatni o'zgartiradi (foydalanuvchi yaratadi, forma yuboradi). Bir ishga
  tushirish 1–1.5 soat va API to'lovi. Meniki ishonchsiz kodni o'qishga
  mo'ljallangan himoyaga ega; u buni ochiq taqiqlaydi.
- **Olish mumkin:**
  1. Tahlil va tekshirish bosqichlari orasida har tur uchun tiplangan nomzod
     navbati (menda bor, lekin xotirada; faylga yozish qayta ishga
     tushirishni osonlashtiradi).
  2. Nomzodlarni tekshiruvdan oldin birlashtirish va takrorlarni olish
     (menda oddiy varianti bor).
  3. SARIF formatida chiqarish va ishonch chegarasi bo'yicha filtr. SARIF
     GitHub va IDE'larda ochiladi.

#### 4.8 PentAGI (`vxcontrol/pentagi`)

- **Nima:** o'z serverda ishlaydigan pentest platformasi; agentlar oddiy
  tildagi topshiriqdan reja tuzib bajaradi. MIT, Go va React.
- **Qanday ishlaydi:**
  - Ierarxik ko'p agentli: boshqaruvchi, tadqiqotchi, dasturchi, ijrochi,
    maslahatchi, reflektor va boshqalar.
  - Ish bo'linishi: oqim → vazifa → kichik vazifa → harakat.
  - 20 dan ortiq vosita (nmap, metasploit, sqlmap), brauzer, qidiruv.
  - Xotira: PostgreSQL va pgvector, ixtiyoriy bilim grafi.
  - Nazorat: bir xil tool chaqiruvi 5 marta takrorlansa maslahatchi
    chaqiriladi; agentga 100 ta (cheklanganlariga 20 ta) chaqiruv chegarasi;
    model 3 marta tool chaqira olmasa reflektor aralashadi.
- **Model:** 10 dan ortiq provayder. Mahalliy mumkin, lekin og'ir (namuna
  sozlama: 27B model, 4 ta RTX 5090). README: 32B dan kichik modellar uchun
  nazorat va rejalash "zarur".
- **Tasdiqlash:** mustaqil tekshirish bosqichi hujjatlanmagan.
- **O'lchov:** e'lon qilinmagan.
- **Menikidan farqi:** katta infratuzilma (ma'lumotlar bazasi, veb-interfeys,
  kuzatuv) va hujum; meniki bitta buyruq va faqat o'qish.
- **Olish mumkin:**
  1. Takror va tsikl detektorlari va qat'iy chaqiruv budjeti. Menda budjet
     bor (`max_model_calls`), takror detektori yo'q.
  2. Model buzuq javob berganda "reflektor" bilan qayta urinish. Hozir menda
     bunday javob shunchaki `invalid_replies` ga sanaladi va oyna yo'qoladi.
  3. Mahalliy modelni ishlatishdan oldin sinab ko'radigan kichik test
     to'plami.

#### 4.9 PentestGPT (`GreyDGL/PentestGPT`)

- **Nima:** LLM boshqaradigan pentest va CTF agenti; USENIX Security 2024
  maqolasidan chiqqan. MIT, Python.
- **Qanday ishlaydi (uch avlod birga yashaydi):**
  - **Eski:** uchta LLM sessiyasi (mulohaza, generatsiya, tahlil) "pentest
    vazifalar daraxti"ni yuritadi; buyruqlarni odam bajaradi.
  - **v1.0:** Claude Code yoki Codex CLI orqali avtonom pipeline.
  - **Yangi:** ikkita rol. Supervisor bitta vazifani tanlaydi, Executor uni
    bajarib tiplangan natija qaytaradi; har biri yangi sessiyada boshlanadi.
    Hujjatdan: "deterministik kod doirani tekshirish, dalil manbai, qayta
    urinish va holatga egalik qiladi"; "SQLite asosiy xotira, model
    transkripti emas".
- **O'lchov:** XBOW'da 104 dan 90 tasi (86.5%), README o'zi "tarixiy natija,
  hozirgi kafolat emas" deydi.
- **Menikidan farqi:** hujum qiladi; alohida verifier yo'q (ataylab). Lekin
  falsafasi menikiga eng yaqin: holat va qoidalar kodda, model faqat taklif
  qiladi.
- **Olish mumkin:**
  1. "Dalil kvitansiyasi": natija faqat yozib olingan tool natijasiga aynan
     mos kelsa qabul qilinadi. Menda "o'qilgan satrni ko'rsat" qoidasi bor,
     bu undan qat'iyroq varianti.
  2. Vazifalar daraxtini qamrov kuzatuvchisi sifatida ishlatish: har route
     yoki fayl tekshirildimi.
  3. Har qadamga yangi sessiya va cheklangan ish to'plami menda allaqachon
     shunday.

#### 4.10 CAI (`aliasrobotics/cai`) — arxivlangan

- **Nima:** xavfsizlik agentlari yasash freymvorki. 2026-yil 28-avgustda
  arxivlangan; ish tijoriy davomchiga (CSI) o'tgan. Litsenziyasi ikki qismli:
  bir qismi MIT, qolgani tadqiqot uchun.
- **Qanday ishlaydi:** ReAct agentlari; naqshlar (swarm, ierarxik, ketma-ket,
  parallel); agentlar bir-birini tool sifatida chaqira oladi; tool'lar hujum
  bosqichlari bo'yicha guruhlangan (razvedka, ekspluatatsiya, yon harakat).
- **O'lchov:** CTF natijalari va "30 dan ortiq CVE" (hammasi o'zi e'lon
  qilgan).
- **Menikidan farqi:** bu tayyor skaner emas, qurilish to'plami; hujumga
  mo'ljallangan; endi qo'llab-quvvatlanmaydi.
- **Olish mumkin:**
  1. Kirish va chiqish himoyalari: nishondan o'qilgan hamma narsa ishonchsiz
     ma'lumot. Menda bu bor.
  2. "Agent tool sifatida": verifier tiplangan natija qaytaradigan chaqiruv.
     Menda shunday.
  3. Kelajakda laboratoriya tekshiruvi yoqilsa, bajarishdan oldin odam
     tasdig'i nuqtasi.

### C guruh: qolganlari

#### 4.11 Anthropic-Cybersecurity-Skills (`mukul975/...`)

- **Nima:** AI agentlar uchun 818 ta kiberxavfsizlik ko'nikmasi to'plami.
  Anthropic'niki emas: README o'zi "mustaqil, hamjamiyat loyihasi" deydi.
  Apache-2.0.
- **Qanday ishlaydi:** har ko'nikma papka: `SKILL.md` (qisqa sarlavha va
  to'liq ish tartibi), yordamchi skriptlar. Agent avval faqat sarlavhalarni
  ko'radi (har biri 30 token atrofida), to'liq matnni (500–2 000 token) faqat
  kerak bo'lganda yuklaydi. O'zi hech narsa bajarmaydi.
- **Menikidan farqi:** bu agent emas, agentga beriladigan bilim. Asosan SOC,
  bulut, tahdid ovi; kod ko'rib chiqishga oid qismi kichik. IDOR yoki path
  traversal uchun aniq ko'nikma borligi tasdiqlanmagan.
- **Olish mumkin:**
  1. Ikki pog'onali karta formati (kichik indeks, to'liq karta talabga
     ko'ra). 8K kontekst uchun mos.
  2. Har kartada majburiy "Tekshirish" bo'limi, verifier'ga beriladi.

#### 4.12 CyberGym (`sunblaze-ucb/cybergym`) — benchmark

- **Nima:** zaiflikni qayta yaratish (PoC yozish) bo'yicha baholash to'plami.
  ICLR 2026 maqolasi (arXiv 2506.02548).
- **Tarkibi:** 188 ta loyihada 1 507 ta haqiqiy zaiflik. **Faqat C/C++ xotira
  xatolari** (buffer overflow, use-after-free va boshqalar). Python veb-ilova,
  SQL injection, path traversal yoki avtorizatsiya xatosi yo'q.
- **Qanday baholaydi:** agent PoC fayl topshiradi; u tuzatishdan oldingi
  versiyada qulashga olib kelishi va tuzatilgan versiyada olib kelmasligi
  kerak.
- **Raqamlar:** Claude Sonnet 4: 17.9%, GPT-5: 22.0%, 32B ochiq modellar:
  ko'pi bilan 2.0%.
- **Men uchun:** yangi test ma'lumoti manbai bo'la olmaydi (til va tur mos
  emas, hajmi 240 GB atrofida).
- **Olish mumkin (usul sifatida):**
  1. Juft baholash: topilma zaif versiyada chiqishi va tuzatilganida
     chiqmasligi kerak.
  2. Yordam darajalari: natijani "hech qanday ishorasiz" va "tavsif berilgan"
     holatlar uchun alohida ko'rsatish.
  3. Yorliqlar namunasini odam tekshirib, aniqligini yozish.

#### 4.13 Cyber-AutoAgent (`westonbrown/Cyber-AutoAgent`) — arxivlangan

- **Nima:** tajriba uchun avtonom pentest agenti. 2025-yil noyabrda
  arxivlangan (muallifning vaqti yo'qligi sababli). MIT.
- **Qanday ishlaydi:** bitta asosiy agent "o'yla, mulohaza qil, harakat qil"
  aylanishida; ishonch 70% dan past bo'lsa parallel kichik agentlar to'dasi;
  kerak bo'lsa ish paytida yangi tool yozadi; topilmalar xotiraga yoziladi va
  hisobot faqat shulardan tuziladi.
- **O'lchov:** README'da XBOW 85% da'vosi.
- **Menikidan farqi:** qora quti hujum, kod ko'rib chiqish emas; mahalliy
  ishlashi uchun 30B model kerak.
- **Olish mumkin:** ishonch darajasi keyingi qadamni o'zgartirishi (past
  ishonchli da'vo yana bitta oyna o'qishga olib keladi).

#### 4.14 cyber-harness (`chainreactors/cyber-harness`)

- **Nima:** pentest, red team va bug bounty uchun bitta bajariladigan fayl;
  manba va binar audit rejimi ham bor. AGPL-3.0, Go.
- **Qanday ishlaydi (audit rejimi):** model tool tanlaydi; manba uchun
  ripgrep, ast-grep, osv-scanner va sir skaneri. Natija papkasi:
  `findings.json`, `coverage.json`, jurnal, dalillar. Topilma holatlari:
  nomzod / tasdiqlangan / rad etilgan / noaniq; tekshirish usuli: statik /
  qayta ijro / urinilmagan.
- **Menikidan farqi:** ko'p maqsadli harness; mahalliy model ishlashi
  tasdiqlanmagan; o'lchov yo'q.
- **Olish mumkin:**
  1. Har topilmada `verification_method` maydoni va aniq "noaniq" holati.
  2. ast-grep naqshlari ikkinchi deterministik seed manbai sifatida (Python 2
     kabi `ast` o'qiy olmaydigan kod uchun ham ishlashi mumkin).
  3. `coverage.json` menda `final.json` ichida allaqachon bor.

#### 4.15 ai-cyber-agent (`capture0x/ai-cyber-agent`)

- **Nima:** nomiga qaramay LLM agenti emas: faol veb zaiflik skaneri. MIT,
  34 yulduz.
- **Qanday ishlaydi:** `distilgpt2` modeli payload generatsiya qiladi, ular
  WAF'ni chetlab o'tish uchun kodlanadi, URL parametrlariga yuboriladi va
  javob vaqti, hajmi, status kodidagi anomaliyaga qarab aniqlanadi.
- **Menikidan farqi:** manba kodni umuman o'qimaydi, jonli nishonga hujum
  qiladi; agent aylanishi, tool chaqiruvi, tekshirish bosqichi yo'q.
- **Olish mumkin:** deyarli hech narsa.

#### 4.16 CyberStrike (`CyberStrikeus/CyberStrike`)

- **Nima:** hujumga mo'ljallangan AI harness. AGPL-3.0, TypeScript,
  3.0 ming yulduz. (Qidiruvda chiqqan `nooperpudd/CyberStrike` 0 yulduzli
  fork; asosiy repo boshqa egada.)
- **Qanday ishlaydi:** 13 dan ortiq ixtisoslashgan agent (veb, mobil, bulut,
  ichki tarmoq); 8 ta proksi sinovchi (IDOR, avtorizatsiyani chetlab o'tish,
  injection va boshqalar); o'z brauzeri trafikni ushlab rollarni aniqlaydi.
- **Model:** 15 dan ortiq provayder; Ollama yoki LM Studio bilan to'liq
  oflayn ishlashi da'vo qilingan.
- **Tasdiqlash:** "uch darvozali protokol": oddiy so'rov, hujum so'rovi,
  javoblarni taqqoslash. Faqat o'lchanadigan va qayta takrorlanadigan farq
  bo'lsa hisobotga kiradi.
- **O'lchov:** e'lon qilinmagan.
- **Menikidan farqi:** dinamik hujum, kod ko'rib chiqish emas.
- **Olish mumkin:**
  1. Uch darvozali g'oyani statik tahlilga ko'chirish: IDOR da'vosi uchun
     ham himoyalangan qo'shni route, ham himoyasiz route dalil sifatida
     ko'rsatilishi shart. Menda qo'shni route'lar verifier'ga beriladi,
     lekin dalil sifatida majburiy emas.
  2. Rollar va endpoint'lar xaritasi umumiy kontekst sifatida (menda route
     xaritasi bor, rollar yo'q).

#### 4.17 mythos-agent (`mythos-agent/mythos-agent`)

- **Nima:** qoidali skanerlarni LLM pipeline bilan birlashtirgan kod ko'rib
  chiqish yordamchisi. MIT, TypeScript, 44 yulduz. Anthropic bilan aloqasi
  haqida README'da hech narsa yo'q.
- **"43 kategoriya" da'vosi haqida:** README'ning o'zi 15 tasi ulangan, 28
  tasi tajribaviy va "hech qanday kirish nuqtasidan chaqirilmaydi" deb
  yozadi. Amalda 15 ta.
- **Qanday ishlaydi:** deterministik qatlam (o'z qoidalari, Semgrep,
  Gitleaks, Trivy); `hunt` buyrug'i 4 ta LLM agentini ketma-ket ishlatadi
  (razvedka, gipoteza, tahlil, ekspluatatsiya); `variants` ma'lum CVE'ning
  ildiz naqshini ajratib, AST bo'yicha o'xshash kodni qidiradi.
- **O'lchov:** bitta raqam: "CVE Replay" 5 tadan 2 tasi.
- **Menikidan farqi:** g'oyasi yaqin (deterministik qatlam va LLM), lekin
  kichik va o'lchovi deyarli yo'q.
- **Olish mumkin:**
  1. **CVE Replay:** zaif commit'da topish, tuzatilgan commit'da jim turish.
     Tuzatilgan Python CVE yoki GHSA maslahatlaridan yangi test to'plami
     yasash yo'li.
  2. Variant qidiruvi: bitta tasdiqlangan topilmaning naqshi bo'yicha
     loyihadagi o'xshash joylarni topish.

---

## 5. Nimani olish mumkin: ustuvorlik bilan

Baho mening loyihamdagi o'lchangan zaifliklarga qarab berilgan. Mehnat
taxminiy.

### Birinchi navbatda (o'lchangan muammoni hal qiladi)

| # | G'oya | Qayerdan | Qaysi muammoni hal qiladi | Mehnat |
|---|---|---|---|---|
| 1 | Tuzatilgan CVE'lardan test to'plami (zaif va tuzatilgan commit jufti) | mythos-agent, CyberGym | Ko'rilmagan Python test ma'lumoti qolmadi; busiz hech bir yaxshilanishni isbotlab bo'lmaydi | 2–4 kun |
| 2 | Route'dan yetib borish filtri (AST call graph) | OpenAnt | Django'da oyna budjeti view'larga yetmagan (T13); keraksiz kodga sarflangan model chaqiruvlari | 2–3 kun |
| 3 | Verifier "cheklangan hujumchi": zarar boshqa odamga yetishi shart | OpenAnt | IDOR aniqligi 0.1 atrofida | 1 kun va dev sinovi |
| 4 | Model so'ragan funksiyani nomi bo'yicha topib berish | Vulnhuntr | Fayllararo holatlar; verifier hal qiluvchi kodni ko'rmaydi | 1–2 kun |
| 5 | Besh javobli hukm ("himoyalangan", "noaniq" bilan) | OpenAnt, cyber-harness | Verifier hozir ikki javobdan birini tanlashga majbur | 0.5–1 kun |

### Ikkinchi navbatda (sifat va qulaylik)

| # | G'oya | Qayerdan | Foydasi | Mehnat |
|---|---|---|---|---|
| 6 | Qat'iy istisnolar va pretsedentlar ro'yxati | claude-code-security-review | Takrorlanadigan soxta signallarni modelsiz olib tashlaydi | 0.5 kun |
| 7 | Loyihaning o'z xavfsizlik odatlarini avval ajratib olish | claude-code-security-review | IDOR: "bu loyihada himoya qanday ko'rinadi" | 1–2 kun |
| 8 | IDOR da'vosida himoyalangan va himoyasiz route juftligi majburiy dalil | CyberStrike | IDOR soxta signallari | 0.5 kun |
| 9 | Buzuq model javobida qayta urinish; takror detektori | PentAGI | Yo'qolgan oynalar | 0.5 kun |
| 10 | Freymvork bo'yicha ko'nikma kartalari, talabga ko'ra yuklash | Strix, Anthropic-Cybersecurity-Skills | Yangi freymvorkka moslashish | 1–2 kun |
| 11 | SARIF chiqishi, PR (diff) rejimi | Shannon, claude-code-security-review | GitHub va IDE'da ishlatish | 1 kun |
| 12 | Bosqichlar bo'yicha yo'qotish jadvali, "istisno" yozuvi | numasec | Hisobot shaffofligi | 0.5 kun |
| 13 | Manba / sink / sanitizer ro'yxatlarini YAML'ga chiqarish | Semgrep | Skanerni kengaytirish osonlashadi | 0.5 kun |
| 14 | ast-grep ikkinchi seed manbai | cyber-harness | Python 2 va `ast` o'qiy olmaydigan kod | 1 kun |
| 15 | Variant qidiruvi | mythos-agent | Bitta topilmadan o'xshashlarini topish | 1–2 kun |

**Muhim shart:** 2–5 va undan keyingi har qanday o'zgarish foyda berganini
bilish uchun avval 1-band kerak. Hozirgi to'rt to'plam "ko'rilgan" bo'lib
qolgan; ularda yaxshilangan raqam isbot emas.

### Menda allaqachon bor (boshqalar ham qiladigan narsalar)

- Avval statik saralash, keyin model (Strix chuqur rejimi).
- Har zaiflik turi uchun alohida mutaxassis qadam (Shannon, CyberStrike).
- Holat va qoidalar kodda, model faqat taklif qiladi (PentestGPT).
- Nishondan o'qilgan matn ishonchsiz ma'lumot (CAI); menda bu o'lchangan ham.
- Qamrov yozuvi va rad etilgan gipotezalar ko'rinib turishi (cyber-harness,
  numasec).
- LLM'siz baseline bilan taqqoslash (Semgrep).

---

## 6. Nimani olib bo'lmaydi va nega

| Narsa | Kimda | Nega olib bo'lmaydi |
|---|---|---|
| Ekspluatatsiya bilan tasdiqlash ("PoC yo'q, hisobot yo'q") | Strix, Shannon, CyberStrike | Nishonni ishga tushirish va unga so'rov yuborish kerak. Mening agentim ataylab hech narsani bajarmaydi |
| Konteynerda dinamik test | OpenAnt | LLM yozgan kodni bajarish kerak. Docker izolyatsiyasi bilan mumkin, lekin mening mashinamda hozir o'chirilgan |
| Erkin agentli qidiruv (model nimani o'qishni o'zi tanlaydi) | claude-code-security-review, Strix | 8B modelda sinalgan va ishlamagan (T07: 45 qidiruv, 1 o'qish) |
| Ko'p agentli parallel ish | PentAGI, Strix, CAI | 8 GB GPU'da bitta model ketma-ket ishlaydi; parallellik tezlik bermaydi |
| XBOW benchmarkida o'lchash | Strix, PentestGPT | U jonli nishonda bayroq olishni o'lchaydi, kod ko'rib chiqishni emas |

---

## 7. Tasdiqlanmagan va ehtiyot bo'lish kerak bo'lgan joylar

- **Hamma o'lchov raqamlari loyihalarning o'zi e'lon qilgan.** XBOW foizlari
  (Strix 96%, PentestGPT 86.5%, Cyber-AutoAgent 85%), CAI'ning CTF
  natijalari, Semgrep'ning "soxta signal 25% kam" da'vosi mustaqil
  tekshirilmagan.
- **Shannon'ning 96.15% natijasi** hozirgi repoda yo'q; faqat uchinchi tomon
  maqolalarida.
- **Strix qaysi model bilan 96% olgani** tasdiqlanmagan.
- **Strix va PentAGI'ning oxirgi reliz sanalari** o'qish vositasi noto'g'ri
  yil qaytargani uchun bu hujjatga kiritilmadi.
- **OpenAnt:** ground truth'ga nisbatan precision/recall yo'q; hujjatining
  o'zi bitta commit'ning ikki skaneri har xil natija berishi mumkinligini
  yozadi.
- **cyber-harness:** Ollama bilan ishlashi tasdiqlanmagan.
- **mythos-agent:** PoC'larni haqiqatan bajaradimi, tasdiqlanmagan.
- **Anthropic-Cybersecurity-Skills:** IDOR, path traversal yoki Python kod
  ko'rib chiqish uchun aniq ko'nikma borligi tasdiqlanmagan.
- **CyberGym dataset litsenziyasi** tasdiqlanmagan (kodi Apache-2.0).
- **Hech bir loyiha ishga tushirib sinalmagan.** "Qanday ishlaydi" bo'limlari
  ularning hujjati va manba fayllariga tayanadi.

---

## 8. Manbalar

Kod ko'rib chiquvchilar:
- Vulnhuntr: https://github.com/protectai/vulnhuntr
- claude-code-security-review: https://github.com/anthropics/claude-code-security-review
- OpenAnt: https://github.com/knostic/OpenAnt , maqola https://arxiv.org/abs/2606.19149
- Semgrep: https://github.com/semgrep/semgrep , https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview
- numasec: https://github.com/FrancescoStabile/numasec

Pentest agentlari:
- Strix: https://github.com/usestrix/strix , https://docs.strix.ai
- Shannon: https://github.com/KeygraphHQ/shannon
- PentAGI: https://github.com/vxcontrol/pentagi
- PentestGPT: https://github.com/GreyDGL/PentestGPT , maqola https://arxiv.org/abs/2308.06782
- CAI: https://github.com/aliasrobotics/cai

Qolganlari:
- Anthropic-Cybersecurity-Skills: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- CyberGym: https://github.com/sunblaze-ucb/cybergym , maqola https://arxiv.org/abs/2506.02548
- Cyber-AutoAgent: https://github.com/westonbrown/Cyber-AutoAgent
- cyber-harness: https://github.com/chainreactors/cyber-harness
- ai-cyber-agent: https://github.com/capture0x/ai-cyber-agent
- CyberStrike: https://github.com/CyberStrikeus/CyberStrike
- mythos-agent: https://github.com/mythos-agent/mythos-agent
