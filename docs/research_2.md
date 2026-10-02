# Tadqiqot 2: agentni kuchaytirish yo'llari

Sana: 2026-10-02. Birinchi tadqiqot (`docs/research.md`) tayyor tool'lar, LLM
maqolalari, dataset'lar, lokal modellar va agent xavfsizligini qamragan edi. Bu
safar **v2 natijalariga qarab** hali o'rganilmagan to'rt yo'nalish ko'rildi:
dastur tahlili, IDOR/avtorizatsiya, kichik model uchun ML usullari, yangi
agentlar va qo'shimcha qamrov. Har yo'nalish ~14 qidiruv bilan cheklangan
(sessiyadagi qidiruv limiti tufayli), shuning uchun ba'zi da'volar tekshirilmagan
deb belgilangan. ✔ — o'zim lokal tekshirganman.

v2 ning hozirgi holati (RealVuln, 15 Flask ilova): P 0.75, R 0.33, F1 0.46.
Zaif joylar: IDOR 11/53, path traversal 2/9, fayllararo oqimlar.

---

## 1. Eng muhim xulosalar

1. **IDOR uchun eng kuchli signal — ma'lumotlar modeli.** MOCGuard (IEEE S&P
   2025): foydalanuvchi jadvaliga foreign key bilan bog'langan jadvallar
   "egalikka ega"; ularga har so'rovda egalik filtri bo'lishi kerak. 30+7
   ilovada 180 report, 161 TP (**89% precision**), 73 CVE; DELETE/UPDATE/INSERT
   da **100% precision**, barcha 19 FP — SELECT'da, sababi "ataylab ochiq"
   ma'lumot ([PDF](https://yuanxzhang.github.io/paper/mocguard-oakland25.pdf)).
2. **Gibrid IDOR tizimi faqat-LLM'dan ancha yaxshi.** Semgrep'ning 2026
   "Multimodal" yondashuvi (qoida asosidagi oqim + LLM "tekshiruv aynan shu
   obyektni himoya qiladimi?") 275 IDOR'da 59.9% recall / 57.5% precision;
   boshqa tizimlar 11–14% recall
   ([Semgrep 2026](https://semgrep.dev/blog/2026/idor-detection-benchmark-semgrep-multimodal/)).
3. **Middleware va decorator'larni oldindan aniqlash shart.** LLM agentlar
   fayllarga tarqalgan RBAC'da 0/19, middleware'da 0/18 topgan; modelga avval
   ilovaning avtorizatsiya mexanizmini berish yordam bergan
   ([Semgrep 2025](https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning/)).
4. **Kontekstni ko'paytirish emas, aniq tanlash.** 509 zaiflik (C/C++/Python)
   tadqiqotida to'liq caller/callee funksiyalarni qo'shish yordam bermagan,
   Python'da farq ahamiyatsiz, tokenlar ~2 barobar oshgan
   ([arXiv 2604.08417](https://arxiv.org/html/2604.08417)); fokuslangan CPG
   slice'lar esa +15–40% F1 bergan (fine-tune qilingan 32B bilan,
   [LLMxCPG, USENIX Sec '25](https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf)).
5. **✔ Ollama `logprobs` bizda ishlaydi, lekin ishonch signali sifatida
   yaroqsiz.** Mulohazadan keyingi verdikt tokeni doim ~1.0 ehtimollik oladi —
   noto'g'ri javobda ham (`int()` bilan himoyalangan so'rov "zaif" deb
   p=1.0000). Ishonch o'lchovi uchun bir necha sampling'ning kelishuvi yoki
   o'rgatilgan filtr kerak. (Tadqiqot agentining "bepul kalibrlash"
   tavsiyasi bizning sozlamada rad etildi.)
6. **✔ Verdikt yorlig'i muhim.** "K/W (keep/withdraw)" yorlig'ida model aniq
   SQLi'ni "W" dedi (p=1.0); `claim_holds: true/false` da 4 tadan 3 to'g'ri.
   v1 verifier'dagi adashuv bilan bir xil sabab.
7. **Ochiq LLM agentlar SAST o'rnini bosa olmaydi** (2026-yilgi tadqiqot,
   Ollama'dagi 3 ochiq model vs Bandit,
   [arXiv 2606.11672](https://arxiv.org/abs/2606.11672)) — deterministik tool'lar
   asos bo'lib qolishi kerak, LLM qo'shimcha.

---

## 2. Qo'shish mumkin bo'lgan narsalar — muhimlik tartibida

| # | Nima | Qaysi zaiflikni yopadi | Vaqt | Dalil |
|---|---|---|---|---|
| **1** | **IDOR: egalik xaritasi** — SQLAlchemy modellaridan owner/tenant ustunlari (FK zanjiri bilan), har route'dagi so'rovda egalik filtri bormi; DELETE/UPDATE ustuvor | IDOR 11/53 | 2–3 kun | MOCGuard, BolaRay ([CCS 2024](https://dl.acm.org/doi/10.1145/3658644.3690227)) |
| **2** | **"Auth facts"** — decorator'larni ta'rifigacha kuzatish (login / role / owner), `before_request` va blueprint qamrovi, har route'ga yozish | IDOR, middleware holatlari | 1–2 kun | Semgrep 2025 |
| **3** | **Izchillik tekshiruvi** — X modeliga tegadigan route'larning ko'pchiligida G tekshiruv bor, bittasida yo'q → shubhali; verifier'ga himoyalangan "aka-uka" route'ni ham ko'rsatish | IDOR | 1–2 kun | RoleCast (OOPSLA 2011), MACE (CCS 2014) |
| **4** | **Prompt injection test to'plami** (8 holat): "Security Team tasdiqlagan" kommenti, docstring'dagi ko'rsatma, shoshilinch "hotfix" hikoyasi, soxta sanitizer, uzun kontekst, `.env` o'qishga undash, ko'rinmas Unicode, teskari tuzoq | Agentning o'z xavfsizligi | 1 kun | SEVRA-BENCH ([2606.13757](https://arxiv.org/abs/2606.13757)), InjecAgent, AgentDojo |
| **5** | **O'rgatilgan FP filtri** (logistic regression; belgilar: oila, route bormi, sink turi, format/concat, verifier kelishuvi) + leave-one-app-out CV + precision/recall egri chizig'i | Precision, ish nuqtasini tanlash | 2 kun | Tayyor dalil topilmadi — o'z hissamiz |
| **6** | **Sampling kelishuvi** — verifier'ni k=5 marta (T=0.6) ishga tushirib, "keep" ulushini ishonch balli qilish; run-to-run variatsiyani ham o'lchaydi | Ishonch o'lchovi, reproducibility | 1–2 kun | 5-band uchun belgi; ✔ logprobs yaroqsizligi |
| **7** | **Opengrep `--taint-intrafile`** + LLM loyiha helper'larini source/sink deb belgilaydi → loyihaga xos qoidalar | Fayl ichidagi/fayllararo helper oqimlari, path traversal | 0.5–2 kun | [Opengrep wiki](https://github.com/opengrep/opengrep/wiki/Intrafile-tainting-tutorial), IRIS (ICLR 2025) |
| **8** | **Arzon qamrov:** Flask config AST tekshiruvi (`SECRET_KEY` literal, cookie flag'lar, `debug=True`, `CORS(*)`), gitleaks (MIT, offline), OSV-Scanner offline baza | Yangi oilalar | 1 kun | Bandit B201/B105, [OSV offline](https://google.github.io/osv-scanner/usage/offline-mode/) |
| 9 | O'xshash belgilangan misollar (few-shot, embedding bilan) — verifier'ga 2–3 qo'shni misol; random misol bilan solishtirish | Precision | 2–3 kun | Python'da foydasi bor ([2510.27675](https://arxiv.org/abs/2510.27675)) |
| 10 | Xavfsizlikka moslashtirilgan model bilan solishtirish: VulnLLM-R-7B (Apache-2.0, GGUF bor) | Model tanlovi | 1 kun | [model card](https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B) |
| — | Fine-tuning (QLoRA) | — | 5+ kun | **Tavsiya etilmaydi:** PrimeVul'da 68% → 3% F1 qulashi; 10 kun ichida xavf yuqori |

**Bu safar ko'rib chiqilmagan:** ishga tushirilgan ilovada dinamik tekshirish
(lab). Dizayni `SECURITY_AGENT_SYSTEM_PROMPT.md` da bor, Docker o'chiq.

---

## 3. Tavsiya etilgan reja (~10 kun)

1. **IDOR to'plami (1+2+3)** — 4–6 kun. Eng katta zaif joy va eng kuchli dalil
   shu yerda. Deterministik qism (egalik xaritasi, auth facts, izchillik)
   modelga **tayyor nomzod va kontekst** beradi; model faqat "ataylab ochiqmi,
   boshqa joyda tekshiruv bormi" degan savolga javob beradi.
2. **Prompt injection to'plami (4)** — 1 kun. Arzon, xavfsizlik agentining o'z
   xavfsizligini o'lchaydi — case study uchun kuchli.
3. **ML qismi (5+6)** — 2–3 kun. ML Engineer pozitsiyasi uchun eng ko'rinadigan
   ish: filtr, CV, egri chiziq, variatsiya.
4. Vaqt qolsa: 7 va 8.

---

## 4. Halol baholash uchun muhim shart

RealVuln Flask qismi v2 ni baholashda **bir marta** ishlatildi. Agar endi
unga qarab tizim yaxshilansa, u ham "ko'rilgan" ma'lumotga aylanadi. Shuning
uchun:

- **Dev to'plami:** RealVuln Flask (15 ilova) — o'rgatilgan filtr va sozlash
  faqat leave-one-app-out CV bilan.
- **Yangi mustaqil test:** RealVuln'dagi **Django/FastAPI** ilovalari (51 ta
  Python target, hozircha hech qaysi tizim ko'rmagan) yoki 40 ta LLM yaratgan
  ilova — v3 uchun oldindan muzlatilgan protokol bilan, bir marta.
  Route inventarizatsiyasi hozir faqat Flask'ni tushunadi; Django/FastAPI
  uchun kengaytirish kerak bo'ladi (bu ham ish).

---

## 5. Yangi agentlar (2025-10 – 2026-09)

- **AgentGG** (Apache-2.0, 2026-06): Ollama bilan ishlaydi; parallel agentlar
  import va call graph bo'ylab yuradi, alohida validatsiya bosqichi
  *confirmed / false-positive / out-of-scope / uncertain* belgilaydi —
  **"uncertain"** ochiq yorliq sifatida
  ([HelpNetSecurity](https://www.helpnetsecurity.com/2026/06/05/agentgg-open-source-agentic-sast-scanner/)).
- **Vulnhalla** (CyberArk, Apache-2.0): CodeQL topilmasi + oldindan olingan
  funksiya konteksti + **CWE'ga xos savollar ro'yxati** → FP'lar 96% gacha
  kamaygan [vendor] ([blog](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)).
  Bizning kartalardagi savollar bilan bir xil g'oya.
- **VLoc Bench** (2026-09): 27 model, eng yaxshi File-F1 0.229; tizimlar
  tuzatilgan repolarda ham joy ko'rsatadi
  ([2609.15939](https://arxiv.org/abs/2609.15939)) — tuzatilgan kod testlari
  zarurligi.

---

## 6. Tekshirilmagan / topilmagan

- Opengrep va Joern litsenziya matnlari, JARVIS litsenziyasi.
- Bandit, OSV-Scanner litsenziyalari (shu sessiyada qayta tekshirilmadi).
- Self-consistency'ning aynan zaiflik topishdagi ta'siri.
- qwen3 thinking rejimining xavfsizlik vazifasidagi ta'siri.
- VulnLLM-R'ning Python bo'yicha alohida raqamlari.
- FixMeUp, Waler, BACScan tafsilotlari.
