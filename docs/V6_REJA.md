# v6 reja: solishtiruvdan olingan g'oyalarni qo'shish

Sana: 2026-10-07. Asos: [`SOLISHTIRUV.md`](SOLISHTIRUV.md) ning 5-bo'limi.
Bu fayl ish tartibini belgilaydi; har qadam tugaganda pastdagi "Holat"
ustuni yangilanadi.

## Asosiy qoida

v5 dan keyin benchmarkda ko'rilmagan Python ma'lumoti qolmadi. Shuning uchun
tartib qat'iy:

1. **Avval yangi test to'plami**, va uning sinov yarmi qotiriladi.
2. Keyin g'oyalar birma-bir qo'shiladi, faqat ishlab chiqish (dev)
   ma'lumotida tekshiriladi.
3. Oxirida v6 muzlatiladi va sinov yarmida **bir marta** ishga tushiriladi.

Har bir g'oya `v6` bayrog'i ortida qo'shiladi, ya'ni v2–v5 o'zgarmaydi. Dev
ma'lumotida zarar bergan g'oya olib tashlanadi va bu yerda yoziladi.

## Qadamlar

| # | Qadam | Qayerdan | Nima quriladi | Qabul sharti | Holat |
|---|---|---|---|---|---|
| 1 | CVE-replay test to'plami | mythos-agent, CyberGym | `scripts/build_cve_replay.py`: PyPI maslahatlar bazasidan (OSV) uch turdagi, tuzatish commit'i bor yozuvlar; har biri uchun zaif va tuzatilgan holat; dev / sinov bo'linishi | To'plam yuklangan, hash bilan qotirilgan, protokol push qilingan | **bajarildi** (dev 28, sinov 30 ta yozuv) |
| 2 | Juft baholash | CyberGym | `secagent/evaluate.py` ga `cve_replay` to'plami va baholash: zaif holatda topish, tuzatilgan holatda jim turish | Skript dev yarmida ishlaydi, testlar o'tadi | **bajarildi** |
| 3 | Dev yarmida boshlang'ich o'lchov | – | single-shot va v5 ni **faqat dev yarmida** ishga tushirish; xatolar tahlili | Jadval va qisqa tahlil shu faylda | **bajarildi** (jadval pastda) |
| 4 | Besh javobli hukm | OpenAnt, cyber-harness | Verifier javobi: zaif / chetlab o'tsa bo'ladi / noaniq / himoyalangan / xavfsiz; "noaniq" past ishonch bilan saqlanadi | Dev to'plamlarda F1 pasaymaydi | **bajarildi**: skaner himoyani kuchli / zaif / yo'q ga ajratadi; verifier besh xil hukm beradi |
| 5 | IDOR verifier'i hujumchi rolida | OpenAnt, CyberStrike | IDOR da'vosi uchun: cheklangan hujumchi, zarar boshqa foydalanuvchiga yetishi shart; himoyalangan qo'shni route dalil sifatida | Dev'da IDOR soxta signali kamayadi, core recall pasaymaydi | **bajarildi** (dev'da zarar ko'rinmadi; foydasi 12 tadan 1 ta avtorizatsiya yozuvi) |
| 6 | Nomi bo'yicha kontekst | Vulnhuntr | Verifier bitta funksiya yoki klassni nomi bilan so'rashi mumkin; controller AST indeksidan topib beradi; ko'pi bilan 2 aylanish, takror so'rovda to'xtaydi | Dev'da F1 pasaymaydi; so'rovlar soni hisobotda | **bajarildi** (dev CVE yarmida 7 marta, Flask'da 3 marta ishlatildi) |
| 7 | Yetib borish tartibi | OpenAnt | Handler'lardan call graph; oynalar budjeti avval yetib boriladigan kodga sarflanadi | Django dev'da o'tkazib yuborilgan oynalar kamayadi | **qoldirildi**: dev CVE yarmida 2 450 oynadan 63 tasi o'qilmagan, foyda kichik; v6 ga kirmadi |
| 8 | Mustahkamlik | PentAGI, claude-code-security-review | Buzuq model javobida bir marta qayta urinish; qat'iy istisnolar ro'yxati (test, migratsiya, seed fayllari va h.k.) | `invalid_replies` kamayadi | **bajarildi**: qayta urinish; model serveri o'chiq bo'lsa to'xtash. Istisnolar ro'yxati yozilmadi (v5 skanerida seed/migratsiya fayllari allaqachon tashlanadi) |
| 9 | Chiqish | Shannon, numasec | SARIF fayl; bosqichlar bo'yicha yo'qotish jadvali hisobotda | SARIF sxema tekshiruvidan o'tadi | **bajarildi**: SARIF 2.1.0 (rasmiy sxemadan o'tdi), bosqichlar jadvali, CLI'da v5/v6 |
| 10 | Muzlatish va sinov | – | v6 hash'i protokolga yoziladi, push; sinov yarmida single-shot, v5, v6 bir martadan | T15 `docs/experiments.md` da | **bajarildi**: sinov yarmida juft muvaffaqiyat single-shot 0/30, v5 3/30, v6 4/30 (T15) |

## 1-qadam tafsiloti: CVE-replay to'plami

**Manba.** OSV'ning ochiq PyPI bazasi
(`osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`). 2026-10-07 dagi
dastlabki sanoq: uch turdagi 670 ga yaqin yozuvda GitHub tuzatish commit'i
bor (path traversal 343, IDOR/avtorizatsiya 257, SQL injection 70); ulardan
322 tasi 2026-yilda e'lon qilingan.

**Tanlash (oldindan belgilangan, natijani ko'rmasdan):**
- faqat **2026-yilda e'lon qilingan** yozuvlar: ular qwen3:8b o'qitilgan
  ma'lumotdan keyin chiqqan, ya'ni model ularni "yodlagan" bo'lishi mumkin
  emas;
- bitta GitHub tuzatish commit'i, u kamida bitta test bo'lmagan `.py` faylni
  o'zgartirgan, o'zgargan Python fayllar 5 tadan ko'p emas;
- turi CWE bo'yicha: SQL injection (89, 564, 943), path traversal (22, 23, 36,
  73), avtorizatsiya (639, 862, 863, 284, 285, 306);
- yozuv identifikatorining SHA-256 qiymati bo'yicha tartiblanadi; juft
  o'rindagilar dev, toq o'rindagilar sinov yarmiga tushadi.

**Har bir yozuv uchun:** zaif holat (tuzatish commit'ining ota-onasi) va
tuzatilgan holat (commit'ning o'zi). To'liq repo emas, faqat tekshiriladigan
doira saqlanadi: o'zgargan fayllar va ular bilan bir papkadagi `.py` fayllar
(hajm chegarasi bilan). Bu "papka ishorasi berilgan" darajadagi sinov; buni
natijada ochiq yozish kerak.

**Baholash:**
- **Topildi:** zaif holatda, o'zgargan faylda, o'zgargan satrlardan ±10 satr
  ichida, shu turdagi topilma bor.
- **Juft muvaffaqiyat:** zaif holatda topildi **va** tuzatilgan holatda o'sha
  joyda shu turdagi topilma yo'q.
- Qo'shimcha: har holatga to'g'ri kelmagan topilmalar soni. Bu yerda
  yorliqlanmagan joy "soxta" ekani aniq emas, shuning uchun precision emas,
  "boshqa topilmalar soni" deb beriladi.

**Ma'lum cheklovlar (oldindan):**
- Tuzatish satrlari zaiflik joyi bilan har doim ham ustma-ust tushmaydi.
- Haqiqiy kutubxonalar o'quv ilovalaridan boshqacha: zaiflik ko'pincha veb
  handler'da emas, kutubxona funksiyasida. Past natija kutiladi.
- To'plam yozuvlari turli hajmda; ba'zilari yuklanmasligi mumkin (o'chirilgan
  repo). Tashlab ketilganlar sababi bilan ro'yxatga yoziladi.

## Nima qilinmaydi

- Kodni ishga tushirish yoki ekspluatatsiya (agent faqat o'qiydi).
- Sinov yarmiga qarab sozlash. Sinov yarmi 10-qadamgacha ochilmaydi.
- Ko'rilgan to'rt to'plamdagi raqamni natija sifatida ko'rsatish.

## Vaqt taxmini

1–3-qadamlar: bir ish kuni atrofida (asosan yuklash va tekshirish).
4–9-qadamlar: har biri yarim kundan bir kungacha, dev sinovlari GPU'da
1–3 soatdan. 10-qadam: bir necha soat GPU. Jami bir haftaga yaqin ish;
qadamlar ketma-ket, har biri alohida commit.

## Dev natijalari (muzlatishdan oldin, ko'rilgan ma'lumot — natija emas)

CVE dev yarmi, 28 ta maslahat (SQL injection 4, path traversal 12, avtorizatsiya 12):

| Tizim | Zaif holatda topdi | Tuzatilgandan keyin ham belgiladi | Juft muvaffaqiyat | Boshqa topilmalar / holat |
|---|---|---|---|---|
| Single-shot LLM | 2 | 0 | 2/28 = 0.07 (0.02–0.23) | 2.9 |
| v5 skaneri (modelsiz) | 7 | 5 | 2/28 = 0.07 (0.02–0.23) | 2.3 |
| v6 skaneri (modelsiz) | 7 | 2 | 5/28 = 0.18 (0.08–0.36) | 2.2 |
| Agent v5 | 4 | 0 | 4/28 = 0.14 (0.06–0.32) | 1.5 |
| **Agent v6** | 7 | 2 (bittasi topilganlar ichida) | 6/28 = 0.21 (0.10–0.40) | 1.5 |

v6 v5 ga nisbatan 4 ta juft qo'shdi va 2 tasini yo'qotdi (sof +2). Oraliqlar
deyarli to'liq ustma-ust; model javobi ishga tushirishdan ishga tushirishga
biroz o'zgaradi, shuning uchun bu farq dalil emas, faqat "zarar ko'rinmadi"
degani. Skaner qoidalari shu yarmidagi uchta tuzatishga qarab yozilgan.

Ko'rilgan eski to'plamlarda (buzilish tekshiruvi): holdout F1 0.86 → 0.91
(21 TP / 3 FP), Flask 0.58 → 0.59 (43 TP / 13 FP; avtorizatsiya soxta signali
7 → 10). FastAPI va Django'da v6 muzlatishdan oldin ishga tushirilmadi.

Dev sinovi paytida uchragan nosozlik: 2026-10-07 da kompyuter qayta yoqilgach
Ollama ishga tushmagan va v5 to'qqizta holatda bo'sh natija yozgan; ular
o'chirilib qayta bajarildi, baholash kodiga himoya qo'shildi.

## Yakuniy natija (sinov yarmi, 30 ta maslahat, bir marta)

| Tizim | Zaif holatda topdi | Juft muvaffaqiyat |
|---|---|---|
| Single-shot LLM | 1 | 0/30 = 0.00 (0.00–0.11) |
| v5 skaneri (modelsiz) | 4 | 1/30 |
| v6 skaneri (modelsiz) | 4 | 1/30 |
| Agent v5 | 5 | 3/30 = 0.10 (0.04–0.26) |
| **Agent v6** | 6 | 4/30 = 0.13 (0.05–0.30) |

Xulosa: olingan g'oyalar o'lchanadigan foyda bermadi (v6 va v5 orasida bitta
yozuv farq). Dev yarmida eng yaxshi ko'ringan qoida (himoya kuchi: 2 → 5)
sinov yarmida hech narsa bermadi (1 → 1). Ikkala agent ham single-shot'dan
yaxshiroq. Batafsil: `docs/experiments.md` T15.

## Muzlatishdan keyin aniqlangan kamchilik

Muzlatilgan v6 FastAPI va Django'da (ko'rilgan to'plamlar) ham ishga
tushirildi; bu muzlatishdan oldin qilinmagan edi:

| To'plam | v5 (to'g'ri / soxta, F1) | v6 (to'g'ri / soxta, F1) | IDOR soxta signali |
|---|---|---|---|
| FastAPI | 84 / 157, 0.40 | 90 / 235, 0.36 | 132 → 202 |
| Django | 60 / 48, 0.39 | 63 / 67, 0.38 | 38 → 55 |

v6 avtorizatsiyada v5 dan shovqinliroq: bir necha qo'shimcha to'g'ri topilma
evaziga ancha ko'p soxta signal. Sababi 4–5-qadamlardagi verifier: "noaniq"
hukm va nazorat satrisiz "himoyalangan" hukmi topilmani saqlab qoladi. Xulosa:
**amalda v5 standart bo'lib qoladi**; v6 dan SARIF, bosqichlar jadvali, server
tekshiruvi va CVE-replay test usuli foydali.

