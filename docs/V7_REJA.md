# v7 reja: v6 dagi shovqinni tuzatish va qolgan foydali g'oyalar

Sana: 2026-10-08. Asos: T15 (`docs/experiments.md`) va `docs/SOLISHTIRUV.md`
ning 5-bo'limi. Foydalanuvchi talabi: qolgan foydali g'oyalarni qo'shish,
sinovni qisqaroq qilish.

## Nega v7

T15 ikki narsani ko'rsatdi:

1. v6 ning yangi verifier'i avtorizatsiyada v5 dan shovqinliroq (FastAPI'da
   IDOR soxta signali 132 → 202). Sabab: "noaniq" hukm va nazorat satrisiz
   "himoyalangan" hukmi topilmani saqlab qoladi; "hujumchi roli" prompti
   modelni "zaif" deyishga undaydi.
2. Solishtiruvdagi 15 g'oyadan 6 tasi umuman qilinmagan edi.

## v7 = v6 + quyidagilar (hammasi `v7` bayrog'i ortida)

| # | O'zgarish | Qayerdan | Maqsad |
|---|---|---|---|
| 1 | Avtorizatsiya da'vosi faqat verifier tasdiqlasa hisobotga kiradi | T15 xulosasi | IDOR soxta signali |
| 2 | "Hujumchi roli" prompti olib tashlandi | T15 o'lchovi | IDOR soxta signali |
| 3 | Egalik tekshiruvi topilgan handler'dagi model da'vosi modelsiz rad etiladi | claude-code-security-review (pretsedentlar) | IDOR soxta signali, tezlik |
| 4 | Verifier'ga loyihaning o'z xavfsizlik odatlari ko'rsatiladi | claude-code-security-review | IDOR aniqligi |
| 5 | Freymvork kartasi (Django / FastAPI / Flask) | Strix | IDOR aniqligi |
| 6 | Python 2 manbalari `lib2to3` orqali o'qiladi | T14 dagi ma'lum kamchilik | qamrov |
| 7 | Loyihadagi `secagent.yml`: o'z manba / sanitizer / sink nomlari | Semgrep | moslashuvchanlik |
| 8 | `--changed-since <git ref>`: faqat o'zgargan fayllar | claude-code-security-review (PR rejimi) | amaliy foydalanish |

Qo'shilmadi: ast-grep (tashqi dastur; 6-band o'sha muammoni hal qiladi),
variant qidiruvi (skaner barcha sinklarni baribir ko'radi), takror detektori
(agentda tsikl yo'q), yetib borish tartibi (T15 da foydasi kichik chiqqan).

## Sinov (qisqartirilgan)

- **Dev (ko'rilgan ma'lumot):** holdout, Flask, Django. Savol: IDOR soxta
  signali v6 va v5 ga nisbatan kamaydimi, haqiqiy topilmalar saqlandimi.
  FastAPI va CVE dev yarmi vaqtni tejash uchun ishga tushirilmaydi.
- **Sinov (ko'rilmagan):** `eval/cve_replay/test2` — oldingi ikki yarmida
  ishlatilmagan repozitoriylardagi 2026-yil maslahatlari, har repozitoriydan
  bittadan: **16 ta** (path traversal 8, avtorizatsiya 8; SQL injection
  nomzodlari tugagan). Qoidalar `docs/cve_replay_protocol.md` dagidek; v7
  muzlatilgach `agent_v5` va `agent_v7` bir martadan ishga tushiriladi.
- **Oldindan aytilgan kutish:** 16 ta juftda farqni ko'rsatib bo'lmaydi;
  kutish faqat "v7 juft muvaffaqiyatda v5 dan past emas". Asosiy dalil dev
  to'plamlardagi IDOR soxta signali bo'ladi, u esa ko'rilgan ma'lumot — buni
  natijada ochiq yozish kerak.

## Holat

### Dev natijalari (ko'rilgan ma'lumot — natija emas)

| To'plam | v5 (to'g'ri / soxta, F1) | v6 | v7 1-variant | **v7 (muzlatilgan)** | IDOR to'g'ri / soxta: v5 → v6 → v7 |
|---|---|---|---|---|---|
| Holdout | 19 / 3, 0.86 | 21 / 3, 0.91 | 21 / 3, 0.91 | qayta ishga tushirilmadi | 7/1 → 8/1 → 8/2 (1-variant) |
| Flask | 41 / 10, 0.58 | 43 / 13, 0.59 | 40 / 10, 0.57 | 42 / 10, 0.59 | 13/7 → 15/10 → 14/6 |
| Django | 60 / 48, 0.385 | 63 / 67, 0.377 | 62 / 57, 0.384 | 62 / 48, 0.395 | 11/38 → 14/55 → 13/38 |

1-variant "faqat tasdiqlangan" qoidasi bilan shovqinni to'liq tuzatmadi
(Django IDOR soxta 47): qoida atigi 1 ta da'voni olib tashladi. Sabab besh
javobli formatning o'zi ekan — unda model kamroq rad etadi (Django'da rad
etishlar v5 57, v6 43, 1-variant 38). Shuning uchun muzlatilgan v7 da
avtorizatsiya da'volari v5 ning ha/yo'q verifier'iga qaytarildi (loyiha
odatlari va freymvork kartasi kontekst sifatida), injection da'volari besh
javobli verifier'da qoldi.

Python 2 tuzatishi (ko'rilgan "boshqa freymvorklar" to'plamida, modelsiz
qism): tornado ilovasida 0 → 2 topilma, jami 6 → 8.

FastAPI va CVE dev yarmi v7 bilan ishga tushirilmadi (vaqtni tejash uchun).

### Muzlatish

v7 = commit `1d8f021`, `secagent/*.py` hash **`223a451dd78c7cab`**. Yozilgan
vaqt: 2026-10-08, `cve_test2` da hech bir tizim ishga tushirilmasidan oldin.
Sinovda `agent_v5`, `agent_v7` va modelsiz `seeds_v7_only` bir martadan
ishlaydi.

### Yakuniy sinov (`cve_test2`, 16 ta maslahat, bir marta)

| Tizim | Zaif holatda topdi | Juft muvaffaqiyat | Boshqa topilmalar / holat |
|---|---|---|---|
| Agent v5 | 1 | 1/16 = 0.06 (0.01–0.28) | 1.7 |
| v7 skaneri (modelsiz) | 3 | 3/16 = 0.19 (0.07–0.43) | 1.9 |
| **Agent v7** | 3 | 3/16 = 0.19 (0.07–0.43) | 2.2 |

Kutish bajarildi (v7 v5 dan past emas), lekin 16 ta juft bundan ortig'ini
ko'rsatmaydi. Foyda verifier'dan emas: modelsiz skanerning o'zi ham shu 3
tasini topgan; v5 ning verifier'i ikkita to'g'ri topilmani rad etgan. v7 ning
besh javobli verifier'i injection da'volarining 75 tasidan atigi 3 tasini rad
etdi (v5: 82 tadan 32), ya'ni to'g'risini ham, yorliqlanmaganini ham deyarli
hammasini o'tkazadi: jami 76 topilma, v5 da 54. Avtorizatsiya: hech bir tizim
8 tadan birortasini topmadi. Batafsil: `docs/experiments.md` T16.

