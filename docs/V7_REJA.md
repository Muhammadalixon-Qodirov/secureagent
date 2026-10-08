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

(natijalar kelgach to'ldiriladi)
