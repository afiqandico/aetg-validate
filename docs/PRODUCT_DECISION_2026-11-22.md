# Product Decision — AETG-Validate
**Tanggal:** 2026-11-22 · **Status:** keputusan fokus (Phase 0) · **Pemilik:** Afiq Andico Pangimpian

Dokumen ini hanya menjawab satu pertanyaan: **produk enterprise mana yang kita bangun,
untuk siapa, dan dari mana uangnya.** Semua angka di bawah punya sumber yang dicantumkan.

---

## 1. Bukti yang kita punya (bukan asumsi)

| Aset | Status verifikasi | Lokasi |
|---|---|---|
| Stack mini-SOC hidup: Zeek + Suricata + Redis + XGBoost detector + dashboard + functional verifier Φ | `docker compose` health-checked, dashboard `127.0.0.1:8000` | `Research/m-comp-sc-research-ongoing/shared/` |
| Generator trafik adversarial PPO (5 modul, 1.381 LOC) | jalan, artefak ESR/FVR di `research/outputs/` | `shared/code/adversarial-traffic-generator/` |
| Detektor XGBoost teraudit | Acc 0,955 · Prec 0,959 · Rec 0,975 · AUC 0,9925 (UNSW-NB15, 175.341 aliran) | `research/models/metrics.json` |
| FVR 100 % (4.995/4.995 langkah valid) | verifier SYN-ACK hidup `:8082` | `research/outputs/fvr_results.json` |
| ESR Φ-tergerbang 0/20.000 (Wilson UB 0,02 %) vs feature-space 70 % (UNSW) / 100 % (CICIDS) | REVIEW_SHEET ESWA | `submissions/eswa_realizability_gap/internal/reviews/` |
| Publikasi + DOI | Zenodo `...122`/`...123`, manuskrip ESWA aktif | repo `Research` |

**Kesimpulan penting:** kita tidak memulai dari nol dan tidak mengarang produk. Yang kita
punya adalah **satu-satunya implementasi nyata dari pengukuran evasi yang di-gate Φ**
(trafik evasi wajib lolos verifikasi fungsional SYN-ACK sebelum boleh dihitung sebagai evasi).

---

## 2. Pasar & celah

Angka pasar (dikutip apa adanya, beda sumber beda cakupan):

- **Security Control Validation (SCV):** USD **5,85 B (2026) → 19,14 B (2032)** — Mordor Intelligence.
- Estimasi konservatif lain: USD 1,45 B (2024), CAGR 13,6 % → 2033 — Growth Market Reports.
- **Breach & Attack Simulation (BAS):** USD **0,72 B** (basis 2025) — MarketsandMarkets.
- Security testing total: USD 23,69 B (2026) — Fortune Business Insights.

Sumber:
- https://www.mordorintelligence.com/industry-reports/security-control-validation-market
- https://www.marketsandmarkets.com/ResearchInsight/automated-breach-attack-simulation-market.asp
- https://growthmarketreports.com/report/security-control-validation-market
- https://www.fortunebusinessinsights.com/security-testing-market-116710

Pemain dan posisinya:

| Pemain | Model | Fokus | Harga |
|---|---|---|---|
| AttackIQ | komersial | emulasi ATT&CK, **agent** di host | kontrak enterprise, puluhan ribu USD/tahun |
| SafeBreach | komersial | CTEM/emulasi, agent + network sensor | enterprise |
| Cymulate | komersial | BAS + exposure validation | enterprise |
| MITRE CALDERA | open source | emulasi adversari, **agent** (Sandcat) | gratis |

**Celah yang tidak diisi siapa pun:**

1. Semua BAS di atas mengukur **"apakah serangan lolos"** pada level host/endpoint.
   Tidak ada yang mengukur **"apakah serangan itu sah secara wire"** — paket yang tidak
   pernah menyelesaikan handshake bukan evasi, itu sampah.
2. Tidak ada yang melaporkan **dua angka terpisah** (feature-space vs Φ-valid) dengan
   interval kepercayaan. Justru di sinilah klaim IDS/ML-NIDS paling sering menyesatkan.
3. Tidak ada alat open source untuk **QA rule Suricata** dari sisi evasion secara sistematis
   dan reproducible.

Ini bukan pasar yang akan digarap AttackIQ (terlalu kecil + terlalu teknis untuk mereka),
tapi cukup besar untuk satu orang.

---

## 3. Keputusan: apa yang dibangun (dan apa yang TIDAK)

**Dibangun: `AETG-Validate`** — platform validasi IDS/ML-NIDS dengan Φ-gate.

Pernyataan nilai satu baris:
> *Kami mengukur seberapa banyak trafik evasi yang lolos dari IDS kamu, dihitung hanya
> dari trafik yang terbukti masih fungsional di jaringan, dengan interval kepercayaan
> dan laporan yang bisa diaudit ulang.*

Tiga pilar produk:

1. **Φ-gate** — setiap aliran wajib lolos verifikasi fungsional sebelum dihitung. Ini
   yang membedakan laporan kita dari angka "70 % evasion" yang tidak bisa dipertahankan.
2. **Dua angka, jujur** — `ESR_feature_space` (diagnostik) dan `ESR_phi` (angka mengikat),
   dengan Wilson 95 % CI masing-masing. Tidak pernah dicampur.
3. **Reproducible** — laporan membawa hash artefak, versi rule, seed, dan signature;
   orang lain bisa mengulang dan akan mendapat angka yang sama.

**TIDAK dibangun (sengaja ditolak):**

- ❌ Mini-SOC-in-a-box untuk UMKM — pesaing gratis (Wazuh, Security Onion) sudah kuat,
  harga jual mendekati nol, dan menjual ke UMKM Indonesia = biaya dukungan tinggi per rupiah.
- ❌ Produk trading (signal-lab/MT5) — beda bidang, pasar penuh bot abal-abal, tidak
  memakai kredibilitas akademik kita sama sekali.
- ❌ Produk pendidikan dari Kitab-STEM — sudah CC BY 4.0, bukan lini pendapatan.
- ❌ SaaS hosted di fase 1 — biaya server + billing + dukungan, sementara pembeli awal
  adalah organisasi yang **tidak mau data trafik mereka keluar** (alasan kuat untuk on-prem).

---

## 4. Beachhead: siapa yang bayar duluan

Bukan Fortune 500 (mereka beli AttackIQ dengan kontrak tahunan). Urutan prioritas:

| # | Segmen | Rasa sakit | Kenapa mau bayar | Cara menjangkau |
|---|---|---|---|---|
| 1 | **Penulis/model ML-NIDS & vendor deteksi** | Reviewer/klien menuduh klaim deteksi mereka tidak reprodusibel | Reputasi + kontrak; validasi pihak ketiga = aset jualan mereka | arXiv, GitHub, komunitas Suricata, konferensi |
| 2 | **MSSP & tim SOC dengan rule Suricata custom** | Rule ditulis, tidak pernah diuji terhadap evasion | Rule yang bocor = insiden yang bisa dihindari | Komunitas Suricata, Reddit r/blue team, LinkedIn |
| 3 | **Lab universitas** | Butuh baseline reproducible untuk paper | Anggaran alat kecil tapi ada; butuh sitasi | arXiv, konferensi, sitasi paper kita |
| 4 | **Auditor/compliance (SI-4, A.8.16)** | Butuh bukti "kontrol sudah diuji", bukan checklist | Laporan bersegel = deliverable mereka | Konsultan GRC |

Alasan memilih #1 sebagai beachhead: mereka **sudah** punya masalah ini secara terbuka,
bisa dijangkau langsung tanpa sales, dan nilai jual kita (angka yang tidak bisa dibantah)
persis masalah mereka.

---

## 5. Monetisasi: open-core AGPL-3.0 + lisensi komersial

| Tier | Isi | Harga | Kenapa masuk akal |
|---|---|---|---|
| **Community** (AGPL-3.0) | CLI, ingest, metrik Φ-gate, laporan JSON/MD, 1 target | **Gratis** | Mesin adopsi + kredibilitas akademik |
| **Pro** | Lisensi komersial (lepas AGPL), laporan HTML/PDF bersegel, ≤ 5 target, integrasi CI | **USD 1.490/tahun/org** | Harga sepersekian BAS enterprise; keputusan bisa diambil tanpa procurement besar |
| **Enterprise** | Target tak terbatas, SSO, SLA dukungan, custom rule pack, laporan multi-situs | **USD 4.900/tahun/org** | Masih < 10 % harga BAS tipikal |
| **Assessment** | Engagement manual: jalankan scan, tulis laporan, presentasi | **USD 1.200–2.500/engagement** | Uang paling awal & paling pasti; sekaligus riset pengguna |

**Kenapa AGPL, bukan Apache-2.0:** AGPL §13 memaksa siapa pun yang menjalankan versi
modifikasi sebagai layanan jaringan untuk membuka kode. Bagi vendor yang ingin menempelkan
mesin ini ke produk mereka secara tertutup, lisensi komersial menjadi satu-satunya jalan.
Apache-2.0 tidak memberi tuas itu sama sekali. (Kalau nanti adopsi macet karena AGPL,
jalur mundurnya adalah dual-license: open-core tetap AGPL, modul laporan jadi proprietary —
bukan mengganti lisensi inti.)

### Proyeksi pendapatan yang jujur

Asumsi konversi open-core solo: **0,5–2 %** dari pengguna aktif nyata menjadi pelanggan berbayar.

| Skenario | Pengguna aktif tahun 1 | Pro | Enterprise | Assessment | Pendapatan tahun 1 |
|---|---|---|---|---|---|
| Pesimis (realistis untuk OSS solo) | 80 | 0 | 0 | 2 | **≈ USD 3.000** |
| Basis | 400 | 3 | 0 | 5 | **≈ USD 10.500** |
| Bull | 1.200 | 8 | 2 | 8 | **≈ USD 36.000** |

Bukan jalur cepat kaya. Yang membuatnya layak: **biaya marjinal ~0** (on-prem, tanpa server),
setiap pelanggan memperkuat kredibilitas akademik, dan assessment memberi uang tunai lebih awal
daripada menunggu konversi lisensi.

---

## 6. Definisi sukses Phase 1 (yang harus ada sebelum publikasi)

1. CLI jalan dan menghasilkan laporan dari **artefak nyata** (`esr_internal.json`,
   `fvr_results.json`, `eve.json`), bukan data karangan.
2. Ada tes otomatis untuk Wilson CI dan perhitungan ESR — angka laporan bisa dibuktikan ulang.
3. `demo` berjalan < 10 detik tanpa docker, supaya orang bisa mencoba tanpa komitmen.
4. Repo publik: AGPL-3.0 + `COMMERCIAL.md` + `SECURITY.md` + CI hijau.
5. Laporan menyebut secara eksplisit bahwa ESR Φ = 0 % adalah **hasil sah**, bukan bug.

Gate publikasi: `make verify` hijau + semua tes lulus + tidak ada klaim tanpa artefak.
