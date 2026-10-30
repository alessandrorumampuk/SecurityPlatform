#!/usr/bin/env python3
"""Probe a base URL for open directory listings ("Index of /...").

When a web server has autoindexing enabled, directories without an index
page render a browsable file list -- Apache/nginx/lighttpd "Index of",
IIS, python -m http.server "Directory listing for". Every entry is a
potentially exposed file.

For each probed directory the script records:
    - whether a real listing page answered (signature-matched, not just
      a 200 -- custom index pages/SPA fallbacks also return 200)
    - server banner when the page discloses one (another small leak)
    - every parsed entry name
    - entries whose filename matches a sensitive-document keyword list:
      Indonesian identity/financial docs (KTP, KK, NPWP, SIM, paspor,
      akta, BPJS, rekening/buku tabungan, kartu kredit/debit, ijazah,
      SKCK, slip gaji, ...) plus generic secrets (backup, dump, .sql,
      password, id_rsa, .env, ...). Matching is substring on a
      normalized name, so "Alessandro KTP.png" still flags on "KTP".

Result is saved as JSON via log_utils.new_log_path and consumed by
auto_hunt.py / vvm.py as "Directory Listing" findings.

Usage:
    python3 directory_listing.py --url https://target.example
    python3 directory_listing.py --url https://target.example --delay 0.2 --out /tmp/dl.json

Local lab / authorized targets only.
"""
import argparse
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

# Directories where autoindex listings are commonly left enabled --
# file stores, upload folders, backups, and content roots.
DIRS = [
    "/files/", "/file/", "/download/", "/downloads/", "/documents/",
    "/docs/", "/doc/", "/uploads/", "/upload/", "/userfiles/",
    "/user_uploads/", "/attachments/", "/media/", "/images/", "/img/",
    "/pictures/", "/photos/", "/videos/", "/audio/",
    "/backup/", "/backups/", "/admin/backup/", "/db_backup/",
    "/data/", "/database/", "/db/", "/sql/", "/dumps/", "/dump/",
    "/export/", "/exports/", "/import/", "/archive/", "/archives/",
    "/logs/", "/log/", "/tmp/", "/temp/", "/cache/", "/storage/",
    "/public/", "/private/", "/internal/", "/shared/", "/share/",
    "/ftp/", "/pub/", "/incoming/", "/outgoing/", "/drop/",
    "/files/uploads/", "/wp-content/uploads/", "/sites/default/files/",
    "/admin/files/", "/admin/documents/", "/content/", "/assets/",
    "/static/", "/webdav/", "/dav/", "/drive/", "/nas/", "/bucket/",
    "/s3/", "/objects/", "/resources/", "/res/", "/release/",
    "/releases/", "/build/", "/builds/", "/artifacts/",
    # bucket-style roots (S3/MinIO/GCS/Azure-compatible endpoints)
    "/", "/?list-type=2", "/?list-type=2&delimiter=/",
    # app-level file browsers
    "/tree", "/_catalog",
]

# Listing page signatures -- a real autoindex page, not any 200.
_LISTING_RES = [
    re.compile(r"<title>\s*Index of\s+", re.I),          # Apache/nginx/lhttpd
    re.compile(r"<h1>\s*Index of\s+", re.I),
    re.compile(r"Directory listing for\s+", re.I),       # python http.server
    re.compile(r"Index of\s+/", re.I),
    # object-storage XML listings (MinIO/S3/GCS/Azure/OpenStack-style)
    re.compile(r"<ListBucketResult[\s>]"),               # S3-compatible
    re.compile(r"<EnumerationResults[\s>]"),             # Azure Blob
    # mod_dav_svn repository browse page
    re.compile(r"Revision\s+\d+:\s*/", re.I),
    # WebDAV PROPFIND reply
    re.compile(r"<[A-Za-z]*:?multistatus[\s>]", re.I),
]

# Entries inside a listing page.
_HREF_RE = re.compile(r'href="([^"#?][^"]*)"')
_DAVHREF_RE = re.compile(r"<[A-Za-z]*:?href[^>]*>\s*([^<]+)", re.I)
_S3KEY_RE = re.compile(r"<Key>([^<]+)</Key>")
_BLOB_RE = re.compile(r"<Name>([^<]+)</Name>")
_ADDR_RE = re.compile(r"<address>([^<]+)</address>", re.I)  # Apache footer

# ---------------------------------------------------------------------------
# Sensitive filename keywords.
#   - multi-word / long keywords match as substring on the normalized name
#   - short codes match as whole tokens so "sim" does not flag "simple.png"
# Normalization: lowercase, non-alnum -> space ("Alessandro_KTP.PNG" ->
# "alessandro ktp png").
# ---------------------------------------------------------------------------

# Indonesian identity / civil / financial documents, employee data,
# bansos/voter lists (UU PDP No.27/2022 "data spesifik": health,
# biometrics, criminal records, children, financial data).
_ID_TOKENS = {
    "ktp", "ektp", "kk", "kia", "npwp", "sim", "stnk", "bpkb", "bpjs",
    "skck", "kis", "nik", "nip", "nrp", "pbb", "sppt", "siup", "tdp",
    "sktm", "suket", "sku", "skdu", "akta", "akte", "ajb", "shm", "hgb",
    "imb", "paspor", "ijazah", "sertifikat", "cv", "pin", "atm",
    "ssn", "ccv", "cvv", "kta", "ktm", "nim", "kip", "kps", "kjp", "kks",
    "fc", "scan", "ttd", "materai", "meterai", "stempel", "mou", "nda",
    # banks & e-wallets in filenames are almost always account docs
    "bca", "bri", "bni", "bsi", "btn", "danamon", "cimb", "permata",
    "jenius", "jago", "gopay", "ovo", "dana", "shopeepay", "linkaja",
    # payroll / employment / budget
    "thr", "cpns", "pppk", "asn", "pns", "sppd", "spj", "lpj", "rab",
    "rkas", "apbd", "hps", "lpse", "bpk", "phk",
    # social aid & citizen datasets (frequent .go.id leaks)
    "bansos", "pkh", "blt", "bpnt", "bst", "dtks", "dpt", "dps",
    "posyandu", "stunting", "bumil", "imunisasi", "pinjol", "nasabah",
    "debitur",
    # health / legal (UU PDP specific categories)
    "hiv", "odha", "tbc", "pcr", "swab", "antigen", "goldar", "napi",
    "dpo", "dtpo",
}
_ID_PHRASES = [
    "kartu tanda penduduk", "kartu keluarga", "kartu kredit",
    "kartu debit", "kartu atm", "kartu bpjs", "kartu indonesia sehat",
    "kartu identitas anak", "kartu nikah", "kartu pelajar",
    "kartu mahasiswa", "kartu vaksin", "kartu anggota",
    "nomor pokok wajib pajak", "surat izin mengemudi", "passport",
    "akta kelahiran", "akta nikah", "akta perkawinan", "akta kematian",
    "akta cerai", "akte kelahiran", "akte nikah", "akte jual beli",
    "surat nikah", "surat cerai", "surat tanah", "sertifikat tanah",
    "girik", "leter c", "izin mendirikan bangunan",
    "buku nikah", "buku tabungan", "buku bank",
    "rekening", "nomor rekening", "no rekening", "norek",
    "rekening koran", "bank statement", "mutasi rekening",
    "bukti transfer", "slip gaji", "daftar gaji", "payslip",
    "pay slip", "pay stub", "uang lembur", "tunjangan",
    "bpjs kesehatan", "bpjs ketenagakerjaan", "jamsostek",
    "jaminan hari tua", "pensiun", "taspen", "mutasi pegawai",
    "surat kuasa", "surat perjanjian", "perjanjian", "kontrak",
    "kontrak kerja", "non disclosure", "surat keputusan",
    "surat tugas", "surat dinas", "nota dinas", "surat masuk",
    "surat keluar", "disposisi", "notulen", "risalah", "minutes",
    "rapat internal",
    "surat keterangan", "surat domisili", "surat keterangan domisili",
    "sk pengangkatan", "sk cpns", "sk honorer", "sk pensiun",
    "data pribadi", "data diri", "biodata", "curriculum vitae",
    "surat lamaran", "lamaran kerja", "kartu pegawai", "data karyawan",
    "data pegawai", "absensi", "presensi", "kehadiran", "daftar hadir",
    "laporan keuangan", "laporan pajak", "surat pajak", "e-billing",
    "faktur pajak", "bukti potong", "bukti setor",
    "kwitansi", "kuitansi", "faktur", "invoice", "tagihan", "nota",
    "transaksi", "mutasi", "surat jalan", "purchase order",
    "sales order", "bill of lading", "air waybill", "airway bill",
    "packing list", "manifest",
    "laporan polisi", "laporan kepolisian", "berita acara", "sttlp",
    "putusan", "vonis", "dakwaan", "surat panggilan", "tilang",
    "pengadilan", "gugatan", "permohonan", "tersangka",
    "warga binaan", "narapidana", "lapas", "tahanan", "intelijen",
    "rahasia negara", "surat rahasia",
    "rahasia", "pribadi", "konfidensial", "confidential", "classified",
    "restricted", "internal use only",
    "kelahiran", "perkawinan", "kematian", "waris", "hibah", "wasiat",
    # education records
    "transkrip", "transkrip nilai", "transcript", "rapor", "raport",
    "kunci jawaban", "answer key", "soal ujian", "daftar nilai",
    "data nilai", "beasiswa", "data siswa", "data murid",
    "data mahasiswa", "data santri", "data guru", "data dosen",
    "data alumni", "peserta didik",
    # finance / lending
    "kredit", "pinjaman", "pinjaman online", "kpr", "deposito",
    "bilyet", "agunan", "jaminan", "fidusia", "investasi", "saham",
    "reksadana", "asuransi", "polis", "klaim",
    # customer/citizen datasets
    "data nasabah", "data pelanggan", "customer data", "data customer",
    "data member", "data user", "data pengguna", "data warga",
    "data penduduk", "data pemilih", "daftar pemilih", "sensus",
    "dukcapil", "penerima bantuan", "data penerima", "bantuan sosial",
    "keluarga penerima", "formulir", "formulir pendaftaran",
    "pendaftaran", "registrasi", "daftar kontak", "daftar nama",
    "phonebook", "kontak",
    "jemaah haji", "jemaah umrah", "data jemaah", "data jamaah",
    "umrah", "haji",
    # scanned id photos / legalized copies
    "foto ktp", "scan ktp", "selfie ktp", "foto kk", "scan kk",
    "pas foto", "pasfoto", "tanda tangan", "fotocopy", "fotokopi",
    "foto copy", "legalisir", "legalisasi", "salinan",
    # foreigner stay / travel
    "kitas", "kitap", "visa", "tiket", "boarding pass", "e ticket",
    # health records (UU PDP spesifik)
    "data pasien", "rekam medis", "medical record", "hasil lab",
    "laboratorium", "rontgen", "usg", "ct scan", "surat sakit",
    "surat sehat", "surat dokter", "resep dokter", "diagnosa",
    "diagnosis", "golongan darah", "hasil swab", "hasil pcr",
    "vaksinasi", "pedulilindungi", "kejiwaan", "konseling", "psikolog",
    "napza", "narkoba", "rehabilitasi",
    # procurement / building / network plans
    "tender", "penawaran", "dokumen penawaran", "harga satuan",
    "site plan", "denah", "blueprint", "as built", "gambar kerja",
    "network diagram", "diagram jaringan", "topologi",
    "anggaran", "pertanggungjawaban", "apbn", "audit",
    "laporan audit", "hasil audit", "internal audit", "temuan",
    "inspektorat",
]
# Generic secrets / ops files worth flagging in a listing. Extensions
# that imply the file itself is the secret/dump are tokens too -- a
# listing where *any* "backup.zip" / "db.sql" appears is already a find.
_GENERIC_TOKENS = {
    "passwd", "shadow", "htpasswd", "id_rsa", "id_dsa", "id_ed25519",
    "ppk", "keystore", "wallet", "mnemonic", "kubeconfig",
    "2fa", "totp", "mfa",
    "sql", "sqlite", "sqlite3", "db", "mdb", "accdb", "dmp",
    "bak", "old", "swp", "zip", "tar", "gz", "7z", "rar", "iso",
    "vmdk", "vhd", "ova", "ovf",
    "pem", "p12", "pfx", "cer", "crt", "der", "asc", "gpg", "key",
    "env", "config", "cfg", "ini", "yml", "yaml", "log", "token",
    "auth", "session", "credentials",
}
_GENERIC_PHRASES = [
    "backup", "dump", "database", "password", "kata sandi", "secret",
    "credential", "kredensial", "private key", "master key",
    "api key", "apikey", "access token", "secret key", "bearer",
    "seed phrase", "recovery code", "backup code", "known hosts",
    "authorized keys", "wp config", "salary", "payroll", "statement",
    "social security",
]


# Tokens >= 3 chars allowed to match glued inside a word boundary
# ("alessandroktp.png" -> token "alessandroktp" ends with "ktp").
# Indonesian users constantly concatenate name+doctype without a
# separator; pure token matching would miss those. 2-char tokens stay
# boundary-exact (kk, cv, pin, fc -> too many collisions).
_CONCAT_TOKENS = {
    "ktp", "ektp", "npwp", "sim", "stnk", "bpkb", "bpjs", "skck",
    "sppt", "siup", "tdp", "sktm", "suket", "sku", "skdu", "ajb",
    "shm", "hgb", "imb", "paspor", "ijazah", "sertifikat", "atm",
    "kta", "ktm", "nim", "kip", "kps", "kjp", "kks", "kia",
    "scan", "ttd", "materai", "meterai", "stempel", "mou",
    "bca", "bri", "bni", "bsi", "btn", "danamon", "cimb", "permata",
    "jenius", "jago", "gopay", "ovo", "dana", "shopeepay", "linkaja",
    "thr", "cpns", "pppk", "asn", "pns", "sppd", "spj", "lpj",
    "rkas", "apbd", "hps", "lpse", "bpk", "phk",
    "bansos", "pkh", "blt", "bpnt", "bst", "dtks", "dpt", "dps",
    "posyandu", "stunting", "bumil", "imunisasi", "pinjol",
    "nasabah", "debitur",
    "hiv", "odha", "tbc", "pcr", "swab", "antigen", "goldar",
    "napi", "dpo", "dtpo", "spt", "ssp", "pkp", "jht",
}
# Common words that start/end with a concat token but are NOT the
# document -- whole glued token is checked against this denylist.
_CONCAT_DENY = {
    # sim*
    "simple", "simpel", "simply", "simulasi", "simulate", "simulates",
    "simulation", "simulator", "simbol", "simbolis", "simbolik",
    "simpan", "simpati", "simpatisan", "simetri", "simetris",
    "simak", "simba", "simbad", "simson", "simcity", "simone",
    "simeulue", "simalungun", "simanjuntak", "simatupang",
    # atm*
    "atmos", "atmosphere", "atmospheric", "atma", "atman", "atmajaya",
    # mou*
    "mouse", "mountain", "mountains", "mouth", "mourn", "mousse",
    "moulin",
    # bri*
    "bridge", "brilliant", "brio", "brief", "bright", "brigade",
    "briket", "brisik", "bring", "british", "brimob",
    # dana*
    "danau", "perdana", "sedana", "pradana", "danaus", "danaid",
    # kia*
    "nokia", "kiara", "kiambang", "kial",
    # imb*
    "imbang", "imbuh", "imbuhan", "imbas", "imba", "imbau",
    # kip*
    "kipas", "kipah", "kiprah", "kiper",
    # scan*
    "scandal", "scandals", "scandinavia", "scandinavian", "scant",
    "scanty", "scania",
    # thr*
    "three", "throw", "throwback", "thread", "threads", "thriller",
    "through", "throat", "throne", "thrift", "thrash", "threat",
    # jago*
    "jagoan", "jaguar", "jagung", "jagong",
}


def _norm(name):
    return re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()


def match_sensitive(name, indonesian=True):
    """Return the matched keyword(s) for a filename, or [].

    Keywords are normalized the same way as filenames, so ".env" or
    "master.key" keywords still fire on normalized names (env token /
    "master key" substring). Three mechanisms:
      1. exact token match          (ktp in "alessandro ktp.png")
      2. concat prefix/suffix match (ktp in "alessandroktp.png",
         guarded by _CONCAT_DENY so "simple" doesn't hit "sim")
      3. squashed phrase substring  ("kartu keluarga" -> kartukeluarga
         matches "kartukeluarga2020.jpg")

    indonesian=False restricts matching to the _GENERIC_* sets: for
    non-.id targets the Indonesian document vocabulary (KTP, NPWP,
    bansos, ...) only costs matching time and risks false positives."""
    n = _norm(html.unescape(urllib.parse.unquote(name)))
    toks = set(n.split())
    sq = n.replace(" ", "")
    hits = []
    kws = _GENERIC_TOKENS | set(_GENERIC_PHRASES)
    if indonesian:
        kws |= _ID_TOKENS | set(_ID_PHRASES)
    for kw in kws:
        nk = _norm(kw)
        if " " in nk:
            if nk in n or nk.replace(" ", "") in sq:
                hits.append(kw)
        elif nk in toks:
            hits.append(kw)
    if indonesian:
        for kw in _CONCAT_TOKENS:
            if kw in hits:
                continue
            for t in toks:
                if t != kw and len(t) > len(kw) and t not in _CONCAT_DENY \
                        and (t.startswith(kw) or t.endswith(kw)):
                    hits.append(kw)
                    break
    return sorted(set(hits))


def _is_listing(body):
    for rx in _LISTING_RES:
        if rx.search(body):
            return rx
    # Apache-style columns without a literal title
    if "Parent Directory" in body and re.search(
            r"(Last\s*modified|Last\s*Modified)", body):
        return True
    return None


def parse_entries(body, path=""):
    """Extract listed names from an autoindex/XML/WebDAV body; skip
    chrome links."""
    out, seen = [], set()

    def push(name, is_dir=False):
        name = html.unescape(name).strip()
        is_dir = is_dir or name.endswith("/")
        name = name.rstrip("/")
        if not name or name in seen:
            return
        seen.add(name)
        out.append({"name": name, "is_dir": is_dir})

    # object-storage XML shapes first -- S3/MinIO keys, Azure blob names
    if "<ListBucketResult" in body:
        for k in _S3KEY_RE.findall(body):
            push(k)
        for p in re.findall(r"<Prefix>([^<]+)</Prefix>", body):
            push(p, is_dir=True)
        return out
    if "<EnumerationResults" in body:
        for n in _BLOB_RE.findall(body):
            push(n)
        return out
    if re.search(r"<[A-Za-z]*:?multistatus[\s>]", body):
        for h in _DAVHREF_RE.findall(body):
            base_seg = urllib.parse.urlsplit(h).path.rstrip("/")
            if not base_seg or base_seg == path.rstrip("/"):
                continue
            push(urllib.parse.unquote(base_seg),
                 is_dir=h.endswith("/"))
        return out

    for href in _HREF_RE.findall(body):
        h = html.unescape(href).strip()
        if not h or h.startswith(("../", "/", "?", "mailto:", "http")):
            continue
        if h.startswith(("C=", "N=", "S=", "M=", "F=", "D=", "P=")):
            continue
        push(h, is_dir=h.endswith("/"))
    return out


def probe_propfind(url, timeout=10):
    """WebDAV fallback: PROPFIND Depth:1 -> 207 multistatus = listing.
    Only tried when plain GET is blocked, since PROPFIND on a missing
    or non-DAV dir just returns another error."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, "Depth": "1"},
            method="PROPFIND")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            if r.status == 207 or "multistatus" in body.lower():
                return body
    except Exception:
        pass
    return None


def probe(base, path, timeout=10, indonesian=True):
    """GET base+path; return a record dict (is_listing when detected)."""
    url = base.rstrip("/") + path
    rec = {"path": path, "url": url, "status": 0, "method": "GET"}
    body = ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            rec["status"] = getattr(r, "status", 200)
            rec["server"] = r.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        rec["status"] = e.code
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:
        rec["error"] = str(e)[:120]
        return rec
    if not _is_listing(body):
        # GET blocked/absent -> WebDAV PROPFIND bypass attempt
        if rec["status"] in (401, 403, 404):
            dav = probe_propfind(url, timeout)
            if dav:
                body, rec["method"], rec["status"] = dav, "PROPFIND", 207
            else:
                return rec
        else:
            return rec
    if not _is_listing(body):
        return rec
    rec["is_listing"] = True
    m = _ADDR_RE.search(body)
    if m:
        rec["server_banner"] = m.group(1).strip()
    entries = parse_entries(body, path)
    rec["file_count"] = len(entries)
    rec["entries"] = [e["name"] for e in entries][:200]
    rec["sensitive"] = [
        {"name": e["name"], "match": match_sensitive(e["name"], indonesian)}
        for e in entries
        if match_sensitive(e["name"], indonesian)]
    return rec


def _is_id_domain(url):
    """True when the target host sits under the .id ccTLD (go.id, co.id,
    ac.id, or.id, sch.id, web.id, desa.id, bare .id, ...). Only those
    targets plausibly host Indonesian-document filenames; anywhere else
    the _ID_* vocabulary is wasted matching time."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    return host == "id" or host.endswith(".id")


def main():
    ap = argparse.ArgumentParser(
        description="Probe for open directory listings and flag "
                    "sensitive filenames inside them")
    ap.add_argument("--url", required=True,
                    help="Base URL, e.g. https://target.example")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--sensitive", choices=("auto", "all", "generic"),
                    default="auto",
                    help="sensitive-filename matcher: auto = Indonesian "
                         "vocabulary only under .id domains (default); "
                         "all = always match it; generic = skip the "
                         "_ID_* sets entirely (generic TLDs, faster)")
    ap.add_argument("--out", help="Output JSON (default: log dir)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    indonesian = args.sensitive == "all" or (
        args.sensitive == "auto" and _is_id_domain(base))
    print(f"[dirlist] sensitive matcher: "
          f"{'indonesian+generic' if indonesian else 'generic only'}")
    out = args.out or new_log_path("dirlist", "json")

    listings, probed = [], []
    for path in DIRS:
        rec = probe(base, path, args.timeout, indonesian)
        probed.append(rec)
        if rec.get("is_listing"):
            listings.append(rec)
            tag = "SENSITIVE" if rec["sensitive"] else "listing"
            print(f"  ◉ {rec['status']} {path} [{rec['method']}]  "
                  f"Index-of ({rec['file_count']} entries) — {tag}")
            for s in rec["sensitive"][:8]:
                print(f"      ⚑ {s['name']}  [{', '.join(s['match'])}]")
        else:
            mark = "▲" if rec["status"] in (401, 403) else "·"
            print(f"  {mark} {rec['status'] or 'ERR':>3} {path}")
        time.sleep(args.delay)

    payload = {
        "generated_by": "directory_listing.py",
        "target": base,
        "sensitive_matcher": "id+generic" if indonesian else "generic",
        "probed_at": datetime.now().isoformat(timespec="seconds"),
        "dirs_tested": len(probed),
        "listings": listings,
        "sensitive_hits": sum(len(l["sensitive"]) for l in listings),
    }
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n💾 {out}")
    print(f"   {len(listings)} open listing(s), "
          f"{payload['sensitive_hits']} sensitive filename(s)")


if __name__ == "__main__":
    main()
