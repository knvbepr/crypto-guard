#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#ifndef CP_ACP
#define CP_ACP 0
#endif

int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, const char *lpMultiByteStr, int cbMultiByte, wchar_t *lpWideCharStr, int cchWideChar);
int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, const wchar_t *lpWideCharStr, int cchWideChar, char *lpMultiByteStr, int cbMultiByte, const char *lpDefaultChar, BOOL *lpUsedDefaultChar);

#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32

static const unsigned char ENC_MAGIC[4] = {0x45, 0x4E, 0x43, 0x01};
static const char PWD_TAG[] = "__pwd_";

typedef struct {
  DWORD lStructSize;
  HWND hwndOwner;
  HINSTANCE hInstance;
  LPCWSTR lpstrFilter;
  LPWSTR lpstrCustomFilter;
  DWORD nMaxCustFilter;
  DWORD nFilterIndex;
  LPWSTR lpstrFile;
  DWORD nMaxFile;
  LPWSTR lpstrFileTitle;
  DWORD nMaxFileTitle;
  LPCWSTR lpstrInitialDir;
  LPCWSTR lpstrTitle;
  DWORD Flags;
  WORD nFileOffset;
  WORD nFileExtension;
  LPCWSTR lpstrDefExt;
  LPARAM lCustData;
  LPVOID lpfnHook;
  LPCWSTR lpTemplateName;
  void *pvReserved;
  DWORD dwReserved;
  DWORD FlagsEx;
} OPENFILENAMEW;

BOOL WINAPI GetOpenFileNameW(OPENFILENAMEW *);
BOOL WINAPI GetSaveFileNameW(OPENFILENAMEW *);
void WINAPI DragAcceptFiles(HWND, BOOL);
UINT WINAPI DragQueryFileW(void *, UINT, LPWSTR, UINT);
void WINAPI DragFinish(void *);

#define OFN_OVERWRITEPROMPT 0x00000002
#define OFN_NOCHANGEDIR 0x00000008
#define OFN_ALLOWMULTISELECT 0x00000200
#define OFN_FILEMUSTEXIST 0x00001000
#define OFN_EXPLORER 0x00080000

typedef struct {
  ULONG cbSize;
  ULONG dwInfoVersion;
  unsigned char *pbNonce;
  ULONG cbNonce;
  unsigned char *pbAuthData;
  ULONG cbAuthData;
  unsigned char *pbTag;
  ULONG cbTag;
  unsigned char *pbMacContext;
  ULONG cbMacContext;
  ULONG cbAAD;
  unsigned long long cbData;
  ULONG dwFlags;
} BCRYPT_AUTH_INFO;

typedef LONG (WINAPI *FN_Open)(void **, LPCWSTR, LPCWSTR, ULONG);
typedef LONG (WINAPI *FN_Close)(void *, ULONG);
typedef LONG (WINAPI *FN_GetProp)(void *, LPCWSTR, unsigned char *, ULONG, ULONG *, ULONG);
typedef LONG (WINAPI *FN_SetProp)(void *, LPCWSTR, unsigned char *, ULONG, ULONG);
typedef LONG (WINAPI *FN_GenKey)(void *, void **, unsigned char *, ULONG, unsigned char *, ULONG, ULONG);
typedef LONG (WINAPI *FN_DestroyKey)(void *);
typedef LONG (WINAPI *FN_Encrypt)(void *, unsigned char *, ULONG, BCRYPT_AUTH_INFO *, unsigned char *, ULONG, unsigned char *, ULONG, ULONG *, ULONG);
typedef LONG (WINAPI *FN_Decrypt)(void *, unsigned char *, ULONG, BCRYPT_AUTH_INFO *, unsigned char *, ULONG, unsigned char *, ULONG, ULONG *, ULONG);
typedef LONG (WINAPI *FN_PBKDF2)(void *, unsigned char *, ULONG, unsigned char *, ULONG, unsigned long long, unsigned char *, ULONG, ULONG);
typedef LONG (WINAPI *FN_Rand)(void *, unsigned char *, ULONG, ULONG);

static HMODULE g_bcrypt;
static FN_Open P_Open;
static FN_Close P_Close;
static FN_GetProp P_GetProp;
static FN_SetProp P_SetProp;
static FN_GenKey P_GenKey;
static FN_DestroyKey P_DestroyKey;
static FN_Encrypt P_Encrypt;
static FN_Decrypt P_Decrypt;
static FN_PBKDF2 P_PBKDF2;
static FN_Rand P_Rand;

static int crypto_init(void) {
  if (g_bcrypt) return 0;
  g_bcrypt = LoadLibraryW(L"bcrypt.dll");
  if (!g_bcrypt) return -1;
  P_Open = (FN_Open)GetProcAddress(g_bcrypt, "BCryptOpenAlgorithmProvider");
  P_Close = (FN_Close)GetProcAddress(g_bcrypt, "BCryptCloseAlgorithmProvider");
  P_GetProp = (FN_GetProp)GetProcAddress(g_bcrypt, "BCryptGetProperty");
  P_SetProp = (FN_SetProp)GetProcAddress(g_bcrypt, "BCryptSetProperty");
  P_GenKey = (FN_GenKey)GetProcAddress(g_bcrypt, "BCryptGenerateSymmetricKey");
  P_DestroyKey = (FN_DestroyKey)GetProcAddress(g_bcrypt, "BCryptDestroyKey");
  P_Encrypt = (FN_Encrypt)GetProcAddress(g_bcrypt, "BCryptEncrypt");
  P_Decrypt = (FN_Decrypt)GetProcAddress(g_bcrypt, "BCryptDecrypt");
  P_PBKDF2 = (FN_PBKDF2)GetProcAddress(g_bcrypt, "BCryptDeriveKeyPBKDF2");
  P_Rand = (FN_Rand)GetProcAddress(g_bcrypt, "BCryptGenRandom");
  if (!P_Open || !P_Close || !P_GetProp || !P_SetProp || !P_GenKey || !P_DestroyKey || !P_Encrypt || !P_Decrypt || !P_PBKDF2 || !P_Rand) return -1;
  return 0;
}

static void random_bytes(unsigned char *buf, int len) {
  P_Rand(0, buf, (ULONG)len, 2);
}

static int pbkdf2_gen(const unsigned char *pwd, int pwdLen, const unsigned char *salt, int saltLen, unsigned long long iters, unsigned char *key, int keyLen) {
  void *h = 0;
  LONG st;
  if (crypto_init()) return -1;
  if (P_Open(&h, L"SHA256", 0, 0x00000008)) return -1;
  st = P_PBKDF2(h, (unsigned char *)pwd, (ULONG)pwdLen, (unsigned char *)salt, (ULONG)saltLen, iters, key, (ULONG)keyLen, 0);
  P_Close(h, 0);
  return st == 0 ? 0 : -1;
}

static int pbkdf2_key(const unsigned char *pwd, int pwdLen, const unsigned char *salt, unsigned char *key) {
  return pbkdf2_gen(pwd, pwdLen, salt, SALT_LEN, 600000ULL, key, KEY_LEN);
}

static int gcm_crypt(int encrypt, const unsigned char *key, const unsigned char *iv,
                     const unsigned char *aad, int aadLen,
                     const unsigned char *in, int inLen,
                     unsigned char *out, unsigned char *tag) {
  void *hAlg = 0;
  void *hKey = 0;
  unsigned char *keyObj = 0;
  ULONG objLen = 0, cb = 0, done = 0;
  BCRYPT_AUTH_INFO ai;
  int rc = -1;
  LONG st;
  if (crypto_init()) return -1;
  if (P_Open(&hAlg, L"AES", 0, 0)) return -1;
  st = P_SetProp(hAlg, L"ChainingMode", (unsigned char *)L"ChainingModeGCM", (ULONG)sizeof(L"ChainingModeGCM"), 0);
  if (st) goto out;
  st = P_GetProp(hAlg, L"ObjectLength", (unsigned char *)&objLen, sizeof(objLen), &cb, 0);
  if (st || objLen == 0) goto out;
  keyObj = (unsigned char *)malloc(objLen);
  if (!keyObj) goto out;
  st = P_GenKey(hAlg, &hKey, keyObj, objLen, (unsigned char *)key, KEY_LEN, 0);
  if (st) goto out;
  memset(&ai, 0, sizeof(ai));
  ai.cbSize = sizeof(ai);
  ai.dwInfoVersion = 1;
  ai.pbNonce = (unsigned char *)iv;
  ai.cbNonce = IV_LEN;
  ai.pbAuthData = (unsigned char *)aad;
  ai.cbAuthData = (ULONG)aadLen;
  ai.pbTag = tag;
  ai.cbTag = TAG_LEN;
  if (encrypt) {
    st = P_Encrypt(hKey, (unsigned char *)in, (ULONG)inLen, &ai, 0, 0, out, (ULONG)inLen, &done, 0);
    if (st == 0 && done == (ULONG)inLen) rc = 0;
  } else {
    st = P_Decrypt(hKey, (unsigned char *)in, (ULONG)inLen, &ai, 0, 0, out, (ULONG)inLen, &done, 0);
    if (st == 0 && done == (ULONG)inLen) rc = 0;
    else if (st == (LONG)0xC000A002 || st == (LONG)0xC000A000) rc = -2;
  }
out:
  if (hKey) P_DestroyKey(hKey);
  if (keyObj) free(keyObj);
  if (hAlg) P_Close(hAlg, 0);
  return rc;
}

static void put16(unsigned char *p, unsigned v) {
  p[0] = (unsigned char)(v & 0xFF);
  p[1] = (unsigned char)((v >> 8) & 0xFF);
}
static void put32(unsigned char *p, unsigned long v) {
  p[0] = (unsigned char)(v & 0xFF);
  p[1] = (unsigned char)((v >> 8) & 0xFF);
  p[2] = (unsigned char)((v >> 16) & 0xFF);
  p[3] = (unsigned char)((v >> 24) & 0xFF);
}
static unsigned get16(const unsigned char *p) {
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}
static unsigned long get32(const unsigned char *p) {
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static char *str_dup(const char *s) {
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  memcpy(p, s, n);
  return p;
}
static wchar_t *wcs_dup(const wchar_t *s) {
  size_t n = (wcslen(s) + 1) * sizeof(wchar_t);
  wchar_t *p = (wchar_t *)malloc(n);
  memcpy(p, s, n);
  return p;
}

static char *w2u8(const wchar_t *w) {
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, 0, 0, 0, 0);
  char *s = (char *)malloc(n);
  WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, 0, 0);
  return s;
}
static wchar_t *u82w(const char *s) {
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, 0, 0);
  wchar_t *w = (wchar_t *)malloc(n * sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
  return w;
}
static wchar_t *a2w(const char *s) {
  int n = MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
  wchar_t *w = (wchar_t *)malloc(n * sizeof(wchar_t));
  MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
  return w;
}

static int pwd_byte_bad(unsigned char c) {
  if (c < 0x20 || c == 0x7F) return 1;
  switch (c) {
    case '%': case '\\': case '/': case ':': case '*': case '?':
    case '"': case '<': case '>': case '|': case '[': case ']':
      return 1;
  }
  return 0;
}

static char *encode_pwd(const char *pwd) {
  size_t n = strlen(pwd), i, o = 0;
  char *out = (char *)malloc(n * 3 + 1);
  char hex[] = "0123456789ABCDEF";
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)pwd[i];
    if (pwd_byte_bad(c)) {
      out[o++] = '%';
      out[o++] = hex[c >> 4];
      out[o++] = hex[c & 15];
    } else {
      out[o++] = (char)c;
    }
  }
  out[o] = 0;
  return out;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static char *decode_pwd(const char *s) {
  size_t n = strlen(s), i, o = 0;
  char *out = (char *)malloc(n + 1);
  for (i = 0; i < n; i++) {
    if (s[i] == '%' && i + 2 < n && hexval(s[i + 1]) >= 0 && hexval(s[i + 2]) >= 0) {
      out[o++] = (char)((hexval(s[i + 1]) << 4) | hexval(s[i + 2]));
      i += 2;
    } else {
      out[o++] = s[i];
    }
  }
  out[o] = 0;
  return out;
}

static int ascii_ieq_n(const char *a, const char *b, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
  }
  return 1;
}

static char *extract_pwd_from_name(const wchar_t *filename) {
  char *u = w2u8(filename);
  size_t n = strlen(u);
  size_t last = (size_t)-1;
  size_t i;
  char *enc;
  char *pwd;
  if (n < 5 || !ascii_ieq_n(u + n - 4, ".enc", 4)) {
    free(u);
    return 0;
  }
  for (i = 0; i + 6 <= n; i++) {
    if (ascii_ieq_n(u + i, PWD_TAG, 6)) last = i;
  }
  if (last == (size_t)-1) {
    free(u);
    return 0;
  }
  enc = (char *)malloc(n - last - 6 - 3);
  memcpy(enc, u + last + 6, n - last - 6 - 4);
  enc[n - last - 6 - 4] = 0;
  pwd = decode_pwd(enc);
  free(enc);
  free(u);
  if (!pwd[0]) {
    free(pwd);
    return 0;
  }
  return pwd;
}

static wchar_t *build_enc_filename(const wchar_t *base, const wchar_t *pwdW) {
  char *pwdU8 = w2u8(pwdW);
  char *encU8 = encode_pwd(pwdU8);
  wchar_t *encW = u82w(encU8);
  size_t n = wcslen(base) + 6 + wcslen(encW) + 4 + 1;
  wchar_t *out = (wchar_t *)malloc(n * sizeof(wchar_t));
  wcscpy(out, base);
  wcscat(out, L"__pwd_");
  wcscat(out, encW);
  wcscat(out, L".enc");
  free(pwdU8);
  free(encU8);
  free(encW);
  return out;
}

typedef struct {
  char *name;
  unsigned char *data;
  size_t size;
} Entry;

static unsigned char *container_encrypt(const unsigned char *data, size_t dataLen, const char *pwd, const char *name, size_t *outLen) {
  unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
  unsigned char *ct, *out;
  size_t nameLen = strlen(name), total, o = 0;
  if (dataLen > 0x7FFFFFF0) return 0;
  random_bytes(salt, SALT_LEN);
  random_bytes(iv, IV_LEN);
  if (pbkdf2_key((const unsigned char *)pwd, (int)strlen(pwd), salt, key)) return 0;
  ct = (unsigned char *)malloc(dataLen ? dataLen : 1);
  if (!ct) return 0;
  if (gcm_crypt(1, key, iv, (const unsigned char *)name, (int)nameLen, data, (int)dataLen, ct, tag)) {
    free(ct);
    return 0;
  }
  total = 4 + SALT_LEN + IV_LEN + 2 + nameLen + dataLen + TAG_LEN;
  out = (unsigned char *)malloc(total);
  memcpy(out, ENC_MAGIC, 4); o += 4;
  memcpy(out + o, salt, SALT_LEN); o += SALT_LEN;
  memcpy(out + o, iv, IV_LEN); o += IV_LEN;
  out[o] = (unsigned char)((nameLen >> 8) & 0xFF);
  out[o + 1] = (unsigned char)(nameLen & 0xFF);
  o += 2;
  memcpy(out + o, name, nameLen); o += nameLen;
  if (dataLen) memcpy(out + o, ct, dataLen);
  o += dataLen;
  memcpy(out + o, tag, TAG_LEN); o += TAG_LEN;
  free(ct);
  *outLen = total;
  return out;
}

static int container_decrypt(const unsigned char *buf, size_t len, const char *pwd,
                             unsigned char **outData, size_t *outLen, char **outName) {
  size_t o = 0, nameLen, ctLen;
  const unsigned char *salt, *iv, *ct, *tag;
  unsigned char key[KEY_LEN];
  unsigned char *pt;
  char *name;
  int r;
  if (len < 4 + SALT_LEN + IV_LEN + 2 + TAG_LEN) return -1;
  if (memcmp(buf, ENC_MAGIC, 4)) return -1;
  o = 4;
  salt = buf + o; o += SALT_LEN;
  iv = buf + o; o += IV_LEN;
  nameLen = ((size_t)buf[o] << 8) | (size_t)buf[o + 1];
  o += 2;
  if (o + nameLen + TAG_LEN > len) return -1;
  name = (char *)malloc(nameLen + 1);
  memcpy(name, buf + o, nameLen);
  name[nameLen] = 0;
  o += nameLen;
  ctLen = len - o - TAG_LEN;
  ct = buf + o;
  tag = buf + o + ctLen;
  if (pbkdf2_key((const unsigned char *)pwd, (int)strlen(pwd), salt, key)) {
    free(name);
    return -1;
  }
  pt = (unsigned char *)malloc(ctLen ? ctLen : 1);
  if (!pt) {
    free(name);
    return -1;
  }
  r = gcm_crypt(0, key, iv, (const unsigned char *)name, (int)nameLen, ct, (int)ctLen, pt, (unsigned char *)tag);
  if (r) {
    free(name);
    free(pt);
    return r == -2 ? -2 : -1;
  }
  *outData = pt;
  *outLen = ctLen;
  if (outName) *outName = name;
  else free(name);
  return 0;
}

static unsigned char *pack_build(Entry *es, int n, size_t *outLen) {
  size_t total = 8, o;
  int i;
  unsigned char *out;
  for (i = 0; i < n; i++) total += 2 + strlen(es[i].name) + 8 + es[i].size;
  out = (unsigned char *)malloc(total);
  memcpy(out, "MPKG", 4);
  put32(out + 4, (unsigned long)n);
  o = 8;
  for (i = 0; i < n; i++) {
    size_t nl = strlen(es[i].name);
    put16(out + o, (unsigned)nl); o += 2;
    memcpy(out + o, es[i].name, nl); o += nl;
    put32(out + o, (unsigned long)(es[i].size & 0xFFFFFFFFUL)); o += 4;
    put32(out + o, (unsigned long)(es[i].size >> 32)); o += 4;
  }
  for (i = 0; i < n; i++) {
    if (es[i].size) memcpy(out + o, es[i].data, es[i].size);
    o += es[i].size;
  }
  *outLen = total;
  return out;
}

static int pack_parse(const unsigned char *u8, size_t len, Entry **outEs, int *outN) {
  unsigned long count;
  size_t o = 8;
  Entry *es;
  int i;
  if (len < 8 || memcmp(u8, "MPKG", 4)) return 0;
  count = get32(u8 + 4);
  if (count == 0 || count > 100000) return 0;
  es = (Entry *)calloc(count, sizeof(Entry));
  for (i = 0; i < (int)count; i++) {
    unsigned nl;
    unsigned long lo, hi;
    if (o + 2 > len) goto fail;
    nl = get16(u8 + o); o += 2;
    if (o + nl + 8 > len) goto fail;
    es[i].name = (char *)malloc(nl + 1);
    memcpy(es[i].name, u8 + o, nl);
    es[i].name[nl] = 0;
    o += nl;
    lo = get32(u8 + o);
    hi = get32(u8 + o + 4);
    o += 8;
    es[i].size = ((size_t)hi << 32) | (size_t)lo;
  }
  for (i = 0; i < (int)count; i++) {
    if (o + es[i].size > len) goto fail;
    es[i].data = (unsigned char *)(u8 + o);
    o += es[i].size;
  }
  *outEs = es;
  *outN = (int)count;
  return 1;
fail:
  for (i = 0; i < (int)count; i++) if (es[i].name) free(es[i].name);
  free(es);
  return 0;
}

static unsigned long crc_table[256];
static int crc_ready = 0;
static void crc_init(void) {
  unsigned long n, k, c;
  for (n = 0; n < 256; n++) {
    c = n;
    for (k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
    crc_table[n] = c;
  }
  crc_ready = 1;
}
static unsigned long crc32_buf(const unsigned char *p, size_t n) {
  unsigned long c = 0xFFFFFFFFUL;
  size_t i;
  if (!crc_ready) crc_init();
  for (i = 0; i < n; i++) c = crc_table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
  return (c ^ 0xFFFFFFFFUL) & 0xFFFFFFFFUL;
}

static unsigned char *zip_build(Entry *es, int n, size_t *outLen) {
  size_t total = 22, o;
  int i;
  unsigned char *out;
  unsigned long *offsets = (unsigned long *)calloc(n, sizeof(unsigned long));
  unsigned long *crcs = (unsigned long *)calloc(n, sizeof(unsigned long));
  WORD dosTime, dosDate;
  SYSTEMTIME st;
  GetLocalTime(&st);
  dosTime = (WORD)((st.wHour << 11) | (st.wMinute << 5) | (st.wSecond >> 1));
  dosDate = (WORD)(((st.wYear - 1980) << 9) | (st.wMonth << 5) | st.wDay);
  for (i = 0; i < n; i++) {
    crcs[i] = crc32_buf(es[i].data, es[i].size);
    total += 30 + strlen(es[i].name) + es[i].size;
  }
  for (i = 0; i < n; i++) total += 46 + strlen(es[i].name);
  out = (unsigned char *)malloc(total);
  o = 0;
  for (i = 0; i < n; i++) {
    size_t nl = strlen(es[i].name);
    offsets[i] = (unsigned long)o;
    put32(out + o, 0x04034b50UL); o += 4;
    put16(out + o, 20); o += 2;
    put16(out + o, 0x0800); o += 2;
    put16(out + o, 0); o += 2;
    put16(out + o, dosTime); o += 2;
    put16(out + o, dosDate); o += 2;
    put32(out + o, crcs[i]); o += 4;
    put32(out + o, (unsigned long)es[i].size); o += 4;
    put32(out + o, (unsigned long)es[i].size); o += 4;
    put16(out + o, (unsigned)nl); o += 2;
    put16(out + o, 0); o += 2;
    memcpy(out + o, es[i].name, nl); o += nl;
    if (es[i].size) memcpy(out + o, es[i].data, es[i].size);
    o += es[i].size;
  }
  {
    unsigned long cdStart = (unsigned long)o;
    unsigned long cdSize;
    for (i = 0; i < n; i++) {
      size_t nl = strlen(es[i].name);
      put32(out + o, 0x02014b50UL); o += 4;
      put16(out + o, 20); o += 2;
      put16(out + o, 20); o += 2;
      put16(out + o, 0x0800); o += 2;
      put16(out + o, 0); o += 2;
      put16(out + o, dosTime); o += 2;
      put16(out + o, dosDate); o += 2;
      put32(out + o, crcs[i]); o += 4;
      put32(out + o, (unsigned long)es[i].size); o += 4;
      put32(out + o, (unsigned long)es[i].size); o += 4;
      put16(out + o, (unsigned)nl); o += 2;
      put16(out + o, 0); o += 2;
      put16(out + o, 0); o += 2;
      put16(out + o, 0); o += 2;
      put16(out + o, 0); o += 2;
      put32(out + o, 0); o += 4;
      put32(out + o, offsets[i]); o += 4;
      memcpy(out + o, es[i].name, nl); o += nl;
    }
    cdSize = (unsigned long)(o - cdStart);
    put32(out + o, 0x06054b50UL); o += 4;
    put16(out + o, 0); o += 2;
    put16(out + o, 0); o += 2;
    put16(out + o, (unsigned)n); o += 2;
    put16(out + o, (unsigned)n); o += 2;
    put32(out + o, cdSize); o += 4;
    put32(out + o, cdStart); o += 4;
    put16(out + o, 0); o += 2;
  }
  *outLen = o;
  free(offsets);
  free(crcs);
  return out;
}

static unsigned char *file_read_w(const wchar_t *path, size_t *outLen) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  DWORD hi = 0, lo, got;
  size_t sz, off = 0;
  unsigned char *buf;
  if (h == INVALID_HANDLE_VALUE) return 0;
  lo = GetFileSize(h, &hi);
  sz = ((size_t)hi << 32) | (size_t)lo;
  buf = (unsigned char *)malloc(sz ? sz : 1);
  while (off < sz) {
    DWORD chunk = (DWORD)((sz - off) > 0x40000000UL ? 0x40000000UL : (sz - off));
    if (!ReadFile(h, buf + off, chunk, &got, 0) || got == 0) {
      free(buf);
      CloseHandle(h);
      return 0;
    }
    off += got;
  }
  CloseHandle(h);
  *outLen = sz;
  return buf;
}

static int file_write_w(const wchar_t *path, const unsigned char *data, size_t len) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  size_t off = 0;
  if (h == INVALID_HANDLE_VALUE) return -1;
  while (off < len) {
    DWORD chunk = (DWORD)((len - off) > 0x40000000UL ? 0x40000000UL : (len - off));
    DWORD wrote;
    if (!WriteFile(h, data + off, chunk, &wrote, 0) || wrote == 0) {
      CloseHandle(h);
      return -1;
    }
    off += wrote;
  }
  CloseHandle(h);
  return 0;
}

static const wchar_t *base_name_w(const wchar_t *p) {
  const wchar_t *b = p, *s = p;
  while (*s) {
    if (*s == L'\\' || *s == L'/') b = s + 1;
    s++;
  }
  return b;
}

static wchar_t *build_out_path(const wchar_t *dir, const wchar_t *rel) {
  wchar_t *full = (wchar_t *)malloc((wcslen(dir) + 1 + wcslen(rel) + 1) * sizeof(wchar_t));
  size_t i, dlen;
  wcscpy(full, dir);
  dlen = wcslen(full);
  full[dlen] = L'\\';
  wcscpy(full + dlen + 1, rel);
  for (i = dlen + 1; full[i]; i++) {
    if (full[i] == L'\\' || full[i] == L'/') {
      wchar_t sep = full[i];
      full[i] = 0;
      CreateDirectoryW(full, 0);
      full[i] = sep;
    }
  }
  return full;
}

static void entry_copy(Entry *dst, const char *name, const unsigned char *data, size_t size) {
  dst->name = str_dup(name);
  dst->data = (unsigned char *)malloc(size ? size : 1);
  if (size) memcpy(dst->data, data, size);
  dst->size = size;
}

#ifdef GUARD_TEST

static char *resolve_pwd_arg(const char *arg) {
  if (arg && arg[0] == '@') {
    wchar_t *wp = a2w(arg + 1);
    size_t n;
    unsigned char *buf = file_read_w(wp, &n);
    free(wp);
    if (!buf) return 0;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
    buf[n] = 0;
    return (char *)buf;
  }
  {
    wchar_t *w = a2w(arg ? arg : "");
    char *u = w2u8(w);
    free(w);
    return u;
  }
}

static int cmd_enc(int argc, char **argv) {
  wchar_t *inW, *outW;
  unsigned char *data, *enc;
  size_t dataLen, encLen;
  char *pwd;
  const char *base;
  if (argc < 5) return 5;
  inW = a2w(argv[2]);
  outW = a2w(argv[3]);
  pwd = resolve_pwd_arg(argv[4]);
  data = file_read_w(inW, &dataLen);
  if (!data || !pwd) return 4;
  {
    const char *s = argv[2], *b = argv[2];
    wchar_t *bw;
    while (*s) {
      if (*s == '\\' || *s == '/') b = s + 1;
      s++;
    }
    bw = a2w(b);
    base = w2u8(bw);
    free(bw);
  }
  enc = container_encrypt(data, dataLen, pwd, base, &encLen);
  if (!enc) return 1;
  if (file_write_w(outW, enc, encLen)) return 4;
  printf("OK %lu\n", (unsigned long)encLen);
  free(data);
  free(enc);
  free(pwd);
  free(inW);
  free(outW);
  return 0;
}

static int cmd_encm(int argc, char **argv) {
  wchar_t *outW;
  int n, i;
  Entry *es;
  unsigned char *pack, *enc;
  size_t packLen, encLen;
  char *pwd;
  char display[128];
  if (argc < 5) return 5;
  outW = a2w(argv[2]);
  pwd = resolve_pwd_arg(argv[3]);
  n = argc - 4;
  es = (Entry *)calloc(n, sizeof(Entry));
  for (i = 0; i < n; i++) {
    wchar_t *fp = a2w(argv[4 + i]);
    size_t sz;
    unsigned char *d = file_read_w(fp, &sz);
    const char *b, *s;
    if (!d) return 4;
    b = argv[4 + i];
    s = b;
    while (*s) {
      if (*s == '\\' || *s == '/') b = s + 1;
      s++;
    }
    {
      wchar_t *bw = a2w(b);
      es[i].name = w2u8(bw);
      free(bw);
    }
    es[i].data = d;
    es[i].size = sz;
    free(fp);
  }
  pack = pack_build(es, n, &packLen);
  sprintf(display, "pack %d", n);
  enc = container_encrypt(pack, packLen, pwd, display, &encLen);
  if (!enc) return 1;
  if (file_write_w(outW, enc, encLen)) return 4;
  printf("OK %lu\n", (unsigned long)encLen);
  return 0;
}

static int cmd_dec(int argc, char **argv) {
  wchar_t *inW, *outW;
  unsigned char *buf, *plain;
  size_t bufLen, plainLen;
  char *pwd = 0, *namePwd, *plainName = 0;
  int r;
  if (argc < 4) return 5;
  inW = a2w(argv[2]);
  outW = a2w(argv[3]);
  buf = file_read_w(inW, &bufLen);
  if (!buf) return 4;
  namePwd = extract_pwd_from_name(base_name_w(inW));
  if (argc >= 5 && argv[4][0]) {
    pwd = resolve_pwd_arg(argv[4]);
  } else {
    pwd = namePwd ? str_dup(namePwd) : 0;
  }
  if (!pwd) {
    printf("ERR no password\n");
    return 2;
  }
  r = container_decrypt(buf, bufLen, pwd, &plain, &plainLen, &plainName);
  if (r && namePwd && argc >= 5 && argv[4][0] && strcmp(pwd, namePwd)) {
    r = container_decrypt(buf, bufLen, namePwd, &plain, &plainLen, &plainName);
  }
  if (r == -2) {
    printf("ERR wrong password\n");
    return 2;
  }
  if (r) {
    printf("ERR bad format\n");
    return 3;
  }
  {
    Entry *pes;
    int pn = 0;
    if (pack_parse(plain, plainLen, &pes, &pn)) {
      size_t outLenW = wcslen(outW);
      int isZip = 0;
      int i;
      if (outLenW > 4) {
        const wchar_t *tail = outW + outLenW - 4;
        if (tail[0] == L'.' &&
            (tail[1] == L'z' || tail[1] == L'Z') &&
            (tail[2] == L'i' || tail[2] == L'I') &&
            (tail[3] == L'p' || tail[3] == L'P')) isZip = 1;
      }
      if (isZip) {
        size_t zipLen;
        unsigned char *zip = zip_build(pes, pn, &zipLen);
        if (file_write_w(outW, zip, zipLen)) return 4;
        free(zip);
        printf("OK zip %d files %lu bytes\n", pn, (unsigned long)zipLen);
      } else {
        CreateDirectoryW(outW, 0);
        for (i = 0; i < pn; i++) {
          wchar_t *nameW = u82w(pes[i].name);
          wchar_t *full = build_out_path(outW, nameW);
          if (file_write_w(full, pes[i].data, pes[i].size)) return 4;
          printf("OK file %s %lu\n", pes[i].name, (unsigned long)pes[i].size);
          free(full);
          free(nameW);
        }
      }
      for (i = 0; i < pn; i++) free(pes[i].name);
      free(pes);
    } else {
      if (file_write_w(outW, plain, plainLen)) return 4;
      printf("OK single %s %lu\n", plainName ? plainName : "file", (unsigned long)plainLen);
    }
  }
  free(plainName);
  free(plain);
  free(pwd);
  free(namePwd);
  free(buf);
  free(inW);
  free(outW);
  return 0;
}

static int hex2bin(const char *hex, unsigned char *out, int maxLen) {
  int n = 0;
  while (hex[0] && hex[1] && n < maxLen) {
    int hi = hexval(hex[0]);
    int lo = hexval(hex[1]);
    if (hi < 0 || lo < 0) break;
    out[n++] = (unsigned char)((hi << 4) | lo);
    hex += 2;
  }
  return n;
}

static void print_hex(const unsigned char *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) printf("%02x", p[i]);
  printf("\n");
}

static int cmd_keytest(int argc, char **argv) {
  unsigned char salt[128], key[64];
  int saltLen, keyLen = 32, iters;
  int pwdLen;
  if (argc < 5) return 5;
  pwdLen = (int)strlen(argv[2]);
  saltLen = hex2bin(argv[3], salt, sizeof(salt));
  iters = atoi(argv[4]);
  if (argc >= 6) keyLen = atoi(argv[5]);
  if (pbkdf2_gen((const unsigned char *)argv[2], pwdLen, salt, saltLen, (unsigned long long)iters, key, keyLen)) return 1;
  print_hex(key, keyLen);
  return 0;
}

static int cmd_gcmtest(int argc, char **argv) {
  unsigned char key[64], iv[64], tag[16], *in, *out;
  int keyLen, ivLen, dataLen;
  if (argc < 6) return 5;
  keyLen = hex2bin(argv[2], key, sizeof(key));
  ivLen = hex2bin(argv[3], iv, sizeof(iv));
  if (keyLen != 32 || ivLen != 12) return 5;
  dataLen = (int)strlen(argv[5]);
  in = (unsigned char *)argv[5];
  out = (unsigned char *)malloc(dataLen ? dataLen : 1);
  if (gcm_crypt(1, key, iv, (const unsigned char *)argv[4], (int)strlen(argv[4]), in, dataLen, out, tag)) return 1;
  printf("CT=");
  print_hex(out, dataLen);
  printf("TAG=");
  print_hex(tag, TAG_LEN);
  free(out);
  return 0;
}

static int cmd_packtest(int argc, char **argv) {
  wchar_t *inW;
  unsigned char *buf;
  size_t len;
  Entry *es = 0;
  int n = 0;
  if (argc < 3) return 5;
  inW = a2w(argv[2]);
  buf = file_read_w(inW, &len);
  if (!buf) return 4;
  printf("len=%lu first=%02x%02x%02x%02x\n", (unsigned long)len, buf[0], buf[1], buf[2], buf[3]);
  printf("memcmp=%d\n", memcmp(buf, "MPKG", 4));
  printf("get32=%lu\n", get32(buf + 4));
  if (pack_parse(buf, len, &es, &n)) printf("PARSE OK n=%d\n", n);
  else printf("PARSE FAIL\n");
  return 0;
}

static int cmd_selftest(void) {
  const unsigned char v[] = {1, 2, 3, 0, 255};
  unsigned long c = crc32_buf((const unsigned char *)"123456789", 9);
  if (c != 0xCBF43926UL) {
    printf("FAIL crc %08lX\n", c);
    return 1;
  }
  {
    size_t el;
    unsigned char *e = container_encrypt(v, 5, "pwd123", "t.bin", &el);
    unsigned char *p;
    size_t pl;
    char *nm;
    if (!e) return 1;
    if (container_decrypt(e, el, "pwd123", &p, &pl, &nm)) return 1;
    if (pl != 5 || memcmp(p, v, 5)) return 1;
    printf("OK selftest %s\n", nm);
  }
  printf("OK\n");
  return 0;
}

int main(int argc, char **argv) {
  if (crypto_init()) {
    printf("ERR bcrypt unavailable\n");
    return 1;
  }
  if (argc < 2) {
    printf("usage: enc | encm | dec | selftest\n");
    return 5;
  }
  if (!strcmp(argv[1], "enc")) return cmd_enc(argc, argv);
  if (!strcmp(argv[1], "encm")) return cmd_encm(argc, argv);
  if (!strcmp(argv[1], "dec")) return cmd_dec(argc, argv);
  if (!strcmp(argv[1], "selftest")) return cmd_selftest();
  if (!strcmp(argv[1], "keytest")) return cmd_keytest(argc, argv);
  if (!strcmp(argv[1], "gcmtest")) return cmd_gcmtest(argc, argv);
  if (!strcmp(argv[1], "packtest")) return cmd_packtest(argc, argv);
  printf("ERR unknown command\n");
  return 5;
}

#else

#define ID_RADIO_ENC 101
#define ID_RADIO_DEC 102
#define ID_LIST 103
#define ID_BTN_ADD 104
#define ID_BTN_REMOVE 105
#define ID_BTN_CLEAR 106
#define ID_LBL_PWD 107
#define ID_EDIT_PWD 108
#define ID_CHK_SHOW 109
#define ID_BTN_GO 110
#define ID_EDIT_LOG 111
#define ID_LBL_HINT 112

static HWND g_hList, g_hPwd, g_hGo, g_hLog, g_hChk, g_hLblPwd, g_hMain;
static wchar_t **g_files = 0;
static int g_count = 0, g_cap = 0;
static int g_mode = 0;
static HFONT g_font;

static wchar_t *g_filter_open;
static wchar_t *g_filter_enc;
static wchar_t *g_filter_zip;

static wchar_t *make_filter(const char *u8) {
  size_t len = 0;
  int n;
  wchar_t *w;
  while (!(u8[len] == 0 && u8[len + 1] == 0)) len++;
  len += 2;
  n = MultiByteToWideChar(CP_UTF8, 0, u8, (int)len, 0, 0);
  w = (wchar_t *)malloc(n * sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, u8, (int)len, w, n);
  return w;
}

static void msg_u8(HWND hwnd, const char *text, UINT icon) {
  wchar_t *w = u82w(text);
  wchar_t *title = u82w("加密卫士");
  MessageBoxW(hwnd, w, title, MB_OK | icon);
  free(w);
  free(title);
}

static void log_append(HWND hwnd, const wchar_t *text) {
  int len = GetWindowTextLengthW(g_hLog);
  SendMessageW(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
  SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)text);
  SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
}

static void log_u8(HWND hwnd, const char *text) {
  wchar_t *w = u82w(text);
  log_append(hwnd, w);
  free(w);
}

static void add_file(HWND hwnd, const wchar_t *path) {
  if (g_count == g_cap) {
    g_cap = g_cap ? g_cap * 2 : 16;
    g_files = (wchar_t **)realloc(g_files, g_cap * sizeof(wchar_t *));
  }
  g_files[g_count] = wcs_dup(path);
  g_count++;
  SendMessageW(g_hList, LB_ADDSTRING, 0, (LPARAM)base_name_w(path));
}

static void clear_files(void) {
  int i;
  for (i = 0; i < g_count; i++) free(g_files[i]);
  g_count = 0;
  SendMessageW(g_hList, LB_RESETCONTENT, 0, 0);
}

static void set_mode(HWND hwnd, int mode) {
  g_mode = mode;
  if (mode == 0) {
    SetWindowTextW(g_hLblPwd, u82w("加密密码（至少 4 位）："));
    SetWindowTextW(g_hGo, u82w("加密并保存..."));
  } else {
    SetWindowTextW(g_hLblPwd, u82w("解密密码（文件名无密码时使用）："));
    SetWindowTextW(g_hGo, u82w("解密并保存..."));
  }
  clear_files();
  SetWindowTextW(g_hLog, L"");
  log_u8(hwnd, mode == 0 ? "已切换到加密模式。请添加文件并设置密码。" : "已切换到解密模式。请添加 .enc 密文文件。");
}

static void add_files_dialog(HWND hwnd) {
  static wchar_t buf[65536];
  OPENFILENAMEW ofn;
  size_t firstLen;
  const wchar_t *p;
  buf[0] = 0;
  memset(&ofn, 0, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = hwnd;
  ofn.lpstrFilter = g_filter_open;
  ofn.lpstrFile = buf;
  ofn.nMaxFile = 65536;
  ofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
  if (!GetOpenFileNameW(&ofn)) return;
  firstLen = wcslen(buf);
  if (firstLen + 1 >= 65536) return;
  if (buf[firstLen + 1] == 0) {
    add_file(hwnd, buf);
  } else {
    wchar_t *dir = (wchar_t *)malloc(65536 * sizeof(wchar_t));
    wcscpy(dir, buf);
    if (firstLen == 0 || (dir[firstLen - 1] != L'\\' && dir[firstLen - 1] != L'/')) {
      dir[firstLen] = L'\\';
      dir[firstLen + 1] = 0;
    }
    p = buf + firstLen + 1;
    while (*p) {
      wchar_t *full = (wchar_t *)malloc(65536 * sizeof(wchar_t));
      wcscpy(full, dir);
      wcscat(full, p);
      add_file(hwnd, full);
      free(full);
      p += wcslen(p) + 1;
    }
    free(dir);
  }
}

static void remove_selected(HWND hwnd) {
  int selCount = (int)SendMessageW(g_hList, LB_GETSELCOUNT, 0, 0);
  int *idx;
  int i;
  if (selCount <= 0) return;
  idx = (int *)malloc(selCount * sizeof(int));
  SendMessageW(g_hList, LB_GETSELITEMS, (WPARAM)selCount, (LPARAM)idx);
  for (i = selCount - 1; i >= 0; i--) {
    int k = idx[i];
    free(g_files[k]);
    memmove(g_files + k, g_files + k + 1, (g_count - k - 1) * sizeof(wchar_t *));
    g_count--;
    SendMessageW(g_hList, LB_DELETESTRING, (WPARAM)k, 0);
  }
  free(idx);
}

static int save_dialog(HWND hwnd, wchar_t *buf, int maxLen, const wchar_t *defExt, const wchar_t *filter) {
  OPENFILENAMEW ofn;
  memset(&ofn, 0, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = hwnd;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = buf;
  ofn.nMaxFile = maxLen;
  ofn.lpstrDefExt = defExt;
  ofn.Flags = OFN_OVERWRITEPROMPT | OFN_EXPLORER | OFN_NOCHANGEDIR;
  return GetSaveFileNameW(&ofn);
}

static void busy(HWND hwnd, int on) {
  EnableWindow(g_hGo, !on);
  EnableWindow(GetDlgItem(hwnd, ID_BTN_ADD), !on);
  EnableWindow(GetDlgItem(hwnd, ID_BTN_REMOVE), !on);
  EnableWindow(GetDlgItem(hwnd, ID_BTN_CLEAR), !on);
  SetCursor(LoadCursorW(0, on ? (LPCWSTR)32514 : (LPCWSTR)32512));
  UpdateWindow(hwnd);
}

static void do_encrypt(HWND hwnd) {
  wchar_t pwd[128];
  char *pwdU8 = 0, *displayName = 0;
  Entry *es;
  unsigned char *payload = 0, *enc = 0;
  size_t payloadLen = 0, encLen = 0;
  wchar_t outBase[512];
  wchar_t *suggested;
  static wchar_t saveBuf[4096];
  int i;
  char line[512];
  if (g_count == 0) {
    msg_u8(hwnd, "请先添加要加密的文件。", MB_ICONINFORMATION);
    return;
  }
  GetWindowTextW(g_hPwd, pwd, 128);
  if (wcslen(pwd) < 4) {
    msg_u8(hwnd, "密码至少 4 位。", MB_ICONERROR);
    SetFocus(g_hPwd);
    return;
  }
  if (crypto_init()) {
    msg_u8(hwnd, "系统加密组件不可用（bcrypt.dll）。", MB_ICONERROR);
    return;
  }
  busy(hwnd, 1);
  es = (Entry *)calloc(g_count, sizeof(Entry));
  for (i = 0; i < g_count; i++) {
    size_t sz;
    unsigned char *d = file_read_w(g_files[i], &sz);
    if (!d) {
      log_u8(hwnd, "读取文件失败，已取消。");
      msg_u8(hwnd, "读取文件失败。", MB_ICONERROR);
      busy(hwnd, 0);
      return;
    }
    es[i].name = w2u8(base_name_w(g_files[i]));
    es[i].data = d;
    es[i].size = sz;
  }
  if (g_count == 1) {
    payload = es[0].data;
    payloadLen = es[0].size;
    displayName = str_dup(es[0].name);
    wcsncpy(outBase, base_name_w(g_files[0]), 100);
    outBase[100] = 0;
  } else {
    payload = pack_build(es, g_count, &payloadLen);
    {
      char disp[64];
      SYSTEMTIME st;
      sprintf(disp, "打包 %d 个文件", g_count);
      displayName = str_dup(disp);
      GetLocalTime(&st);
      {
        wchar_t *fmt = u82w("%d个文件_%04d%02d%02d");
        wsprintfW(outBase, fmt, g_count, st.wYear, st.wMonth, st.wDay);
        free(fmt);
      }
    }
  }
  pwdU8 = w2u8(pwd);
  enc = container_encrypt(payload, payloadLen, pwdU8, displayName, &encLen);
  if (!enc) {
    log_u8(hwnd, "加密失败。");
    msg_u8(hwnd, "加密失败。", MB_ICONERROR);
    busy(hwnd, 0);
    return;
  }
  suggested = build_enc_filename(outBase, pwd);
  wcsncpy(saveBuf, suggested, 4095);
  saveBuf[4095] = 0;
  free(suggested);
  if (save_dialog(hwnd, saveBuf, 4096, L"enc", g_filter_enc)) {
    if (file_write_w(saveBuf, enc, encLen)) {
      msg_u8(hwnd, "写入文件失败。", MB_ICONERROR);
    } else {
      char line2[1024];
      char *outU8 = w2u8(saveBuf);
      sprintf(line2, "加密完成: %s (%lu 字节)", outU8, (unsigned long)encLen);
      log_u8(hwnd, line2);
      free(outU8);
      msg_u8(hwnd, "加密完成，密码已保存在文件名中。", MB_ICONINFORMATION);
    }
  } else {
    log_u8(hwnd, "已取消保存。");
  }
  for (i = 0; i < g_count; i++) {
    if (es[i].name) free(es[i].name);
    if (es[i].data) free(es[i].data);
  }
  free(es);
  free(displayName);
  free(pwdU8);
  free(enc);
  busy(hwnd, 0);
}

static void do_decrypt(HWND hwnd) {
  wchar_t manualPwd[128];
  Entry *outs = 0;
  int outCount = 0, outCap = 0;
  int i;
  char line[1024];
  if (g_count == 0) {
    msg_u8(hwnd, "请先添加要解密的 .enc 文件。", MB_ICONINFORMATION);
    return;
  }
  GetWindowTextW(g_hPwd, manualPwd, 128);
  if (crypto_init()) {
    msg_u8(hwnd, "系统加密组件不可用（bcrypt.dll）。", MB_ICONERROR);
    return;
  }
  busy(hwnd, 1);
  for (i = 0; i < g_count; i++) {
    size_t bufLen, plainLen;
    unsigned char *buf = file_read_w(g_files[i], &bufLen);
    char *namePwd, *pwdU8 = 0;
    unsigned char *plain;
    char *plainName = 0;
    int r;
    if (!buf) {
      log_u8(hwnd, "读取文件失败，已跳过。");
      continue;
    }
    namePwd = extract_pwd_from_name(base_name_w(g_files[i]));
    if (namePwd) pwdU8 = str_dup(namePwd);
    else if (manualPwd[0]) pwdU8 = w2u8(manualPwd);
    if (!pwdU8) {
      log_u8(hwnd, "未找到密码（文件名无密码且未输入手动密码），已跳过。");
      free(buf);
      continue;
    }
    r = container_decrypt(buf, bufLen, pwdU8, &plain, &plainLen, &plainName);
    if (r == -2 && namePwd && manualPwd[0]) {
      char *mp = w2u8(manualPwd);
      r = container_decrypt(buf, bufLen, mp, &plain, &plainLen, &plainName);
      free(mp);
    }
    if (r == -2) {
      log_u8(hwnd, "密码错误或文件已损坏，已跳过。");
      free(pwdU8);
      free(namePwd);
      free(buf);
      continue;
    }
    if (r) {
      log_u8(hwnd, "不是有效的密文文件，已跳过。");
      free(pwdU8);
      free(namePwd);
      free(buf);
      continue;
    }
    {
      Entry *pes = 0;
      int pn = 0;
      char *plainDisplayName = plainName ? plainName : (char *)"";
      if (pack_parse(plain, plainLen, &pes, &pn)) {
        int k;
        for (k = 0; k < pn; k++) {
          if (outCount == outCap) {
            outCap = outCap ? outCap * 2 : 16;
            outs = (Entry *)realloc(outs, outCap * sizeof(Entry));
          }
          entry_copy(&outs[outCount], pes[k].name, pes[k].data, pes[k].size);
          outCount++;
          free(pes[k].name);
        }
        free(pes);
      } else {
        if (outCount == outCap) {
          outCap = outCap ? outCap * 2 : 16;
          outs = (Entry *)realloc(outs, outCap * sizeof(Entry));
        }
        entry_copy(&outs[outCount], plainDisplayName, plain, plainLen);
        outCount++;
      }
    }
    free(plainName);
    free(plain);
    free(pwdU8);
    free(namePwd);
    free(buf);
  }
  if (outCount == 0) {
    msg_u8(hwnd, "没有成功解密任何文件。", MB_ICONERROR);
    busy(hwnd, 0);
    return;
  }
  if (outCount == 1) {
    static wchar_t saveBuf[4096];
    wchar_t *def = u82w(outs[0].name);
    wcsncpy(saveBuf, def, 4095);
    saveBuf[4095] = 0;
    free(def);
    if (save_dialog(hwnd, saveBuf, 4096, L"", g_filter_open)) {
      if (file_write_w(saveBuf, outs[0].data, outs[0].size)) {
        msg_u8(hwnd, "写入文件失败。", MB_ICONERROR);
      } else {
        log_u8(hwnd, "解密完成，已保存。");
        msg_u8(hwnd, "解密完成。", MB_ICONINFORMATION);
      }
    } else {
      log_u8(hwnd, "已取消保存。");
    }
  } else {
    static wchar_t saveBuf[4096];
    SYSTEMTIME st;
    wchar_t *fmt;
    int okSave;
    GetLocalTime(&st);
    fmt = u82w("解密文件_%04d%02d%02d.zip");
    wsprintfW(saveBuf, fmt, st.wYear, st.wMonth, st.wDay);
    free(fmt);
    okSave = save_dialog(hwnd, saveBuf, 4096, L"zip", g_filter_zip);
    if (okSave) {
      size_t zipLen;
      unsigned char *zip = zip_build(outs, outCount, &zipLen);
      if (file_write_w(saveBuf, zip, zipLen)) {
        msg_u8(hwnd, "写入文件失败。", MB_ICONERROR);
      } else {
        sprintf(line, "解密完成，%d 个文件已打包保存。", outCount);
        log_u8(hwnd, line);
        msg_u8(hwnd, "解密完成，已打包保存为 ZIP。", MB_ICONINFORMATION);
      }
      free(zip);
    } else {
      log_u8(hwnd, "已取消保存。");
    }
  }
  for (i = 0; i < outCount; i++) {
    free(outs[i].name);
    free(outs[i].data);
  }
  free(outs);
  busy(hwnd, 0);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      HWND c;
      int y;
      struct { int id; LPCWSTR cls; const char *text; DWORD style; int x, y, w, h; } C[] = {
        {ID_RADIO_ENC, L"BUTTON", "加密", WS_CHILD | WS_VISIBLE | WS_GROUP | BS_AUTORADIOBUTTON, 16, 12, 70, 24},
        {ID_RADIO_DEC, L"BUTTON", "解密", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 96, 12, 70, 24},
        {0, L"STATIC", "选择文件后点击下方按钮。密码会保存到加密文件名中，解密时自动识别。", WS_CHILD | WS_VISIBLE | SS_LEFT, 180, 16, 372, 20}
      };
      int ci;
      g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
      for (ci = 0; ci < 3; ci++) {
        wchar_t *t = u82w(C[ci].text);
        c = CreateWindowExW(0, C[ci].cls, t, C[ci].style, C[ci].x, C[ci].y, C[ci].w, C[ci].h, hwnd, (HMENU)(LONG_PTR)C[ci].id, 0, 0);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        free(t);
      }
      g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", 0, WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | LBS_EXTENDEDSEL | LBS_NOINTEGRALHEIGHT, 16, 42, 536, 150, hwnd, (HMENU)ID_LIST, 0, 0);
      SendMessageW(g_hList, WM_SETFONT, (WPARAM)g_font, TRUE);
      c = CreateWindowExW(0, L"BUTTON", u82w("添加文件..."), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 16, 200, 100, 28, hwnd, (HMENU)ID_BTN_ADD, 0, 0);
      SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
      c = CreateWindowExW(0, L"BUTTON", u82w("移除所选"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 122, 200, 90, 28, hwnd, (HMENU)ID_BTN_REMOVE, 0, 0);
      SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
      c = CreateWindowExW(0, L"BUTTON", u82w("清空列表"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 218, 200, 90, 28, hwnd, (HMENU)ID_BTN_CLEAR, 0, 0);
      SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
      g_hChk = CreateWindowExW(0, L"BUTTON", u82w("显示密码"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 452, 202, 100, 24, hwnd, (HMENU)ID_CHK_SHOW, 0, 0);
      SendMessageW(g_hChk, WM_SETFONT, (WPARAM)g_font, TRUE);
      g_hLblPwd = CreateWindowExW(0, L"STATIC", u82w("加密密码（至少 4 位）："), WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 244, 250, 20, hwnd, (HMENU)ID_LBL_PWD, 0, 0);
      SendMessageW(g_hLblPwd, WM_SETFONT, (WPARAM)g_font, TRUE);
      g_hPwd = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 270, 240, 282, 24, hwnd, (HMENU)ID_EDIT_PWD, 0, 0);
      SendMessageW(g_hPwd, WM_SETFONT, (WPARAM)g_font, TRUE);
      SendMessageW(g_hPwd, EM_SETLIMITTEXT, 64, 0);
      g_hGo = CreateWindowExW(0, L"BUTTON", u82w("加密并保存..."), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 16, 276, 536, 40, hwnd, (HMENU)ID_BTN_GO, 0, 0);
      SendMessageW(g_hGo, WM_SETFONT, (WPARAM)g_font, TRUE);
      g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 16, 328, 536, 130, hwnd, (HMENU)ID_EDIT_LOG, 0, 0);
      SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_font, TRUE);
      DragAcceptFiles(hwnd, TRUE);
      (void)y;
      return 0;
    }
    case WM_DROPFILES: {
      void *hd = (void *)wp;
      UINT n = DragQueryFileW(hd, 0xFFFFFFFF, 0, 0);
      UINT i;
      for (i = 0; i < n; i++) {
        UINT len = DragQueryFileW(hd, i, 0, 0);
        wchar_t *buf = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
        DragQueryFileW(hd, i, buf, len + 1);
        add_file(hwnd, buf);
        free(buf);
      }
      DragFinish(hd);
      return 0;
    }
    case WM_COMMAND: {
      switch (LOWORD(wp)) {
        case ID_RADIO_ENC:
          if (HIWORD(wp) == BN_CLICKED && g_mode != 0) set_mode(hwnd, 0);
          return 0;
        case ID_RADIO_DEC:
          if (HIWORD(wp) == BN_CLICKED && g_mode != 1) set_mode(hwnd, 1);
          return 0;
        case ID_BTN_ADD:
          add_files_dialog(hwnd);
          return 0;
        case ID_BTN_REMOVE:
          remove_selected(hwnd);
          return 0;
        case ID_BTN_CLEAR:
          clear_files();
          return 0;
        case ID_CHK_SHOW: {
          int checked = (int)SendMessageW(g_hChk, BM_GETCHECK, 0, 0);
          SendMessageW(g_hPwd, EM_SETPASSWORDCHAR, checked == BST_CHECKED ? 0 : (WPARAM)0x25CF, 0);
          InvalidateRect(g_hPwd, 0, TRUE);
          return 0;
        }
        case ID_BTN_GO:
          if (g_mode == 0) do_encrypt(hwnd);
          else do_decrypt(hwnd);
          return 0;
      }
      return 0;
    }
    case WM_CLOSE:
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
  WNDCLASSEXW wc;
  HWND hwnd;
  MSG msg;
  (void)hPrev;
  (void)cmd;
  g_filter_open = make_filter("所有文件 (*.*)\0*.*\0加密文件 (*.enc)\0*.enc\0\0");
  g_filter_enc = make_filter("加密文件 (*.enc)\0*.enc\0所有文件 (*.*)\0*.*\0\0");
  g_filter_zip = make_filter("ZIP 压缩包 (*.zip)\0*.zip\0所有文件 (*.*)\0*.*\0\0");
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WndProc;
  wc.hInstance = hInst;
  wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
  if (!wc.hIcon) wc.hIcon = LoadIconW(0, (LPCWSTR)32512);
  wc.hIconSm = wc.hIcon;
  wc.hCursor = LoadCursorW(0, (LPCWSTR)32512);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = L"CryptoGuardWnd";
  RegisterClassExW(&wc);
  {
    wchar_t *title = u82w("加密卫士 - 文件加密/解密");
    hwnd = CreateWindowExW(0, L"CryptoGuardWnd", title, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 584, 512, 0, 0, hInst, 0);
    free(title);
  }
  g_hMain = hwnd;
  ShowWindow(hwnd, show);
  UpdateWindow(hwnd);
  set_mode(hwnd, 0);
  while (GetMessageW(&msg, 0, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return 0;
}

#endif
