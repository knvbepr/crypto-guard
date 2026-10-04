#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CP_ACP
#define CP_ACP 0
#endif

int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, const char *lpMultiByteStr, int cbMultiByte, wchar_t *lpWideCharStr, int cchWideChar);

HANDLE WINAPI BeginUpdateResourceW(LPCWSTR pFileName, BOOL bDeleteExistingResources);
BOOL WINAPI UpdateResourceW(HANDLE hUpdate, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage, LPVOID lpData, DWORD cb);
BOOL WINAPI EndUpdateResourceW(HANDLE hUpdate, BOOL fDiscard);

static wchar_t *a2w(const char *s) {
  int n = MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
  wchar_t *w = (wchar_t *)malloc(n * sizeof(wchar_t));
  MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
  return w;
}

int main(int argc, char **argv) {
  FILE *f;
  long fsz;
  unsigned char *ico;
  unsigned char *grp;
  HANDLE h;
  int count, i;
  wchar_t *icoW, *exeW;
  if (argc < 3) {
    printf("usage: seticon <app.ico> <target.exe>\n");
    return 1;
  }
  f = fopen(argv[1], "rb");
  if (!f) {
    printf("ERR cannot open ico\n");
    return 1;
  }
  fseek(f, 0, SEEK_END);
  fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  ico = (unsigned char *)malloc(fsz);
  if (fread(ico, 1, fsz, f) != (size_t)fsz) {
    printf("ERR read ico\n");
    return 1;
  }
  fclose(f);
  if (fsz < 22 || ico[0] != 0 || ico[1] != 0 || ico[2] != 1 || ico[3] != 0) {
    printf("ERR not an ico file\n");
    return 1;
  }
  count = ico[4] | (ico[5] << 8);
  if (count < 1 || 6 + count * 16 > fsz) {
    printf("ERR bad ico directory\n");
    return 1;
  }
  grp = (unsigned char *)malloc(6 + 14 * count);
  grp[0] = 0;
  grp[1] = 0;
  grp[2] = 1;
  grp[3] = 0;
  grp[4] = (unsigned char)(count & 0xFF);
  grp[5] = (unsigned char)((count >> 8) & 0xFF);
  icoW = a2w(argv[1]);
  exeW = a2w(argv[2]);
  h = BeginUpdateResourceW(exeW, FALSE);
  if (!h) {
    printf("ERR BeginUpdateResource failed\n");
    return 1;
  }
  for (i = 0; i < count; i++) {
    unsigned char *e = ico + 6 + i * 16;
    unsigned char *g = grp + 6 + i * 14;
    DWORD bytes = (DWORD)e[8] | ((DWORD)e[9] << 8) | ((DWORD)e[10] << 16) | ((DWORD)e[11] << 24);
    DWORD off = (DWORD)e[12] | ((DWORD)e[13] << 8) | ((DWORD)e[14] << 16) | ((DWORD)e[15] << 24);
    if (off + bytes > (DWORD)fsz) {
      printf("ERR icon entry out of bounds\n");
      return 1;
    }
    g[0] = e[0];
    g[1] = e[1];
    g[2] = 0;
    g[3] = 0;
    g[4] = 1;
    g[5] = 0;
    g[6] = e[6];
    g[7] = e[7];
    g[8] = (unsigned char)(bytes & 0xFF);
    g[9] = (unsigned char)((bytes >> 8) & 0xFF);
    g[10] = (unsigned char)((bytes >> 16) & 0xFF);
    g[11] = (unsigned char)((bytes >> 24) & 0xFF);
    g[12] = (unsigned char)((i + 1) & 0xFF);
    g[13] = 0;
    if (!UpdateResourceW(h, RT_ICON, MAKEINTRESOURCEW(i + 1), 0, ico + off, bytes)) {
      printf("ERR UpdateResource(RT_ICON) failed\n");
      EndUpdateResourceW(h, TRUE);
      return 1;
    }
  }
  if (!UpdateResourceW(h, RT_GROUP_ICON, MAKEINTRESOURCEW(1), 0, grp, 6 + 14 * count)) {
    printf("ERR UpdateResource(RT_GROUP_ICON) failed\n");
    EndUpdateResourceW(h, TRUE);
    return 1;
  }
  if (!EndUpdateResourceW(h, FALSE)) {
    printf("ERR EndUpdateResource failed\n");
    return 1;
  }
  printf("OK icon injected (%d images)\n", count);
  return 0;
}
