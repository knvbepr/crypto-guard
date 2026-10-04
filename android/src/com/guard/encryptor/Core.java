package com.guard.encryptor;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class Core {

    public static final byte[] ENC_MAGIC = {0x45, 0x4E, 0x43, 0x01};
    public static final byte[] PKG_MAGIC = {0x4D, 0x50, 0x4B, 0x47};
    public static final String PWD_TAG = "__pwd_";
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_LEN = 32;
    private static final int ITER = 600000;

    private static final SecureRandom RNG = new SecureRandom();
    private static Boolean platformPbkdf2Ok = null;

    private Core() {}

    public static final class Entry {
        public final String name;
        public final byte[] data;
        public Entry(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    public static String encodePwdForName(String pwd) {
        StringBuilder sb = new StringBuilder(pwd.length() + 16);
        for (int i = 0; i < pwd.length(); i++) {
            char c = pwd.charAt(i);
            if (c < 0x20 || c == 0x7F || c == '%' || c == '\\' || c == '/' || c == ':'
                    || c == '*' || c == '?' || c == '"' || c == '<' || c == '>'
                    || c == '|' || c == '[' || c == ']') {
                sb.append('%');
                sb.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xF, 16)));
                sb.append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String decodePwdFromName(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    sb.append((char) ((hi << 4) | lo));
                    i += 2;
                    continue;
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    public static String extractPwdFromEncName(String fileName) {
        if (fileName == null) return null;
        if (fileName.length() < 5 || !fileName.regionMatches(true, fileName.length() - 4, ".enc", 0, 4)) return null;
        int idx = fileName.toLowerCase().lastIndexOf(PWD_TAG);
        if (idx < 0) return null;
        String rest = fileName.substring(idx + PWD_TAG.length());
        if (!rest.regionMatches(true, rest.length() - 4, ".enc", 0, 4)) return null;
        String pwd = decodePwdFromName(rest.substring(0, rest.length() - 4));
        return pwd.isEmpty() ? null : pwd;
    }

    private static byte[] platformPbkdf2(String pwd, byte[] salt, int iter, int dkLen) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(pwd.toCharArray(), salt, iter, dkLen * 8);
        return f.generateSecret(spec).getEncoded();
    }

    private static byte[] manualPbkdf2(byte[] pwd, byte[] salt, int iter, int dkLen) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(pwd, "HmacSHA256"));
        int blocks = (dkLen + 31) / 32;
        byte[] out = new byte[blocks * 32];
        for (int i = 1; i <= blocks; i++) {
            mac.update(salt);
            mac.update(new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i});
            byte[] u = mac.doFinal();
            byte[] t = u.clone();
            for (int j = 1; j < iter; j++) {
                u = mac.doFinal(u);
                for (int k = 0; k < 32; k++) t[k] ^= u[k];
            }
            System.arraycopy(t, 0, out, (i - 1) * 32, 32);
        }
        return Arrays.copyOf(out, dkLen);
    }

    public static byte[] deriveKey(String pwd, byte[] salt) throws Exception {
        byte[] pwdBytes = pwd.getBytes(StandardCharsets.UTF_8);
        if (platformPbkdf2Ok == null) {
            try {
                byte[] a = platformPbkdf2(pwd, salt, 1, KEY_LEN);
                byte[] b = manualPbkdf2(pwdBytes, salt, 1, KEY_LEN);
                platformPbkdf2Ok = Arrays.equals(a, b);
            } catch (Throwable t) {
                platformPbkdf2Ok = Boolean.FALSE;
            }
        }
        if (platformPbkdf2Ok.booleanValue()) {
            return platformPbkdf2(pwd, salt, ITER, KEY_LEN);
        }
        return manualPbkdf2(pwdBytes, salt, ITER, KEY_LEN);
    }

    public static byte[] encryptContainer(byte[] data, String pwd, String displayName) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        RNG.nextBytes(salt);
        RNG.nextBytes(iv);
        byte[] key = deriveKey(pwd, salt);
        byte[] nameBytes = displayName.getBytes(StandardCharsets.UTF_8);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        c.updateAAD(nameBytes);
        byte[] ct = c.doFinal(data);
        ByteArrayOutputStream bos = new ByteArrayOutputStream(4 + SALT_LEN + IV_LEN + 2 + nameBytes.length + ct.length);
        bos.write(ENC_MAGIC, 0, 4);
        bos.write(salt, 0, SALT_LEN);
        bos.write(iv, 0, IV_LEN);
        bos.write((nameBytes.length >> 8) & 0xFF);
        bos.write(nameBytes.length & 0xFF);
        bos.write(nameBytes, 0, nameBytes.length);
        bos.write(ct, 0, ct.length);
        return bos.toByteArray();
    }

    public static Entry decryptContainer(byte[] buf, String pwd) throws Exception {
        if (buf.length < 4 + SALT_LEN + IV_LEN + 2 + 16) throw new Exception("无效的密文文件格式");
        for (int i = 0; i < 4; i++) {
            if (buf[i] != ENC_MAGIC[i]) throw new Exception("无效的密文文件格式");
        }
        int o = 4;
        byte[] salt = Arrays.copyOfRange(buf, o, o + SALT_LEN); o += SALT_LEN;
        byte[] iv = Arrays.copyOfRange(buf, o, o + IV_LEN); o += IV_LEN;
        int nameLen = ((buf[o] & 0xFF) << 8) | (buf[o + 1] & 0xFF); o += 2;
        if (o + nameLen + 16 > buf.length) throw new Exception("无效的密文文件格式");
        String name = new String(buf, o, nameLen, StandardCharsets.UTF_8); o += nameLen;
        byte[] ct = Arrays.copyOfRange(buf, o, buf.length);
        byte[] key = deriveKey(pwd, salt);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        c.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        byte[] pt;
        try {
            pt = c.doFinal(ct);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new Exception("密码错误或文件已损坏");
        }
        return new Entry(name, pt);
    }

    public static byte[] buildPackage(List<Entry> items) {
        int total = 8;
        byte[][] names = new byte[items.size()][];
        for (int i = 0; i < items.size(); i++) {
            names[i] = items.get(i).name.getBytes(StandardCharsets.UTF_8);
            total += 2 + names[i].length + 8 + items.get(i).data.length;
        }
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PKG_MAGIC);
        bb.putInt(items.size());
        for (int i = 0; i < items.size(); i++) {
            long size = items.get(i).data.length;
            bb.putShort((short) names[i].length);
            bb.put(names[i]);
            bb.putInt((int) (size & 0xFFFFFFFFL));
            bb.putInt((int) (size >>> 32));
        }
        for (int i = 0; i < items.size(); i++) {
            bb.put(items.get(i).data);
        }
        return bb.array();
    }

    public static List<Entry> parsePackage(byte[] buf) {
        if (buf.length < 8) return null;
        for (int i = 0; i < 4; i++) {
            if (buf[i] != PKG_MAGIC[i]) return null;
        }
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        int count = bb.getInt(4);
        if (count <= 0 || count > 100000) return null;
        int o = 8;
        String[] names = new String[count];
        long[] sizes = new long[count];
        try {
            for (int i = 0; i < count; i++) {
                if (o + 2 > buf.length) return null;
                int nl = ((buf[o] & 0xFF) | ((buf[o + 1] & 0xFF) << 8)); o += 2;
                if (o + nl + 8 > buf.length) return null;
                names[i] = new String(buf, o, nl, StandardCharsets.UTF_8); o += nl;
                long low = ((long) (buf[o] & 0xFF)) | ((long) (buf[o + 1] & 0xFF) << 8)
                        | ((long) (buf[o + 2] & 0xFF) << 16) | ((long) (buf[o + 3] & 0xFF) << 24);
                long high = ((long) (buf[o + 4] & 0xFF)) | ((long) (buf[o + 5] & 0xFF) << 8)
                        | ((long) (buf[o + 6] & 0xFF) << 16) | ((long) (buf[o + 7] & 0xFF) << 24);
                sizes[i] = (high << 32) | (low & 0xFFFFFFFFL);
                o += 8;
            }
            List<Entry> out = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                if (o + sizes[i] > buf.length) return null;
                out.add(new Entry(names[i], Arrays.copyOfRange(buf, o, o + (int) sizes[i])));
                o += (int) sizes[i];
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private static void put16le(ByteArrayOutputStream bos, int v) {
        bos.write(v & 0xFF);
        bos.write((v >> 8) & 0xFF);
    }

    private static void put32le(ByteArrayOutputStream bos, long v) {
        bos.write((int) (v & 0xFF));
        bos.write((int) ((v >> 8) & 0xFF));
        bos.write((int) ((v >> 16) & 0xFF));
        bos.write((int) ((v >> 24) & 0xFF));
    }

    public static byte[] buildZip(List<Entry> items) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Long> offsets = new ArrayList<>();
        List<Long> crcs = new ArrayList<>();
        Calendar cal = Calendar.getInstance();
        int dosTime = (cal.get(Calendar.HOUR_OF_DAY) << 11) | (cal.get(Calendar.MINUTE) << 5) | (cal.get(Calendar.SECOND) >> 1);
        int dosDate = ((cal.get(Calendar.YEAR) - 1980) << 9) | ((cal.get(Calendar.MONTH) + 1) << 5) | cal.get(Calendar.DAY_OF_MONTH);
        long offset = 0;
        for (Entry e : items) {
            CRC32 crc = new CRC32();
            crc.update(e.data);
            long c = crc.getValue();
            byte[] name = e.name.getBytes(StandardCharsets.UTF_8);
            long size = e.data.length;
            crcs.add(c);
            offsets.add(offset);
            ByteArrayOutputStream lh = new ByteArrayOutputStream();
            put32le(lh, 0x04034b50L);
            put16le(lh, 20);
            put16le(lh, 0x0800);
            put16le(lh, 0);
            put16le(lh, dosTime);
            put16le(lh, dosDate);
            put32le(lh, c);
            put32le(lh, size);
            put32le(lh, size);
            put16le(lh, name.length);
            put16le(lh, 0);
            lh.write(name, 0, name.length);
            out.write(lh.toByteArray());
            out.write(e.data);
            offset += lh.size() + size;
        }
        long cdStart = offset;
        for (int i = 0; i < items.size(); i++) {
            Entry e = items.get(i);
            byte[] name = e.name.getBytes(StandardCharsets.UTF_8);
            long size = e.data.length;
            ByteArrayOutputStream cd = new ByteArrayOutputStream();
            put32le(cd, 0x02014b50L);
            put16le(cd, 20);
            put16le(cd, 20);
            put16le(cd, 0x0800);
            put16le(cd, 0);
            put16le(cd, dosTime);
            put16le(cd, dosDate);
            put32le(cd, crcs.get(i));
            put32le(cd, size);
            put32le(cd, size);
            put16le(cd, name.length);
            put16le(cd, 0);
            put16le(cd, 0);
            put16le(cd, 0);
            put16le(cd, 0);
            put32le(cd, 0);
            put32le(cd, offsets.get(i));
            cd.write(name, 0, name.length);
            out.write(cd.toByteArray());
        }
        long cdSize = out.size() - cdStart;
        ByteArrayOutputStream eocd = new ByteArrayOutputStream();
        put32le(eocd, 0x06054b50L);
        put16le(eocd, 0);
        put16le(eocd, 0);
        put16le(eocd, items.size());
        put16le(eocd, items.size());
        put32le(eocd, cdSize);
        put32le(eocd, cdStart);
        put16le(eocd, 0);
        out.write(eocd.toByteArray());
        return out.toByteArray();
    }
}
