package com.guard.encryptor;

import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Typeface;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.VideoView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final int REQ_PICK_ENC = 1;
    private static final int REQ_PICK_DEC = 2;
    private static final int REQ_SAVE = 3;

    private static final int COLOR_SUB = 0xFF9E9E9E;
    private static final int COLOR_FAIL = 0xFFFF5252;
    private static final int TEXT_PREVIEW_LIMIT = 300 * 1024;
    private static final int HEX_PREVIEW_LIMIT = 64 * 1024;

    private static final String[] IMG_EXT = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico", "avif"};
    private static final String[] VID_EXT = {"mp4", "webm", "mov", "m4v", "ogv", "avi", "mkv"};
    private static final String[] AUD_EXT = {"mp3", "wav", "ogg", "m4a", "aac", "flac", "opus"};
    private static final String[] TXT_EXT = {"txt", "md", "json", "xml", "csv", "log", "yml", "yaml",
            "ini", "conf", "js", "ts", "css", "html", "htm", "py", "java", "c", "cpp", "h", "hpp",
            "cs", "go", "rs", "rb", "php", "sh", "bat", "sql"};
    private static final HashMap<String, String> MIME = new HashMap<String, String>();
    static {
        MIME.put("png", "image/png");
        MIME.put("jpg", "image/jpeg");
        MIME.put("jpeg", "image/jpeg");
        MIME.put("gif", "image/gif");
        MIME.put("webp", "image/webp");
        MIME.put("bmp", "image/bmp");
        MIME.put("svg", "image/svg+xml");
        MIME.put("ico", "image/x-icon");
        MIME.put("avif", "image/avif");
        MIME.put("mp4", "video/mp4");
        MIME.put("webm", "video/webm");
        MIME.put("mov", "video/quicktime");
        MIME.put("m4v", "video/mp4");
        MIME.put("ogv", "video/ogg");
        MIME.put("avi", "video/x-msvideo");
        MIME.put("mkv", "video/x-matroska");
        MIME.put("mp3", "audio/mpeg");
        MIME.put("wav", "audio/wav");
        MIME.put("ogg", "audio/ogg");
        MIME.put("m4a", "audio/mp4");
        MIME.put("aac", "audio/aac");
        MIME.put("flac", "audio/flac");
        MIME.put("opus", "audio/opus");
        MIME.put("zip", "application/zip");
    }

    private RadioButton rbEnc;
    private RadioButton rbDec;
    private ListView listView;
    private FileAdapter adapter;
    private EditText pwdEdit;
    private CheckBox showPwd;
    private Button randPwdBtn;
    private Button goBtn;
    private Button addBtn;
    private Button rmBtn;
    private Button clrBtn;
    private TextView statusView;
    private ProgressBar progress;
    private TextView emptyHint;

    private final ArrayList<UriItem> items = new ArrayList<UriItem>();
    private final ArrayList<ResultItem> results = new ArrayList<ResultItem>();
    private final SecureRandom rng = new SecureRandom();
    private boolean decryptMode = false;
    private int decryptFailCount = 0;
    private byte[] pendingData;
    private String pendingName;
    private int pendingToast;
    private ArrayList<Core.Entry> saveQueue;
    private int saveQueuePos;
    private int saveQueueSaved;
    private int saveQueueCompletion;

    private Dialog resultDialog;
    private Dialog previewDialog;
    private MediaPlayer previewPlayer;
    private VideoView previewVideo;
    private File previewTmp;
    private Handler mediaHandler;
    private Runnable mediaUpdater;

    private static class UriItem {
        final Uri uri;
        final String name;
        final long size;
        boolean checked;
        UriItem(Uri uri, String name, long size) {
            this.uri = uri;
            this.name = name;
            this.size = size;
        }
    }

    private static class ResultItem {
        final boolean ok;
        final String name;
        final byte[] data;
        final String reason;
        final String type;
        boolean checked;
        ResultItem(boolean ok, String name, byte[] data, String reason) {
            this.ok = ok;
            this.name = name;
            this.data = data;
            this.reason = reason;
            this.type = ok ? typeOf(name) : "other";
            this.checked = true;
        }
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }

    private Bitmap makeIcon(String kind, int color) {
        int s = dp(24);
        Bitmap bmp = Bitmap.createBitmap(s, s, Bitmap.Config.ARGB_8888);
        Canvas cv = new Canvas(bmp);
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(color);
        if (kind.equals("play")) {
            Path path = new Path();
            path.moveTo(s * 0.30f, s * 0.18f);
            path.lineTo(s * 0.82f, s * 0.50f);
            path.lineTo(s * 0.30f, s * 0.82f);
            path.close();
            p.setStyle(Paint.Style.FILL);
            cv.drawPath(path, p);
        } else if (kind.equals("pause")) {
            p.setStyle(Paint.Style.FILL);
            cv.drawRect(s * 0.28f, s * 0.18f, s * 0.45f, s * 0.82f, p);
            cv.drawRect(s * 0.55f, s * 0.18f, s * 0.72f, s * 0.82f, p);
        }
        return bmp;
    }

    private void setPlayIcon(ImageButton b, boolean playing) {
        b.setImageBitmap(makeIcon(playing ? "pause" : "play", 0xFF333333));
        b.setContentDescription(playing ? "暂停" : "播放");
    }    private static String fmtSize(long n) {
        if (n < 0) return "?";
        if (n < 1024) return n + " B";
        String[] u = {"KB", "MB", "GB"};
        double v = n;
        int i = -1;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(Locale.US, "%.1f %s", v, u[i]);
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyyMMdd", Locale.US).format(new Date());
    }

    private static String extOf(String name) {
        if (name == null) return "";
        int d = name.lastIndexOf('.');
        return d >= 0 ? name.substring(d + 1).toLowerCase(Locale.US) : "";
    }

    private static boolean inArray(String[] arr, String s) {
        for (int i = 0; i < arr.length; i++) {
            if (arr[i].equals(s)) return true;
        }
        return false;
    }

    private static String typeOf(String name) {
        String e = extOf(name);
        if (inArray(IMG_EXT, e)) return "image";
        if (inArray(VID_EXT, e)) return "video";
        if (inArray(AUD_EXT, e)) return "audio";
        if (inArray(TXT_EXT, e)) return "text";
        if (e.equals("zip")) return "archive";
        return "other";
    }

    private static String typeLabel(String t) {
        if (t.equals("image")) return "图片";
        if (t.equals("video")) return "视频";
        if (t.equals("audio")) return "音频";
        if (t.equals("text")) return "文本";
        if (t.equals("archive")) return "压缩包";
        return "文件";
    }

    private static String mimeOf(String name) {
        String m = MIME.get(extOf(name));
        if (m != null) return m;
        if (inArray(TXT_EXT, extOf(name))) return "text/plain";
        return "application/octet-stream";
    }

    private static String hexDump(byte[] data, int max) {
        int n = Math.min(data.length, max);
        StringBuilder sb = new StringBuilder(n * 4 + 64);
        for (int o = 0; o < n; o += 16) {
            sb.append(String.format(Locale.US, "%08X  ", o));
            for (int i = 0; i < 16; i++) {
                if (o + i < n) sb.append(String.format(Locale.US, "%02X ", data[o + i] & 0xFF));
                else sb.append("   ");
                if (i == 7) sb.append(' ');
            }
            sb.append(' ');
            for (int i = 0; i < 16 && o + i < n; i++) {
                int c = data[o + i] & 0xFF;
                sb.append(c >= 32 && c < 127 ? (char) c : '.');
            }
            sb.append('\n');
        }
        if (n < data.length) {
            sb.append("\n...（仅显示前 ").append(hexLimitText(max)).append("，共 ")
                    .append(data.length).append(" 字节）");
        }
        return sb.toString();
    }

    private static String hexLimitText(int max) {
        if (max >= 1024 * 1024) return (max / (1024 * 1024)) + "MB";
        return (max / 1024) + "KB";
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(8), dp(12), dp(8));

        RadioGroup modeGroup = new RadioGroup(this);
        modeGroup.setOrientation(RadioGroup.HORIZONTAL);
        rbEnc = new RadioButton(this);
        rbEnc.setText("加密");
        rbEnc.setId(1001);
        rbEnc.setChecked(true);
        rbDec = new RadioButton(this);
        rbDec.setText("解密");
        rbDec.setId(1002);
        modeGroup.addView(rbEnc);
        LinearLayout.LayoutParams rbDecLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rbDecLp.leftMargin = dp(16);
        modeGroup.addView(rbDec, rbDecLp);
        modeGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                decryptMode = checkedId == rbDec.getId();
                onModeChanged();
            }
        });
        root.addView(modeGroup);

        FrameLayout listWrap = new FrameLayout(this);
        listView = new ListView(this);
        adapter = new FileAdapter();
        listView.setAdapter(adapter);
        listWrap.addView(listView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        emptyHint = new TextView(this);
        emptyHint.setText("未选择文件\n请点击下方「添加文件」");
        emptyHint.setGravity(Gravity.CENTER);
        emptyHint.setTextColor(COLOR_SUB);
        FrameLayout.LayoutParams hintLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hintLp.gravity = Gravity.CENTER;
        listWrap.addView(emptyHint, hintLp);
        root.addView(listWrap, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout btnRow = new LinearLayout(this);
        addBtn = new Button(this);
        addBtn.setText("添加文件");
        rmBtn = new Button(this);
        rmBtn.setText("移除勾选");
        clrBtn = new Button(this);
        clrBtn.setText("清空");
        LinearLayout.LayoutParams third = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        btnRow.addView(addBtn, third);
        btnRow.addView(rmBtn, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnRow.addView(clrBtn, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(btnRow);

        LinearLayout pwdRow = new LinearLayout(this);
        pwdRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView pwdLabel = new TextView(this);
        pwdLabel.setText("密码:");
        pwdEdit = new EditText(this);
        pwdEdit.setSingleLine(true);
        pwdEdit.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        showPwd = new CheckBox(this);
        showPwd.setText("显示");
        randPwdBtn = new Button(this);
        randPwdBtn.setText("随机");
        pwdRow.addView(pwdLabel);
        pwdRow.addView(pwdEdit, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        pwdRow.addView(showPwd);
        pwdRow.addView(randPwdBtn);
        root.addView(pwdRow);

        goBtn = new Button(this);
        goBtn.setText("加密并保存");
        root.addView(goBtn);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setVisibility(View.GONE);
        root.addView(progress, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        statusView = new TextView(this);
        statusView.setText("密码会写入加密文件名，解密时自动识别。");
        root.addView(statusView);

        setContentView(root);

        addBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                pickFiles(decryptMode);
            }
        });
        rmBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                int removed = 0;
                for (int i = items.size() - 1; i >= 0; i--) {
                    if (items.get(i).checked) {
                        items.remove(i);
                        removed++;
                    }
                }
                if (removed == 0) {
                    toast("请先勾选要移除的文件");
                    return;
                }
                refreshList();
            }
        });
        clrBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                items.clear();
                refreshList();
            }
        });
        showPwd.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                int base = InputType.TYPE_CLASS_TEXT;
                pwdEdit.setInputType(base | (checked
                        ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        : InputType.TYPE_TEXT_VARIATION_PASSWORD));
            }
        });
        randPwdBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#*-_=+";
                StringBuilder sb = new StringBuilder(14);
                for (int i = 0; i < 14; i++) {
                    sb.append(chars.charAt(rng.nextInt(chars.length())));
                }
                String out = sb.toString();
                pwdEdit.setText(out);
                showPwd.setChecked(true);
                toast("已生成随机密码：" + out);
            }
        });
        goBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                startWork();
            }
        });
    }

    private void onModeChanged() {
        goBtn.setText(decryptMode ? "解密并保存" : "加密并保存");
        randPwdBtn.setVisibility(decryptMode ? View.GONE : View.VISIBLE);
        items.clear();
        refreshList();
    }

    private void refreshList() {
        adapter.notifyDataSetChanged();
        emptyHint.setVisibility(items.isEmpty() ? View.VISIBLE : View.GONE);
        if (items.isEmpty()) {
            statusView.setText(decryptMode
                    ? "请添加 .enc 密文文件，密码将自动从文件名识别。"
                    : "请添加文件。多选时自动打包为一个加密文件，密码会写入文件名。");
        } else {
            int checked = 0;
            for (UriItem it : items) if (it.checked) checked++;
            statusView.setText("已选 " + items.size() + " 个文件"
                    + (checked > 0 ? "（勾选 " + checked + " 个）" : "")
                    + (decryptMode ? "，将按各自文件名解密。" : (items.size() > 1 ? "，将打包加密。" : "。")));
        }
    }

    private View buildFileRow(final UriItem it, ViewGroup parent) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));
        TextView tv = new TextView(this);
        StringBuilder sb = new StringBuilder();
        sb.append(it.name).append('\n').append(fmtSize(it.size));
        if (decryptMode) {
            String p = Core.extractPwdFromEncName(it.name);
            sb.append(p != null ? "  ·  密码: " + p : "  ·  需手动输入密码");
        }
        tv.setText(sb.toString());
        tv.setTextSize(14);
        row.addView(tv, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final CheckBox cb = new CheckBox(this);
        cb.setChecked(it.checked);
        cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                it.checked = checked;
                refreshList();
            }
        });
        row.addView(cb, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        row.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                cb.toggle();
            }
        });
        return row;
    }

    private class FileAdapter extends BaseAdapter {
        public int getCount() {
            return items.size();
        }

        public Object getItem(int position) {
            return items.get(position);
        }

        public long getItemId(int position) {
            return position;
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            return buildFileRow(items.get(position), parent);
        }
    }

    private void setBusy(boolean busy, String msg) {
        goBtn.setEnabled(!busy);
        addBtn.setEnabled(!busy);
        rmBtn.setEnabled(!busy);
        clrBtn.setEnabled(!busy);
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        if (msg != null) statusView.setText(msg);
    }

    private void pickFiles(boolean dec) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(i, dec ? REQ_PICK_DEC : REQ_PICK_ENC);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_SAVE) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null && pendingData != null) {
                try {
                    OutputStream os = getContentResolver().openOutputStream(data.getData());
                    try {
                        os.write(pendingData);
                    } finally {
                        os.close();
                    }
                    toast("已保存: " + pendingName);
                    if (saveQueue != null) {
                        saveQueueSaved++;
                        pendingData = null;
                        pendingName = null;
                        pendingToast = 0;
                        continueSaveQueue();
                        return;
                    }
                    if (pendingToast > 0) {
                        toast(pendingToast == 2 ? "已完成（部分文件解密失败）" : "已完成");
                    }
                } catch (Exception e) {
                    saveQueue = null;
                    toast("保存失败: " + e.getMessage());
                }
            } else {
                toast("已取消保存");
                if (saveQueue != null) {
                    saveQueue = null;
                }
            }
            pendingData = null;
            pendingName = null;
            pendingToast = 0;
            setBusy(false, null);
            return;
        }
        if (resultCode != RESULT_OK || data == null) return;
        ArrayList<Uri> uris = new ArrayList<Uri>();
        if (data.getClipData() != null) {
            int n = data.getClipData().getItemCount();
            for (int i = 0; i < n; i++) {
                Uri u = data.getClipData().getItemAt(i).getUri();
                if (u != null) uris.add(u);
            }
        } else if (data.getData() != null) {
            uris.add(data.getData());
        }
        for (Uri u : uris) {
            String name = displayName(u);
            long size = sizeOf(u);
            items.add(new UriItem(u, name, size));
        }
        refreshList();
    }

    private String displayName(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0 && !c.isNull(idx)) {
                    String n = c.getString(idx);
                    if (n != null && n.length() > 0) return n;
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) c.close();
        }
        String s = uri.getLastPathSegment();
        return s != null ? s : "unnamed";
    }

    private long sizeOf(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.SIZE);
                if (idx >= 0 && !c.isNull(idx)) return c.getLong(idx);
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) c.close();
        }
        return -1;
    }

    private byte[] readAll(Uri uri) throws IOException {
        InputStream in = getContentResolver().openInputStream(uri);
        if (in == null) throw new IOException("无法读取文件");
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        } finally {
            in.close();
        }
    }

    private void saveBytes(String name, byte[] data, String mime, int completionToast) {
        pendingData = data;
        pendingName = name;
        pendingToast = completionToast;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        i.putExtra(Intent.EXTRA_TITLE, name);
        startActivityForResult(i, REQ_SAVE);
    }

    private void startWork() {
        if (items.isEmpty()) {
            toast("请先添加文件");
            return;
        }
        final String pwd = pwdEdit.getText().toString();
        if (!decryptMode && pwd.length() < 4) {
            toast("密码至少 4 位");
            return;
        }
        setBusy(true, decryptMode ? "解密中..." : "加密中...");
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (decryptMode) {
                        doDecrypt(pwd);
                    } else {
                        doEncrypt(pwd);
                    }
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            setBusy(false, null);
                            toast("失败: " + (e.getMessage() != null ? e.getMessage() : e.toString()));
                        }
                    });
                }
            }
        }).start();
    }

    private void doEncrypt(final String pwd) throws Exception {
        final ArrayList<UriItem> snapshot = new ArrayList<UriItem>(items);
        List<Core.Entry> entries = new ArrayList<Core.Entry>();
        for (int i = 0; i < snapshot.size(); i++) {
            final int idx = i;
            runOnUiThread(new Runnable() {
                public void run() {
                    statusView.setText("读取文件 " + (idx + 1) + "/" + snapshot.size() + " ...");
                }
            });
            entries.add(new Core.Entry(snapshot.get(i).name, readAll(snapshot.get(i).uri)));
        }
        final byte[] payload;
        final String displayName;
        final String base;
        if (entries.size() == 1) {
            payload = entries.get(0).data;
            displayName = entries.get(0).name;
            String b = displayName;
            if (b.length() > 100) b = b.substring(0, 100);
            base = b;
        } else {
            runOnUiThread(new Runnable() {
                public void run() {
                    statusView.setText("打包 " + snapshot.size() + " 个文件...");
                }
            });
            payload = Core.buildPackage(entries);
            displayName = "打包 " + entries.size() + " 个文件";
            base = entries.size() + "个文件_" + stamp();
        }
        runOnUiThread(new Runnable() {
            public void run() {
                statusView.setText("加密中（AES-256）...");
            }
        });
        final byte[] enc = Core.encryptContainer(payload, pwd, displayName);
        final String outName = base + Core.PWD_TAG + Core.encodePwdForName(pwd) + ".enc";
        runOnUiThread(new Runnable() {
            public void run() {
                saveBytes(outName, enc, "application/octet-stream", 1);
            }
        });
    }

    private void doDecrypt(final String manualPwd) throws Exception {
        final ArrayList<UriItem> snapshot = new ArrayList<UriItem>(items);
        final ArrayList<ResultItem> found = new ArrayList<ResultItem>();
        int fail = 0;
        for (int i = 0; i < snapshot.size(); i++) {
            final int idx = i;
            runOnUiThread(new Runnable() {
                public void run() {
                    statusView.setText("解密 " + (idx + 1) + "/" + snapshot.size() + " ...");
                }
            });
            UriItem it = snapshot.get(i);
            String namePwd = Core.extractPwdFromEncName(it.name);
            byte[] buf;
            try {
                buf = readAll(it.uri);
            } catch (Exception e) {
                fail++;
                found.add(new ResultItem(false, it.name, null, "无法读取文件"));
                continue;
            }
            Core.Entry r = null;
            String reason = "密码错误或文件已损坏";
            if (namePwd != null) {
                try {
                    r = Core.decryptContainer(buf, namePwd);
                } catch (Exception e) {
                    r = null;
                }
            }
            if (r == null && manualPwd.length() > 0 && (namePwd == null || !manualPwd.equals(namePwd))) {
                try {
                    r = Core.decryptContainer(buf, manualPwd);
                } catch (Exception e) {
                    r = null;
                }
            }
            if (r == null) {
                fail++;
                found.add(new ResultItem(false, it.name, null, reason));
                continue;
            }
            List<Core.Entry> parsed = Core.parsePackage(r.data);
            if (parsed != null) {
                for (Core.Entry e : parsed) {
                    found.add(new ResultItem(true, e.name, e.data, null));
                }
            } else {
                found.add(new ResultItem(true, r.name, r.data, null));
            }
        }
        if (found.isEmpty() || countOk(found) == 0) {
            throw new Exception("没有成功解密任何文件（密码错误或文件损坏）");
        }
        final int failCount = fail;
        runOnUiThread(new Runnable() {
            public void run() {
                results.clear();
                results.addAll(found);
                decryptFailCount = failCount;
                setBusy(false, null);
                int ok = countOk(results);
                statusView.setText("解密完成：成功 " + ok + " 个"
                        + (failCount > 0 ? "，失败 " + failCount + " 个" : "") + "。请勾选要保存的内容。");
                showResultsDialog();
            }
        });
    }

    private static int countOk(List<ResultItem> list) {
        int n = 0;
        for (ResultItem r : list) if (r.ok) n++;
        return n;
    }

    private static List<Core.Entry> dedupNames(List<Core.Entry> list) {
        List<Core.Entry> out = new ArrayList<Core.Entry>();
        HashMap<String, Boolean> used = new HashMap<String, Boolean>();
        for (Core.Entry e : list) {
            String name = e.name;
            if (used.containsKey(name)) {
                int dot = name.lastIndexOf('.');
                String base = dot > 0 ? name.substring(0, dot) : name;
                String ext = dot > 0 ? name.substring(dot) : "";
                int n = 2;
                while (used.containsKey(base + "(" + n + ")" + ext)) n++;
                name = base + "(" + n + ")" + ext;
            }
            used.put(name, Boolean.TRUE);
            out.add(new Core.Entry(name, e.data));
        }
        return out;
    }

    private void showResultsDialog() {
        if (results.isEmpty()) return;
        final Dialog d = new Dialog(this);
        resultDialog = d;

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(10), dp(12), dp(8));

        int okCount = countOk(results);
        int failCount = results.size() - okCount;
        TextView title = new TextView(this);
        title.setText("解密结果：成功 " + okCount + " 个"
                + (failCount > 0 ? "，失败 " + failCount + " 个" : ""));
        title.setTextSize(16);
        title.setTypeface(null, Typeface.BOLD);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("勾选要保存的文件（点文件行可切换）；「保存勾选」逐个保存所选原文件，「全部保存」打包为 ZIP。");
        hint.setTextSize(12);
        hint.setTextColor(COLOR_SUB);
        hint.setPadding(0, dp(2), 0, dp(6));
        root.addView(hint);

        ListView lv = new ListView(this);
        lv.setAdapter(new ResultAdapter());
        root.addView(lv, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout btns = new LinearLayout(this);
        Button bClose = new Button(this);
        bClose.setText("关闭");
        Button bSaveAll = new Button(this);
        bSaveAll.setText("全部保存");
        Button bSaveSel = new Button(this);
        bSaveSel.setText("保存勾选");
        LinearLayout.LayoutParams third = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        btns.addView(bClose, third);
        btns.addView(bSaveAll, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btns.addView(bSaveSel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(btns);

        bClose.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                d.dismiss();
            }
        });
        bSaveAll.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                saveResults(true);
            }
        });
        bSaveSel.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                saveResults(false);
            }
        });

        d.setOnDismissListener(new DialogInterface.OnDismissListener() {
            public void onDismiss(DialogInterface di) {
                if (resultDialog == d) resultDialog = null;
            }
        });
        d.setContentView(root);
        d.show();
        Window w = d.getWindow();
        if (w != null) {
            WindowManager.LayoutParams lp = w.getAttributes();
            lp.width = ViewGroup.LayoutParams.MATCH_PARENT;
            lp.height = (int) (getResources().getDisplayMetrics().heightPixels * 0.85);
            w.setAttributes(lp);
        }
    }

    private void saveResults(boolean all) {
        List<Core.Entry> sel = new ArrayList<Core.Entry>();
        for (ResultItem r : results) {
            if (r.ok && (all || r.checked)) {
                sel.add(new Core.Entry(r.name, r.data));
            }
        }
        if (sel.isEmpty()) {
            toast(all ? "没有可保存的文件" : "请先勾选要保存的文件");
            return;
        }
        if (resultDialog != null) {
            resultDialog.dismiss();
            resultDialog = null;
        }
        int completion = decryptFailCount > 0 ? 2 : 1;
        if (sel.size() == 1) {
            saveBytes(sel.get(0).name, sel.get(0).data, mimeOf(sel.get(0).name), completion);
            return;
        }
        if (all) {
            try {
                byte[] zip = Core.buildZip(dedupNames(sel));
                saveBytes("解密文件_" + stamp() + ".zip", zip, "application/zip", completion);
            } catch (Exception e) {
                toast("打包失败: " + e.getMessage());
            }
            return;
        }
        saveQueue = new ArrayList<Core.Entry>(sel);
        saveQueuePos = 0;
        saveQueueSaved = 0;
        saveQueueCompletion = completion;
        continueSaveQueue();
    }

    private void continueSaveQueue() {
        if (saveQueue == null) return;
        if (saveQueuePos >= saveQueue.size()) {
            int n = saveQueueSaved;
            int completion = saveQueueCompletion;
            saveQueue = null;
            setBusy(false, null);
            toast("已逐个保存 " + n + " 个文件"
                    + (completion == 2 ? "（部分文件解密失败）" : ""));
            return;
        }
        Core.Entry e = saveQueue.get(saveQueuePos++);
        setBusy(true, "正在保存 " + saveQueuePos + "/" + saveQueue.size() + "：" + e.name);
        saveBytes(e.name, e.data, mimeOf(e.name), 0);
    }

    private View buildResultRow(final ResultItem r) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));
        TextView tv = new TextView(this);
        if (r.ok) {
            tv.setText(r.name + "\n" + fmtSize(r.data.length) + "  ·  " + typeLabel(r.type));
            tv.setTextSize(14);
        } else {
            tv.setText(r.name + "\n" + r.reason);
            tv.setTextSize(14);
            tv.setTextColor(COLOR_FAIL);
        }
        row.addView(tv, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        if (r.ok) {
            Button pv = new Button(this);
            pv.setText("预览");
            pv.setTextSize(12);
            pv.setPadding(dp(8), 0, dp(8), 0);
            pv.setMinimumWidth(0);
            pv.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    openPreview(r);
                }
            });
            row.addView(pv, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            final CheckBox cb = new CheckBox(this);
            cb.setChecked(r.checked);
            cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                public void onCheckedChanged(CompoundButton v, boolean checked) {
                    r.checked = checked;
                }
            });
            row.addView(cb, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            row.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    cb.toggle();
                }
            });
        }
        return row;
    }

    private class ResultAdapter extends BaseAdapter {
        public int getCount() {
            return results.size();
        }

        public Object getItem(int position) {
            return results.get(position);
        }

        public long getItemId(int position) {
            return position;
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            return buildResultRow(results.get(position));
        }
    }

    private void openPreview(final ResultItem r) {
        if (!r.ok) return;
        final String type = r.type;
        new Thread(new Runnable() {
            public void run() {
                if (type.equals("text")) {
                    int n = Math.min(r.data.length, TEXT_PREVIEW_LIMIT);
                    String text = new String(r.data, 0, n, StandardCharsets.UTF_8);
                    if (r.data.length > n) {
                        text += "\n\n...（内容过长，仅显示前 300KB，共 " + r.data.length + " 字节）";
                    }
                    final String finalText = text;
                    runOnUiThread(new Runnable() {
                        public void run() {
                            showTextViewer(r, finalText);
                        }
                    });
                } else if (type.equals("image")) {
                    final Bitmap bmp = decodePreviewBitmap(r.data);
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (bmp != null) {
                                showImageViewer(r, bmp);
                            } else {
                                showHexViewer(r, hexDump(r.data, HEX_PREVIEW_LIMIT));
                            }
                        }
                    });
                } else if (type.equals("audio") || type.equals("video")) {
                    final File tmp = writeTempFile(r);
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (tmp == null) {
                                toast("无法准备预览文件");
                                return;
                            }
                            if (type.equals("audio")) {
                                showAudioPlayer(r, tmp);
                            } else {
                                showVideoPlayer(r, tmp);
                            }
                        }
                    });
                } else {
                    final String hex = hexDump(r.data, HEX_PREVIEW_LIMIT);
                    runOnUiThread(new Runnable() {
                        public void run() {
                            showHexViewer(r, hex);
                        }
                    });
                }
            }
        }).start();
    }

    private Bitmap decodePreviewBitmap(byte[] data) {
        try {
            BitmapFactory.Options o = new BitmapFactory.Options();
            o.inJustDecodeBounds = true;
            BitmapFactory.decodeByteArray(data, 0, data.length, o);
            if (o.outWidth <= 0 || o.outHeight <= 0) return null;
            int sample = 1;
            while ((o.outWidth / sample) > 2048 || (o.outHeight / sample) > 2048) {
                sample *= 2;
            }
            BitmapFactory.Options o2 = new BitmapFactory.Options();
            o2.inSampleSize = sample;
            return BitmapFactory.decodeByteArray(data, 0, data.length, o2);
        } catch (Throwable t) {
            return null;
        }
    }

    private File writeTempFile(ResultItem r) {
        try {
            String safe = r.name.replaceAll("[^A-Za-z0-9._-]", "_");
            if (safe.length() > 40) safe = safe.substring(safe.length() - 40);
            File f = new File(getCacheDir(), "preview_" + System.currentTimeMillis() + "_" + safe);
            FileOutputStream fos = new FileOutputStream(f);
            try {
                fos.write(r.data);
            } finally {
                fos.close();
            }
            return f;
        } catch (Exception e) {
            return null;
        }
    }

    private ScrollView makeScrollWith(TextView tv) {
        ScrollView sv = new ScrollView(this);
        sv.setPadding(dp(8), dp(8), dp(8), dp(8));
        sv.addView(tv, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return sv;
    }

    private Dialog buildPreviewDialog(final ResultItem r, View content, double heightFrac) {
        if (previewDialog != null) {
            previewDialog.dismiss();
            previewDialog = null;
        }
        final Dialog d = new Dialog(this);
        previewDialog = d;

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(10), dp(12), dp(8));

        TextView title = new TextView(this);
        title.setText(r.name + "  ·  " + fmtSize(r.data.length) + "  ·  " + typeLabel(r.type));
        title.setTextSize(16);
        title.setTypeface(null, Typeface.BOLD);
        root.addView(title);

        FrameLayout frame = new FrameLayout(this);
        frame.addView(content, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.addView(frame, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout btns = new LinearLayout(this);
        Button bClose = new Button(this);
        bClose.setText("关闭");
        Button bSave = new Button(this);
        bSave.setText("保存");
        btns.addView(bClose, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btns.addView(bSave, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(btns);

        bClose.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                d.dismiss();
            }
        });
        bSave.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                saveBytes(r.name, r.data, mimeOf(r.name), 0);
            }
        });

        d.setOnDismissListener(new DialogInterface.OnDismissListener() {
            public void onDismiss(DialogInterface di) {
                if (mediaHandler != null && mediaUpdater != null) {
                    mediaHandler.removeCallbacks(mediaUpdater);
                }
                mediaHandler = null;
                mediaUpdater = null;
                if (previewPlayer != null) {
                    try {
                        previewPlayer.stop();
                    } catch (Exception ignored) {
                    }
                    previewPlayer.release();
                    previewPlayer = null;
                }
                if (previewVideo != null) {
                    try {
                        previewVideo.stopPlayback();
                    } catch (Exception ignored) {
                    }
                    previewVideo = null;
                }
                if (previewTmp != null) {
                    previewTmp.delete();
                    previewTmp = null;
                }
                if (previewDialog == d) previewDialog = null;
            }
        });

        d.setContentView(root);
        d.show();
        Window w = d.getWindow();
        if (w != null) {
            WindowManager.LayoutParams lp = w.getAttributes();
            lp.width = ViewGroup.LayoutParams.MATCH_PARENT;
            lp.height = (int) (getResources().getDisplayMetrics().heightPixels * heightFrac);
            w.setAttributes(lp);
        }
        return d;
    }

    private void showTextViewer(ResultItem r, String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(13);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        buildPreviewDialog(r, makeScrollWith(tv), 0.85);
    }

    private void showHexViewer(ResultItem r, String hex) {
        TextView tv = new TextView(this);
        tv.setText(hex);
        tv.setTextSize(11);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        buildPreviewDialog(r, makeScrollWith(tv), 0.85);
    }

    private void showImageViewer(ResultItem r, Bitmap bmp) {
        ScrollView sv = new ScrollView(this);
        ImageView iv = new ImageView(this);
        iv.setImageBitmap(bmp);
        iv.setAdjustViewBounds(true);
        iv.setScaleType(ImageView.ScaleType.FIT_CENTER);
        sv.addView(iv, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        buildPreviewDialog(r, sv, 0.85);
    }

    private interface MediaOps {
        int duration();
        int position();
        boolean playing();
        void play();
        void pause();
        void seek(int ms);
    }

    private static String fmtTime(int ms) {
        if (ms < 0) ms = 0;
        int s = ms / 1000;
        return String.format(Locale.US, "%d:%02d", s / 60, s % 60);
    }

    private View buildMediaPanel(MediaOps ops, View mediaView, String info) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        if (mediaView != null) {
            col.addView(mediaView, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        } else {
            LinearLayout box = new LinearLayout(this);
            box.setGravity(Gravity.CENTER);
            TextView tip = new TextView(this);
            tip.setText(info);
            tip.setGravity(Gravity.CENTER);
            box.addView(tip, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            col.addView(box, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        }

        LinearLayout ctl = new LinearLayout(this);
        ctl.setGravity(Gravity.CENTER_VERTICAL);
        ctl.setPadding(0, dp(6), 0, dp(2));
        final ImageButton toggle = new ImageButton(this);
        toggle.setPadding(dp(4), dp(4), dp(4), dp(4));
        setPlayIcon(toggle, ops.playing());
        final TextView elapsed = new TextView(this);
        elapsed.setText(fmtTime(ops.position()));
        elapsed.setPadding(dp(8), 0, dp(4), 0);
        final SeekBar bar = new SeekBar(this);
        int dur = ops.duration();
        bar.setMax(dur > 0 ? dur : 1);
        bar.setProgress(ops.position());
        final TextView remain = new TextView(this);
        remain.setText(dur > 0 ? "-" + fmtTime(dur - ops.position()) : "--:--");
        remain.setPadding(dp(4), 0, dp(8), 0);
        ctl.addView(toggle, new LinearLayout.LayoutParams(dp(56), dp(32)));
        ctl.addView(elapsed, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        ctl.addView(bar, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ctl.addView(remain, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        col.addView(ctl, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final boolean[] dragging = {false};
        toggle.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (ops.playing()) {
                    ops.pause();
                    setPlayIcon(toggle, false);
                } else {
                    int d = ops.duration();
                    if (d > 0 && ops.position() >= d - 50) ops.seek(0);
                    ops.play();
                    setPlayIcon(toggle, true);
                }
            }
        });
        bar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            public void onProgressChanged(SeekBar sb, int progress, boolean fromUser) {
                if (fromUser) {
                    ops.seek(progress);
                    elapsed.setText(fmtTime(progress));
                    int d = ops.duration();
                    remain.setText(d > 0 ? "-" + fmtTime(d - progress) : "--:--");
                }
            }

            public void onStartTrackingTouch(SeekBar sb) {
                dragging[0] = true;
            }

            public void onStopTrackingTouch(SeekBar sb) {
                dragging[0] = false;
            }
        });

        mediaHandler = new Handler();
        mediaUpdater = new Runnable() {
            public void run() {
                int d = ops.duration();
                if (d > 0) {
                    int p = ops.position();
                    if (p > d) p = d;
                    bar.setMax(d);
                    if (!dragging[0]) {
                        bar.setProgress(p);
                        elapsed.setText(fmtTime(p));
                    }
                    remain.setText("-" + fmtTime(d - p));
                    setPlayIcon(toggle, ops.playing());
                }
                mediaHandler.postDelayed(this, 500);
            }
        };
        mediaHandler.postDelayed(mediaUpdater, 500);
        return col;
    }

    private void showAudioPlayer(final ResultItem r, File tmp) {
        previewTmp = tmp;
        final MediaPlayer mp = new MediaPlayer();
        try {
            mp.setDataSource(tmp.getAbsolutePath());
            mp.prepare();
            mp.start();
        } catch (Exception e) {
            try {
                mp.release();
            } catch (Exception ignored) {
            }
            toast("无法播放音频: " + e.getMessage());
            showHexViewer(r, hexDump(r.data, HEX_PREVIEW_LIMIT));
            return;
        }
        previewPlayer = mp;
        mp.setOnCompletionListener(new MediaPlayer.OnCompletionListener() {
            public void onCompletion(MediaPlayer m) {
            }
        });
        MediaOps ops = new MediaOps() {
            public int duration() {
                try {
                    return mp.getDuration();
                } catch (Exception e) {
                    return -1;
                }
            }

            public int position() {
                try {
                    return mp.getCurrentPosition();
                } catch (Exception e) {
                    return 0;
                }
            }

            public boolean playing() {
                try {
                    return mp.isPlaying();
                } catch (Exception e) {
                    return false;
                }
            }

            public void play() {
                try {
                    mp.start();
                } catch (Exception ignored) {
                }
            }

            public void pause() {
                try {
                    mp.pause();
                } catch (Exception ignored) {
                }
            }

            public void seek(int ms) {
                try {
                    mp.seekTo(ms);
                } catch (Exception ignored) {
                }
            }
        };
        buildPreviewDialog(r, buildMediaPanel(ops, null, r.name), 0.55);
    }

    private void showVideoPlayer(ResultItem r, File tmp) {
        previewTmp = tmp;
        final VideoView vv = new VideoView(this);
        vv.setVideoPath(tmp.getAbsolutePath());
        vv.setOnPreparedListener(new MediaPlayer.OnPreparedListener() {
            public void onPrepared(MediaPlayer mp) {
                mp.setLooping(false);
                vv.start();
            }
        });
        vv.setOnErrorListener(new MediaPlayer.OnErrorListener() {
            public boolean onError(MediaPlayer mp, int what, int extra) {
                toast("无法播放此视频");
                return true;
            }
        });
        previewVideo = vv;
        MediaOps ops = new MediaOps() {
            public int duration() {
                return vv.getDuration();
            }

            public int position() {
                return vv.getCurrentPosition();
            }

            public boolean playing() {
                return vv.isPlaying();
            }

            public void play() {
                vv.start();
            }

            public void pause() {
                vv.pause();
            }

            public void seek(int ms) {
                vv.seekTo(ms);
            }
        };
        buildPreviewDialog(r, buildMediaPanel(ops, vv, null), 0.75);
    }
}
