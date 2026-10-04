package com.guard.encryptor;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final int REQ_PICK_ENC = 1;
    private static final int REQ_PICK_DEC = 2;
    private static final int REQ_SAVE = 3;

    private RadioButton rbEnc;
    private RadioButton rbDec;
    private ListView listView;
    private ArrayAdapter<String> adapter;
    private EditText pwdEdit;
    private CheckBox showPwd;
    private Button goBtn;
    private Button addBtn;
    private Button rmBtn;
    private Button clrBtn;
    private TextView statusView;
    private ProgressBar progress;
    private TextView emptyHint;

    private final ArrayList<UriItem> items = new ArrayList<UriItem>();
    private boolean decryptMode = false;
    private byte[] pendingData;
    private String pendingName;
    private int pendingToast;

    private static class UriItem {
        final Uri uri;
        final String name;
        final long size;
        UriItem(Uri uri, String name, long size) {
            this.uri = uri;
            this.name = name;
            this.size = size;
        }
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }

    private static String fmtSize(long n) {
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
        listView.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, new ArrayList<String>());
        listView.setAdapter(adapter);
        listWrap.addView(listView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        emptyHint = new TextView(this);
        emptyHint.setText("未选择文件\n请点击下方「添加文件」");
        emptyHint.setGravity(Gravity.CENTER);
        emptyHint.setTextColor(0xFF9E9E9E);
        FrameLayout.LayoutParams hintLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hintLp.gravity = Gravity.CENTER;
        listWrap.addView(emptyHint, hintLp);
        root.addView(listWrap, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout btnRow = new LinearLayout(this);
        addBtn = new Button(this);
        addBtn.setText("添加文件");
        rmBtn = new Button(this);
        rmBtn.setText("移除所选");
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
        pwdRow.addView(pwdLabel);
        pwdRow.addView(pwdEdit, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        pwdRow.addView(showPwd);
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
                int p = listView.getCheckedItemPosition();
                if (p < 0) {
                    toast("请先在列表中选中要移除的文件");
                    return;
                }
                items.remove(p);
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
        goBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                startWork();
            }
        });
    }

    private void onModeChanged() {
        goBtn.setText(decryptMode ? "解密并保存" : "加密并保存");
        items.clear();
        refreshList();
    }

    private void refreshList() {
        ArrayList<String> rows = new ArrayList<String>();
        for (UriItem it : items) {
            String line = it.name + "  (" + fmtSize(it.size) + ")";
            if (decryptMode) {
                String p = Core.extractPwdFromEncName(it.name);
                line += p != null ? "  [密码:" + p + "]" : "  [需手动密码]";
            }
            rows.add(line);
        }
        adapter.clear();
        adapter.addAll(rows);
        adapter.notifyDataSetChanged();
        emptyHint.setVisibility(items.isEmpty() ? View.VISIBLE : View.GONE);
        if (items.isEmpty()) {
            statusView.setText(decryptMode
                    ? "请添加 .enc 密文文件，密码将自动从文件名识别。"
                    : "请添加文件。多选时自动打包为一个加密文件，密码会写入文件名。");
        } else {
            statusView.setText("已选 " + items.size() + " 个文件"
                    + (decryptMode ? "，将按各自文件名解密。" : (items.size() > 1 ? "，将打包加密。" : "。")));
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
                    if (pendingToast > 0) {
                        toast(pendingToast == 2 ? "已完成（部分文件解密失败）" : "已完成");
                    }
                } catch (Exception e) {
                    toast("保存失败: " + e.getMessage());
                }
            } else {
                toast("已取消保存");
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
        List<Core.Entry> outs = new ArrayList<Core.Entry>();
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
                continue;
            }
            Core.Entry r = null;
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
                continue;
            }
            List<Core.Entry> parsed = Core.parsePackage(r.data);
            if (parsed != null) {
                outs.addAll(parsed);
            } else {
                outs.add(new Core.Entry(r.name, r.data));
            }
        }
        if (outs.isEmpty()) throw new Exception("没有成功解密任何文件（密码错误或文件损坏）");
        final int failCount = fail;
        runOnUiThread(new Runnable() {
            public void run() {
                statusView.setText("准备保存...");
            }
        });
        if (outs.size() == 1) {
            final byte[] data = outs.get(0).data;
            final String name = outs.get(0).name;
            runOnUiThread(new Runnable() {
                public void run() {
                    saveBytes(name, data, "application/octet-stream", failCount > 0 ? 2 : 1);
                }
            });
        } else {
            runOnUiThread(new Runnable() {
                public void run() {
                    statusView.setText("打包 ZIP...");
                }
            });
            final byte[] zip = Core.buildZip(outs);
            final String name = "解密文件_" + stamp() + ".zip";
            runOnUiThread(new Runnable() {
                public void run() {
                    saveBytes(name, zip, "application/zip", failCount > 0 ? 2 : 1);
                }
            });
        }
    }
}
