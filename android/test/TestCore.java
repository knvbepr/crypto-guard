import com.guard.encryptor.Core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class TestCore {

    public static void main(String[] args) throws Exception {
        String cmd = args[0];
        if (cmd.equals("enc")) {
            byte[] data = Files.readAllBytes(Paths.get(args[1]));
            String pwd = pwdArg(args[3]);
            String base = Paths.get(args[1]).getFileName().toString();
            byte[] enc = Core.encryptContainer(data, pwd, base);
            Files.write(Paths.get(args[2]), enc);
            System.out.println("OK " + enc.length);
        } else if (cmd.equals("encm")) {
            String pwd = pwdArg(args[2]);
            List<Core.Entry> es = new ArrayList<Core.Entry>();
            for (int i = 3; i < args.length; i++) {
                es.add(new Core.Entry(Paths.get(args[i]).getFileName().toString(),
                        Files.readAllBytes(Paths.get(args[i]))));
            }
            byte[] enc = Core.encryptContainer(Core.buildPackage(es), pwd, "打包 " + es.size() + " 个文件");
            Files.write(Paths.get(args[1]), enc);
            System.out.println("OK " + enc.length);
        } else if (cmd.equals("dec")) {
            byte[] buf = Files.readAllBytes(Paths.get(args[1]));
            String pwd = args.length > 3 ? pwdArg(args[3]) : null;
            if (pwd == null) {
                pwd = Core.extractPwdFromEncName(Paths.get(args[1]).getFileName().toString());
            }
            if (pwd == null) {
                System.out.println("ERR no password");
                System.exit(2);
            }
            Core.Entry r;
            try {
                r = Core.decryptContainer(buf, pwd);
            } catch (Exception e) {
                System.out.println("ERR " + e.getMessage());
                System.exit(2);
                return;
            }
            List<Core.Entry> parsed = Core.parsePackage(r.data);
            Path out = Paths.get(args[2]);
            if (parsed != null) {
                if (args[2].toLowerCase().endsWith(".zip")) {
                    Files.write(out, Core.buildZip(parsed));
                    System.out.println("OK zip " + parsed.size());
                } else {
                    Files.createDirectories(out);
                    for (Core.Entry e : parsed) {
                        Path f = out.resolve(e.name);
                        if (f.getParent() != null) Files.createDirectories(f.getParent());
                        Files.write(f, e.data);
                        System.out.println("OK file " + e.name + " " + e.data.length);
                    }
                }
            } else {
                Files.write(out, r.data);
                System.out.println("OK single " + r.name + " " + r.data.length);
            }
        } else if (cmd.equals("keytest")) {
            byte[] salt = hex2bin(args[2]);
            byte[] key = Core.deriveKey(pwdArg(args[1]), salt);
            System.out.println(hex(key));
        } else {
            System.out.println("ERR unknown command");
            System.exit(5);
        }
    }

    private static String pwdArg(String a) throws Exception {
        if (a.startsWith("@")) {
            String s = new String(Files.readAllBytes(Paths.get(a.substring(1))), StandardCharsets.UTF_8);
            int end = s.length();
            while (end > 0 && (s.charAt(end - 1) == '\n' || s.charAt(end - 1) == '\r')) end--;
            return s.substring(0, end);
        }
        return a;
    }

    private static byte[] hex2bin(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
